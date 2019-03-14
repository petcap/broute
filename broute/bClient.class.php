<?php
require_once("bGraph.php");

class bClient {
  public $cn;
  public static $cn_self; //Static since it's always the same and we need to use it without an initialized object
  public $peer;
  private $outgoing_buffer;
  private $incoming_buffer;
  public $socket;
  private $disconnect;
  public $last_active;
  public $last_ping;
  public $connection_time;
  public static $own_cert;
  public $has_signature;
  public $cert;
  private $signature;
  public $routing_table_hash; //Set by bGraph

  //Called when a new peer is connected and TLS verified
  function __construct($cn, $peer, $socket) {
    $this -> cn = $cn;
    $this -> peer = $peer;
    $this -> socket = $socket;
    echo "Connected to $cn via $peer\n";
    //$this -> outgoing_buffer = "Hello world from outgoing data\n";
    $this -> disconnect = false;
    $this -> has_signature = false;
    $this -> last_active = time();
    $this -> last_ping = time();
    bClient::$cn_self = cryptohelper::getCN(file_get_contents(CLIENT_CERT));
    $this -> connection_time = time();
    $this -> routing_table_hash = "";

    //Export ONLY the public key from our PEM file and store it for later use
    openssl_x509_export(file_get_contents(CLIENT_CERT), bClient::$own_cert);

    //Make sure we don't connect to the same CN as ourselves
    if (bClient::$cn_self === $this -> cn) {
      $this -> disconnect = true;
      echo "Other peer has same CN, disconnecting\n";
      return;
    }

    //On connect, send an adjacent proof signature to other peer
    $this -> sendAdjacentProof();
  }

  //Returns the connection proof and signature for this connection only
  //This is called by the grapher code
  function getSignature() {
    if (!$this -> has_signature) die("getSignature, but has no signature (this should never happen)\n");

    $sig = base64_encode(cryptohelper::signData(
      file_get_contents(CLIENT_CERT), //Sign with our own cert
      bClient::$cn_self."|".$this -> cn //us -> them
    ));

    $proof = array(
      "src" => bClient::$cn_self, //Route from us...
      "dst" => $this -> cn, //...to them
      "cert_src" => bClient::$own_cert, //Our cert
      "cert_dst" => $this -> cert, //Their cert
      "signature_src" => $sig, //Our proof of us -> them
      "signature_dst" => $this -> signature, //Their proof of us -> them
    );
    return $proof;
  }

  //When a peer is disconnected
  //Always eventually called
  function disconnect() {
    echo "Disconnecting from ".$this -> peer."\n";
    fclose($this -> socket);
    if (isset(bGraph::$adjacent[$this -> cn])) {
      unset(bGraph::$adjacent[$this -> cn]);
      bGraph::isUpdated();
    }
  }

  //Called when we receive a router announce from the other peer
  //Returns true if decode and validation is OK, otherwise false
  private function checkRouting($data) {

    //Make sure we've got the correct data
    if (!isset($data -> table) || !is_array($data -> table)) {
      return false;
    }

    //Verify signatures for each route
    foreach($data -> table as $route) {

      //Check that we have enough data to verify this route
      if (
        !isset($route -> src) ||
        !isset($route -> dst) ||
        !isset($route -> signature_src) ||
        !isset($route -> signature_dst) ||
        !isset($route -> cert_src) ||
        !isset($route -> cert_dst)
      ) {
        return false;
      }

      //Verify both signatures of the route
      if (!bClient::verifyRoute($route)) {
        echo "Route verification failed, disconnecting peer\n";
        $this -> disconnect = true;
      }

      //Add the graph to bGraph
      bGraph::addRoute(array(
        "src" => $route -> src,
        "dst" => $route -> dst,
        "cert_src" => $route -> cert_src,
        "cert_dst" => $route -> cert_dst,
        "signature_src" => $route -> signature_src,
        "signature_dst" => $route -> signature_dst,
      ));

    }

    return true;
  }

  //Verify a single one-way route (verifies both signatures)
  private static function verifyRoute($route) {

    //Check data types
    if (!is_string($route -> src)) return false;
    if (!is_string($route -> dst)) return false;
    if (!is_string($route -> signature_src)) return false;
    if (!is_string($route -> signature_dst)) return false;
    if (!is_string($route -> cert_src)) return false;
    if (!is_string($route -> cert_dst)) return false;

    //Verify that the received certificate is signed by our CA
    if (!cryptohelper::isCertificateValid($route -> cert_src) || !cryptohelper::isCertificateValid($route -> cert_dst)) {
      echo "Invalid CA\n";
      return false;
    }

    //Verify that the received certificate corresponds to the CN for this client
    if (cryptohelper::getCN($route -> cert_src) !== $route -> src || cryptohelper::getCN($route -> cert_dst) !== $route -> dst) {
      echo "Invalid CN for presented certificate\n";
      return false;
    }

    //Verify signature #1
    if (!cryptohelper::verifySignature(
      $route -> cert_src,
      $route -> src."|".$route -> dst, //Verify this string
      base64_decode($route -> signature_src)
    )) {
      echo "Invalid signature #1\n";
      return false;
    }

    //Verify signature #2
    if (!cryptohelper::verifySignature(
      $route -> cert_dst,
      $route -> src."|".$route -> dst, //Verify this string
      base64_decode($route -> signature_dst)
    )) {
      echo "Invalid signature #2\n";
      return false;
    }

    return true;
  }

  //Verify a proof of adjacency
  private static function verifyProof($route_dst, $route_src, $signature, $cert) {

    //Check data types
    if (!is_string($route_dst)) return false;
    if (!is_string($route_src)) return false;
    if (!is_string($signature)) return false;
    if (!is_string($cert)) return false;

    //Verify that the received certificate is signed by our CA
    if (!cryptohelper::isCertificateValid($cert)) {
      return false;
    }

    //Verify that the received certificate corresponds to the CN for this client
    if (cryptohelper::getCN($cert) !== $route_dst) {
      return false;
    }

    //Verify that the signature is correct
    if (!cryptohelper::verifySignature(
      $cert,
      $route_src."|".$route_dst, //Verify this string
      base64_decode($signature)
    )) {
      return false;
    }

    //Verify that the signature is really for us
    if ($route_src !== bClient::$cn_self) {
      return false;
    }

    return true;
  }

  //Send proof of validity, i.e. "here's proof that you are adjacent to me"
  function sendAdjacentProof() {
    echo "Sending adjacent proof\n";

    $this -> sendMessage(array(
      "type" => "adjacent_proof",
      "dst" => bClient::$cn_self, //Our CN
      "src" => $this -> cn, //Peers CN
      "signature" => base64_encode(cryptohelper::signData(
        file_get_contents(CLIENT_CERT), //Use our private key
        $this -> cn."|".bClient::$cn_self //Sign "they are allowed to talk to us"
      )),
      "cert" => bClient::$own_cert,
    ));
  }

  //Called when we receive an adjacent proof from the other peer
  private function verifyAdjacentProof($data) {

    //Check that we have all data we need
    if (
      !isset($data -> dst) ||
      !isset($data -> src) ||
      !isset($data -> signature) ||
      !isset($data -> cert)
    ) {
      echo "Bad signature from ".$this -> cn.", dropping connection\n";
      $this -> disconnect = true;
      return;
    }

    if (!bClient::verifyProof($data -> dst, $data -> src, $data -> signature, $data -> cert)) {
      echo "Invalid proof received from ".$this -> cn.", disconnecting\n";
      $this -> disconnect = true;
      return;
    }

    //We now have our signature, store the relevant data in this object
    $this -> has_signature = true;
    $this -> cert = $data -> cert; //Other peer cert
    $this -> signature = $data -> signature; //Their signature

    //Tell bGraph about this new route
    bGraph::addRoute($this -> getSignature());

    //Send our currect routing table to this peer
    bGraph::sendRoutesToPeer($this);
  }

  //Called when a JSON object is ready for deserialization
  function newJSON() {
    $data = explode("\n", $this -> incoming_buffer, 2);
    $this -> incoming_buffer = $data[1];
    $data = trim($data[0]);
    $data = json_decode($data);

    if ($data === false || !isset($data -> type)) {
      $this -> disconnect = true;
      return;
    }

    //Ping request from other peer
    if ($data -> type === "ping") {
      $this -> sendMessage(array("type" => "pong"));
      return;
    }

    //Pong from other peer
    if ($data -> type === "pong") {
      return;
    }

    echo set_color(COLOR_CYAN);
    echo "Got message from ".$this -> cn.": ".$data -> type."\n";
    echo set_color(COLOR_DEFAULT);

    //Proof of adjecent received from other peer
    if ($data -> type === "adjacent_proof") {
      $this -> verifyAdjacentProof($data);
    }

    //At this point, make sure we only process other commands after we have
    //a signature from the other peer
    if (!$this -> has_signature) return;

    //Signed list of all active routes the other peer knows about
    if ($data -> type === "routing_table") {
      echo set_color(COLOR_RED);

      //Update all received routes and verify route integrity
      if (!$this -> checkRouting($data)) {
        echo "Failed to verify routes, disconnecting peer\n";
        $this -> disconnect = true;
      }
      echo set_color(COLOR_DEFAULT);
    }
  }

  //Send JSON message
  function sendMessage($m) {
    $this -> outgoing_buffer .= json_encode($m)."\n";
    if ($m['type'] !== "pong" && $m['type'] !== "ping") {
      echo set_color(COLOR_YELLOW);
      echo "Sending message to ".$this -> cn.": ".$m['type']."\n";
      echo set_color(COLOR_DEFAULT);
    }
  }

  //Received incoming data
  function incoming($data) {

    //Make sure we wont get flooded
    if (strlen($this -> incoming_buffer) > 1024*1024*10) {
      $this -> disconnect = true;
      return;
    }

    //Store data in the buffer
    $this -> incoming_buffer .= $data;
    $this -> last_active = time();
    if (strstr($this -> incoming_buffer, "\n") !== false) {
      $this -> newJSON();
    }
  }

  //Deliver outgoing data
  function outgoing() {
    if ($this -> disconnect) return "";
    //echo "Sending data\n";
    return $this -> outgoing_buffer;
  }

  //Ack n bytes of transmitted data (i.e. delete n bytes from internal outgoing buffer)
  function ackData($n) {
    //echo "Acked $n bytes\n";
    $this -> outgoing_buffer = substr($this -> outgoing_buffer, $n);
  }

  //Check if we have data to deliver to the other peer
  function hasData() {
    if ($this -> disconnect) return false;
    return !empty($this -> outgoing_buffer);
  }

  //Do we want to disconnect?
  function wantsDisconnect() {
    return $this -> disconnect;
  }
}
?>
