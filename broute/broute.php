<?php
//Limit number of connections
define("MAX_TCP_CONN", 512);

//Disconnect if no traffic has been received for this many seconds
define("CONN_TIMEOUT", 15);

//Send a ping this often in seconds
define("CONN_PING", 5);

//Send our known routes this often (seconds)
define("SEND_ROUTES", 10);

//Path to root CA
define("ROOT_CA", "root.crt");

//Path to client certs
//FIXME: Delete debugging
if (in_array("g2", $argv)) {
  define("CLIENT_CERT", "g2.pem");
} else {
  define("CLIENT_CERT", "g1.pem");
}

//Path to ip list file
define("PEER_LIST_FILE", "/dev/shm/peer-list");

require_once("bClient.class.php");
require_once("bash_color.php");

//Initiate an outgoing connection and add it to the peer list
function connectTo($peer) {
  global $peers;
  $context = stream_context_create();
  stream_context_set_option($context, 'ssl', 'local_cert', CLIENT_CERT);
  stream_context_set_option($context, 'ssl', 'crypto_method', STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT);
  stream_context_set_option($context, 'ssl', 'allow_self_signed', false);
  stream_context_set_option($context, 'ssl', 'cafile', ROOT_CA);
  stream_context_set_option($context, 'ssl', 'verify_peer', true);
  stream_context_set_option($context, 'ssl', 'verify_depth', 3);
  stream_context_set_option($context, 'ssl', 'capture_peer_cert', true);
  stream_context_set_option($context, 'ssl', 'verify_peer_name', false);
  $c = @stream_socket_client('tls://'.$peer.':1337', $errno, $errstr, 3, STREAM_CLIENT_CONNECT, $context);
  if ($c === false) return false;

  $certcontext = stream_context_get_params($c);
  if (!isset($certcontext['options']['ssl']['peer_certificate'])) return false;
  $certinfo = openssl_x509_parse($certcontext['options']['ssl']['peer_certificate']);
  if (!isset($certinfo['subject']['CN'])) return false;
  $peers[$peer] = new bClient($certinfo['subject']['CN'], $peer, $c);
  return true;
}

$context = stream_context_create();
stream_context_set_option($context, 'ssl', 'local_cert', CLIENT_CERT);
stream_context_set_option($context, 'ssl', 'crypto_method', STREAM_CRYPTO_METHOD_TLSv1_2_SERVER);
stream_context_set_option($context, 'ssl', 'allow_self_signed', false);
stream_context_set_option($context, 'ssl', 'cafile', ROOT_CA);
stream_context_set_option($context, 'ssl', 'verify_peer', true);
stream_context_set_option($context, 'ssl', 'verify_depth', 3);
stream_context_set_option($context, 'ssl', 'capture_peer_cert', true);
stream_context_set_option($context, 'ssl', 'verify_peer_name', false);

$server = @stream_socket_server('tls://0.0.0.0:1337', $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context);

if ($server === false) {
  die("Failed to listen to socket\n");
}

echo "Starting bRoute...\n";

$peers = array();
$noOutboundConnectionsUntil = 0;

while (true) {
  //Check for objects that wants to disconnect
  //Also check for pings and timeouts
  foreach($peers as $key => $peer) {

    //Check if we have a pending disconnect
    if ($peer -> wantsDisconnect() || $peer -> last_active + CONN_TIMEOUT < time()) {
      $peer -> disconnect();
      unset($peers[$key]);
      continue;
    }

    //Ping other peer
    if ($peer -> last_ping + CONN_PING < time()) {
      $peer -> sendMessage(array(
        "type" => "ping"
      ));
      $peer -> last_ping = time();
    }
  }

  //Check for announced peers and connect if any exists
  if (file_exists(PEER_LIST_FILE) && $noOutboundConnectionsUntil < time()) {
    $list = @file_get_contents(PEER_LIST_FILE);
    if ($list !== false) {
      $list = @json_decode($list);
      if ($list !== false) {
        //echo "Got list: "; print_r($list);
        foreach($list as $ip) {
          if (!isset($peers[$ip])) {
            echo "Connecting to discovered peer: $ip\n";
            connectTo($ip);
            $noOutboundConnectionsUntil = time()+30;
          }
        }
      }
    }
  }

  $except = getAllPeers();
  $read = getAllPeers();
  $write = getTransmittingPeers();

  //Do we want to accept new connections?
  if (count($peers) < MAX_TCP_CONN) {
    $read[] = $server;
  }

  //sleep(1);
  //echo date("H:i:s")." - Connected to ".count($peers)." peer(s)\n";
  usleep(rand(0, 100000));
  if (stream_select($read, $write, $except, 1)) {
    //Read client data
    foreach ($read as $c) {
      if ($c === $server) { //Read possible from listening socket
        //Accept incoming connection
        $c = @stream_socket_accept($server, 0, $peer);

        if ($c === false) continue;

        $peer = explode(":", $peer)[0];

        //Check if peer is already connected
        if (isset($peers[$peer])) {
          fclose($c);
          continue;
        }

        $certcontext = stream_context_get_params($c);
        if (!isset($certcontext['options']['ssl']['peer_certificate'])) continue;
        $certinfo = openssl_x509_parse($certcontext['options']['ssl']['peer_certificate']);
        if (!isset($certinfo['subject']['CN'])) continue;
        $peers[$peer] = new bClient($certinfo['subject']['CN'], $peer, $c);

        continue;
      }

      //Is peer still connected?
      if (feof($c)) {
        removePeer($c);
        continue;
      }

      //We have more incoming data
      $contents = @fread($c, 1024*1024*10);
      if ($contents !== false) {
        getPeer($c) -> incoming($contents);
      }
    }

    //Write client data
    foreach ($write as $c) {

      //Is peer still connected?
      if (@feof($c)) {
        removePeer($c);
        continue;
      }

      $clientObj = getPeer($c);
      if ($clientObj === false) continue;

      //Send data in the buffer
      $written = fwrite($c, $clientObj -> outgoing());
      if ($written !== false) {
        //if ($written > 0) echo "Wrote $written bytes\n";
        $clientObj -> ackData($written);
      }
    }

    //Check for client exceptions
    foreach ($except as $c) {
      removePeer($c);
    }
  }
}

//Get all current open sockets
function getAllPeers() {
  global $peers;
  $ret = array();
  foreach($peers as $peer) {
    $ret[] = $peer -> socket;
  }
  return $ret;
}

//Get all peers that wants to transmit data over the socket
function getTransmittingPeers() {
  global $peers;
  $ret = array();
  foreach($peers as $peer) {
    if ($peer -> hasData()) {
      $ret[] = $peer -> socket;
    }
  }
  return $ret;
}

//Remove a peer from the list
function removePeer($socket) {
  global $peers;
  foreach($peers as $key => $cmp) {
    if ($cmp -> socket === $socket) {
      $cmp -> disconnect();
      unset($peers[$key]);
    }
  }
}

//Get a peer from the list
function getPeer($socket) {
  global $peers;
  foreach($peers as $key => $cmp) {
    if ($cmp -> socket === $socket) {
      return $cmp;
    }
  }
  return false;
}

//Close the listening socket
socket_close($sock);
