<?php
//Maximum number of peers to keep track of
//Prevents DoSing the script
define("MAX_PEERS", 4096);

//If a peer is not seen for this many seconds, delete it from the list
define("PEER_TIMEOUT", 30);

//Path to peer id file
define("PEER_ID_FILE", "/dev/shm/peer-id");

//Path to ip list file
define("PEER_LIST_FILE", "/dev/shm/peer-list");

$addr = "255.255.255.255";
$broadcast_port = 8888;

$socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
socket_set_option($socket, SOL_SOCKET, SO_BROADCAST, 1);
socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, array("sec" => 5, "usec" => 0));
socket_bind($socket, $addr, $broadcast_port);

//All known peers will be put in this array
$peers = array();

while (true) {

  //Loop and find timeouts
  foreach($peers as $key => $peer) {
    if ($peer['timeout'] < time()) {
      echo "Peer timed out: ".$peer['addr'].", Peer-ID: ".substr($key, 0, 12)."...\n";
      unset($peers[$key]);
      updateListFile();
    }
  }

  $ret = socket_recvfrom($socket, $buf, 47, 0, $addr, $broadcast_port);
  if ($ret === false) continue;
  if (strlen($buf) === 47) {

    //Decode fields
    $sig = substr($buf, 0, 7); //Signature
    $peer_id = substr($buf, 7, 20); //Peer-ID
    $hash = substr($buf, 27, 20); //Hash

    //Make sure the signature and hash are both correct (prevents transmission errors)
    if ($sig === "B-Route" && sha1($peer_id, true) === $hash && file_exists(PEER_ID_FILE)) {

      //Ignore our own announces
      if (file_get_contents(PEER_ID_FILE) === $peer_id) continue;

      //Make sure we don't flood the peer list
      if (count($peers) > MAX_PEERS) {
        echo "WARNING! Too many peers, dropping announce from ".$addr."\n";
        continue;
      }

      $key = sha1($peer_id);
      if (!isset($peers[$key])) {
        $peers[$key] = array(
          "addr" => $addr,
          "peer_id" => $peer_id,
          "timeout" => 0,
        );
        echo "Discovered new peer: $addr, Peer-ID: ".substr($key, 0, 12)."...\n";
        updateListFile(); //Update list on disk
      }

      //Update timeout
      $peers[$key]['timeout'] = time() + PEER_TIMEOUT;
    }

  }
}

//Update the peer list file which is read by other programs
function updateListFile() {
  global $peers;
  $data = array();

  foreach($peers as $peer) {
    //Make sure we don't add the same IP addr twice
    if (!in_array($peer['addr'], $data)) {
      $data[] = $peer['addr'];
    }
  }

  //Export as JSON to temporary file
  file_put_contents(PEER_LIST_FILE.".tmp", json_encode($data));

  //Call rename, this way we immediately points the inode to the correct file
  //and we won't get any weird half reads in other programs
  rename(PEER_LIST_FILE.".tmp", PEER_LIST_FILE);

  echo "Wrote peer data: ".file_get_contents(PEER_LIST_FILE)."\n";
}

socket_close($socket);

?>
