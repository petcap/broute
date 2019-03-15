<?php
//Store the randomized Peer-ID in this file
define("PEER_ID_FILE", "/dev/shm/peer-id");

//Send a beacon every BEACON_INTERVAL second
define("BEACON_INTERVAL", 3);

$broadcast_addr = "255.255.255.255";
$broadcast_port = 8888;
$sender_port = 9999;

$socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
socket_set_option($socket, SOL_SOCKET, SO_BROADCAST, 1);
socket_bind($socket, $broadcast_addr, $sender_port);

//Transmitted packets formats:
// B-Route || Peer-ID (20 bytes, random) || Checksum (20 bytes = sha1(Peer-ID))

$peer_id = ""; for($i=0;$i!=100;$i++) $peer_id = sha1($peer_id.rand().time().$i, true);

$send = "B-Route".$peer_id.sha1($peer_id, true);

//Store our Peer-ID to disk
file_put_contents(PEER_ID_FILE, $peer_id);

while (true) {
  socket_sendto($socket, $send, strlen($send), 0, $broadcast_addr, $broadcast_port);
  sleep(BEACON_INTERVAL);

  //Adds some randomness to when beacons are sent
  usleep(rand(1, 100000));
}

socket_close($socket);

?>
