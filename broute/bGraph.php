<?php
/*
* This class implements the mesh graph and keeps track of peers and their
* adjacent peers
*/

require_once("cryptohelper.class.php");

class bGraph {
  //All previously seen (and verified!) proofs of adjacency over the entire network
  private static $routing = array();

  //A hash of the current routing table
  private static $hash = "N/A";

  //Adds an (already verified) route to the routing table
  public static function addRoute($route) {

    //Check if we already know this route
    foreach(bGraph::$routing as $r) {
      if ($r['src'] == $route['src'] && $r['dst'] == $route['dst']) {
        return;
      }
    }

    //Add the route
    bGraph::$routing[] = $route;
    echo "Route added: ".$route['src']." -> ".$route['dst']."\n";

    echo "Routing table is now:\n";
    foreach(bGraph::$routing as $r) {
      echo "* ".$r['src']." -> ".$r['dst']."\n";
    }
    echo "\n";

    //Announce the route to all adjacent peers
    bGraph::isUpdated();
  }

  //Updates the current routing table hash
  private static function updateHash() {
    bGraph::$hash = sha1(print_r(bGraph::$routing, true));
  }

  //Called when the adjacent list is changed
  //I.e. either a peer is added or removed
  //When this is called, we should update our routing table and broadcast it
  //over the rest of the network
  public static function isUpdated() {
    global $peers;
    echo "bGraph adjacent list updated\n";

    //Send our updated list to all peers
    foreach($peers as $peer) {
      if (!$peer -> has_signature) continue;

      //Notify the peer of our adjacent connections
      bGraph::sendRoutesToPeer($peer);
    }
  }

  //Send our routing table to a specific peer
  public static function sendRoutesToPeer($peer) {

    //Check if this peer already knows our routing table
    if ($peer -> routing_table_hash === bGraph::$hash) {
      return;
    }

    //Update peer hash
    $peer -> routing_table_hash = bGraph::$hash;

    $peer -> sendMessage(array(
      "type" => "routing_table",
      "table" => bGraph::$routing,
    ));
  }
}
?>
