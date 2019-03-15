# Broute
A secure mesh network that will eventually forward UDP from point A to B within the network. Secure routing and network graphing comes built-in. The repository includes the peer discovery service and PKI tools necessary to get everything up and running.

Peers authenticate using TLS and individual certificates. Once authenticated, they exchange a proof-of-adjacency which is signed by both peers and then broadcasted over the network. Other peers verifies the signatures and (if they are valid) adds the corresponding routes to its routing table.

**Currently working**
- Discovery service (adjacent peers discover each other when nearby)
- Two-way TLS authentication over a TCP control channel
- Secure/signed routing table exchange

**Not working**
- UDP payload forwarding (not yet implemented)

**Requirements**
- PHP 7 or later with JSON and OpenSSL support (On Debian/Ubuntu, install php-json and php7.0-cli)

**Running Broute**
Start the discovery and broadcast services in separate terminals on all nodes:
```
$ php beacon.php
$ php discover.php
```

Then launch Broute on the first:
```
$ php broute.php
```

The repo comes with two pre-signed certificates, on the second node start Broute with the second certificate:
Then launch Broute on each node as well:
```
$ php broute.php g2
```

If you want more nodes, you need to sign more certificates:
```
$ php generic_create.php anotherclient
$ cat certs/anotherclient.* > anotherclient.pem
```
