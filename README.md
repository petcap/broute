# Broute
A secure mesh network that will eventually forward UDP from point A to B within the network. Secure routing and network graphing comes built-in. The repository includes the peer discovery service and PKI tools necessary to get everything up and running.

Peers authenticate using TLS and individual certificates. Once authenticated, they exchange a proof-of-adjacency which is signed by both peers and then broadcasted over the network. Other peers verify the signature and (if they are valid) adds the peers to its routing list.

Currently working:
- Discovery service (adjacent peers discover each other when nearby)
- Two-way TLS authentication over a TCP control channel
- Secure/signed routing table exchange

Not working:
- UDP payload forwarding (not yet implemented)
