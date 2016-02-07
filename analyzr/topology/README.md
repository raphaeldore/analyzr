Topologie réseau
================

La topologie du réseau va être modélisée à partir d'un graphe. Chaque élément du réseau
sera un noeud dans le graphe.

Terminologie tirée de https://wiki.onosproject.org/display/ONOS/Representing+Networks

## Model Object Types

The interface definitions and implementations of these objects can be found across several packages under [org.onlab.onos.net.*]. While not formal, implicit object classifications fall out of the organization of these packages.Note that the following list is not comprehensive.

### Network Topology

Many of the model objects have graph analogues, as ONOS represents networks as directed graphs.
* Device - A network infrastructure element, e.g. a switch, router, access-point, or middle-box. Devices have a set of interfaces/ports and a DeviceId. Devices are interior vertices of the network graph.
* Port - A network interface on a Device. A Port and DeviceId pair forms a ConnectPoint, which represents an endpoint of a graph edge. 
* Host - A network end-station, which has an IP address, MAC address, VLAN ID, and a ConnectPoint. Hosts are exterior (leaf) vertices of the network graph.
* Link - A directed link between two infrastructure Devices (ConnectPoints). Links are interior edges of the network graph.
* EdgeLink - A specialized Link connecting a Host to a Device. EdgeLinks are exterior edges of the network graph.
* Path - A list of one or more adjacent Links, including EdgeLinks. EdgeLinks, if present in the path, can only be exterior links (beginning and end of the list).
* Topology - A Snapshot of a traversable graph representing the network. Path computations against this graph may be done using an arbitrary graph traversal algorithm, e.g. BFS, Dijkstra, or Bellman-Ford.