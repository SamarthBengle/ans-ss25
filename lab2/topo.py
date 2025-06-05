"""
 Copyright (c) 2025 Computer Networks Group @ UPB
 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:
 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 """

class Edge:
    """Represents a connection between two nodes."""
    def __init__(self):
        self.lnode = None
        self.rnode = None

    def remove(self):
        self.lnode.edges.remove(self)
        self.rnode.edges.remove(self)
        self.lnode = None
        self.rnode = None

class Node:
    """Represents a device (host or switch) in the topology."""
    def __init__(self, id, type):
        self.edges = []
        self.id = id
        self.type = type
        self.ip = None    # IP address for the node
        self.mac = None   # MAC address for hosts
        self.dpid = None  # Datapath ID for switches

    def add_edge(self, node):
        edge = Edge()
        edge.lnode = self
        edge.rnode = node
        self.edges.append(edge)
        node.edges.append(edge)
        return edge

class Fattree:
    """
    Generates a k-ary fat-tree topology.
    This class creates the logical structure of the network, including nodes,
    links, and addressing, which can then be instantiated in a simulator like Mininet.
    """
    def __init__(self, k):
        if k % 2 != 0:
            raise ValueError("Fat-tree parameter 'k' must be an even number.")
        
        self.k = k
        self.num_pods = k
        self.num_core_switches = (k // 2) ** 2
        self.num_agg_switches_per_pod = k // 2
        self.num_edge_switches_per_pod = k // 2
        self.num_hosts_per_edge_switch = k // 2
        
        self.hosts = []
        self.core_switches = []
        self.agg_switches = []
        self.edge_switches = []
        
        self._generate_topology()
        self._assign_addresses()

    def _generate_topology(self):
        """Creates switches, hosts, and connects them."""
        self._create_switches()
        self._create_hosts()
        self._connect_layers()

    def _create_switches(self):
        # Create core switches
        for i in range(self.num_core_switches):
            dpid = (self.k * self.k) + i
            switch = Node(f"c{i+1}", "core")
            switch.dpid = dpid
            self.core_switches.append(switch)

        # Create pod switches
        for p in range(self.num_pods):
            for s in range(self.num_edge_switches_per_pod):
                dpid = (p * self.num_edge_switches_per_pod) + s
                # Edge switch
                edge_switch = Node(f"e_p{p}_s{s}", "edge")
                edge_switch.dpid = dpid
                self.edge_switches.append(edge_switch)
                # Aggregation switch
                agg_switch = Node(f"a_p{p}_s{s}", "aggregation")
                agg_switch.dpid = (p * self.num_agg_switches_per_pod) + s + (self.k * self.num_edge_switches_per_pod)
                self.agg_switches.append(agg_switch)

    def _create_hosts(self):
        total_hosts = self.num_pods * self.num_edge_switches_per_pod * self.num_hosts_per_edge_switch
        for i in range(total_hosts):
            host = Node(f"h{i}", "host")
            self.hosts.append(host)

    def _connect_layers(self):
        # Connect edge switches to hosts
        for p in range(self.num_pods):
            for e in range(self.num_edge_switches_per_pod):
                edge_switch_index = p * self.num_edge_switches_per_pod + e
                edge_switch = self.edge_switches[edge_switch_index]
                for h in range(self.num_hosts_per_edge_switch):
                    host_index = edge_switch_index * self.num_hosts_per_edge_switch + h
                    edge_switch.add_edge(self.hosts[host_index])

        # Connect edge switches to aggregation switches within the same pod
        for p in range(self.num_pods):
            for e in range(self.num_edge_switches_per_pod):
                edge_switch_index = p * self.num_edge_switches_per_pod + e
                for a in range(self.num_agg_switches_per_pod):
                    agg_switch_index = p * self.num_agg_switches_per_pod + a
                    self.edge_switches[edge_switch_index].add_edge(self.agg_switches[agg_switch_index])
        
        # Connect aggregation switches to core switches
        for p in range(self.num_pods):
            for a in range(self.num_agg_switches_per_pod):
                agg_switch_index = p * self.num_agg_switches_per_pod + a
                for c in range(self.num_agg_switches_per_pod):
                    core_switch_index = a * self.num_agg_switches_per_pod + c
                    self.agg_switches[agg_switch_index].add_edge(self.core_switches[core_switch_index])

    def _assign_addresses(self):
        """Assigns IP and MAC addresses based on the fat-tree addressing scheme."""
        # Hosts: 10.pod.switch.ID
        for p in range(self.num_pods):
            for e in range(self.num_edge_switches_per_pod):
                for h in range(self.num_hosts_per_edge_switch):
                    host_id = h + 2 # Host IDs are .2, .3, ...
                    host_index = (p * self.num_edge_switches_per_pod + e) * self.num_hosts_per_edge_switch + h
                    host = self.hosts[host_index]
                    host.ip = f"10.{p}.{e}.{host_id}"
                    host.mac = f"00:00:00:{p:02x}:{e:02x}:{host_id:02x}"
    
    def get_all_switches(self):
        return self.core_switches + self.agg_switches + self.edge_switches
        
    def get_hosts(self):
        return self.hosts