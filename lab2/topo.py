"""
 Copyright (c) 2025 Computer Networks Group @ UPB
 (MODIFIED TO AVOID DPID 0)
"""

class Edge:
    def __init__(self):
        self.lnode = None
        self.rnode = None

class Node:
    def __init__(self, id, type):
        self.edges = []
        self.id = id
        self.type = type
        self.ip = None
        self.mac = None
        self.dpid = None

    def add_edge(self, node):
        edge = Edge()
        edge.lnode = self
        edge.rnode = node
        self.edges.append(edge)
        node.edges.append(edge)
        return edge

class Fattree:
    def __init__(self, k):
        if k % 2 != 0:
            raise ValueError("Fat tree  k values must be an even number.")
        
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
        
        self.generate_topology()
        self.assign_addresses()

    def generate_topology(self):
        self.create_switches()
        self.create_hosts()
        self.connect_layers()

    def create_switches(self):
        # --- DPID ASSIGNMENT MODIFIED TO START FROM 1 ---
        edge_dpid_start = 1
        agg_dpid_start = edge_dpid_start + (self.k * self.num_edge_switches_per_pod)
        core_dpid_start = agg_dpid_start + (self.k * self.num_agg_switches_per_pod)

        # Create Core Switches
        for i in range(self.num_core_switches):
            switch = Node(f"c{i+1}", "core")
            switch.dpid = core_dpid_start + i
            self.core_switches.append(switch)

        # Create Pod Switches
        for p in range(self.num_pods):
            for s in range(self.num_edge_switches_per_pod):
                # Edge switch
                edge_switch = Node(f"e_p{p}_s{s}", "edge")
                edge_switch.dpid = edge_dpid_start + (p * self.num_edge_switches_per_pod) + s
                self.edge_switches.append(edge_switch)
                # Aggregation switch
                agg_switch = Node(f"a_p{p}_s{s}", "aggregation")
                agg_switch.dpid = agg_dpid_start + (p * self.num_agg_switches_per_pod) + s
                self.agg_switches.append(agg_switch)

    def create_hosts(self):
        total_hosts = self.num_pods * self.num_edge_switches_per_pod * self.num_hosts_per_edge_switch
        for i in range(total_hosts):
            self.hosts.append(Node(f"h{i}", "host"))

    def connect_layers(self):
        # Connect edge switches to hosts
        for p in range(self.num_pods):
            for e in range(self.num_edge_switches_per_pod):
                edge_switch_index = p * self.num_edge_switches_per_pod + e
                for h in range(self.num_hosts_per_edge_switch):
                    host_index = edge_switch_index * self.num_hosts_per_edge_switch + h
                    self.edge_switches[edge_switch_index].add_edge(self.hosts[host_index])
        # Connect edge to aggregation
        for p in range(self.num_pods):
            for e in range(self.num_edge_switches_per_pod):
                edge_switch_index = p * self.num_edge_switches_per_pod + e
                for a in range(self.num_agg_switches_per_pod):
                    agg_switch_index = p * self.num_agg_switches_per_pod + a
                    self.edge_switches[edge_switch_index].add_edge(self.agg_switches[agg_switch_index])
        # Connect aggregation to core
        for p in range(self.num_pods):
            for a in range(self.num_agg_switches_per_pod):
                agg_switch_index = p * self.num_agg_switches_per_pod + a
                for c in range(self.num_agg_switches_per_pod):
                    core_switch_index = a * self.num_agg_switches_per_pod + c
                    self.agg_switches[agg_switch_index].add_edge(self.core_switches[core_switch_index])

    def assign_addresses(self):
        for p in range(self.num_pods):
            for e in range(self.num_edge_switches_per_pod):
                for h in range(self.num_hosts_per_edge_switch):
                    host_id = h + 2
                    host_index = (p * self.num_edge_switches_per_pod + e) * self.num_hosts_per_edge_switch + h
                    host = self.hosts[host_index]
                    host.ip = f"10.{p}.{e}.{host_id}"
                    host.mac = f"00:00:00:{p:02x}:{e:02x}:{host_id:02x}"
    
    def get_all_switches(self):
        return self.core_switches + self.agg_switches + self.edge_switches
        
    def get_hosts(self):
        return self.hosts