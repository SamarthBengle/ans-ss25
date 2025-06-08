"""
Updated Fat-Tree Two-Level Routing Controller
Based on the original paper specifications
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ether_types
from ryu.topology.api import get_switch, get_link
from ryu.lib import hub
import time

class FTRouter(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FTRouter, self).__init__(*args, **kwargs)
        self.k = 4  # Number of ports per switch
        self.arp_table = {}
        self.rules_installed = False
        self.host_locations = {}  # ip -> (dpid, port)
        self.last_log_time = {}  # Rate limit logging
        self.monitor_thread = hub.spawn(self._monitor)

    def _monitor(self):
        """Monitor topology and install rules when ready."""
        while not self.rules_installed:
            hub.sleep(4)
            switches = get_switch(self, None)
            links = get_link(self, None)
            
            # Expected counts for k=4 fat-tree
            num_switches_expected = (self.k**2 // 4) + self.k**2  # 20 switches
            num_links_expected = self.k**3  # 64 links

            if len(switches) < num_switches_expected or len(links) < num_links_expected:
                continue

            self.logger.info("Full topology discovered. Installing two-level routing rules.")
            if self._install_two_level_rules(switches, links):
                self.rules_installed = True
                self.logger.info("Two-level routing rules installed successfully.")
            else:
                self.logger.error("Failed to install two-level routing rules. Retrying...")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Install default flow to send packets to controller."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                        ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        """Add a flow entry to the switch."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                  priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                  match=match, instructions=inst)
        datapath.send_msg(mod)

    def _get_switch_info(self, dpid):
        """Get switch type and position info from dpid."""
        k = self.k
        edge_start = 1
        agg_start = 1 + (k**2 // 2)
        core_start = 1 + k**2

        if dpid >= core_start:
            # Core switch
            core_index = dpid - core_start
            return "core", -1, core_index
        elif dpid >= agg_start:
            # Aggregation switch
            agg_index = dpid - agg_start
            pod = agg_index // (k // 2)
            index = agg_index % (k // 2)
            return "aggregation", pod, index
        else:
            # Edge switch
            edge_index = dpid - edge_start
            pod = edge_index // (k // 2)
            index = edge_index % (k // 2)
            return "edge", pod, index

    def _install_two_level_rules(self, switches, link_list):
        """Install two-level routing rules according to the paper."""
        try:
            # Build adjacency list
            links = {s.dp.id: {} for s in switches}
            for link in link_list:
                links[link.src.dpid][link.dst.dpid] = link.src.port_no

            for switch in switches:
                datapath = switch.dp
                dpid = datapath.id
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser
                
                switch_type, pod_info, index_info = self._get_switch_info(dpid)
                
                if switch_type == "core":
                    self._install_core_rules(datapath, dpid, links, parser)
                elif switch_type == "aggregation":
                    self._install_aggregation_rules(datapath, dpid, links, parser, pod_info, index_info)
                elif switch_type == "edge":
                    self._install_edge_rules(datapath, dpid, links, parser, pod_info, index_info)

            return True
        except Exception as e:
            self.logger.error(f"Error installing two-level rules: {e}")
            return False

    def _install_core_rules(self, datapath, dpid, links, parser):
        """Install core switch rules - terminating prefixes for pods."""
        # Core switches have terminating /16 prefixes for each pod
        for pod in range(self.k):
            pod_prefix = f"10.{pod}.0.0"
            pod_mask = "255.255.0.0"  # /16 prefix
            
            # Find port connected to this pod
            for neighbor_dpid, port in links[dpid].items():
                neighbor_info = self._get_switch_info(neighbor_dpid)
                if neighbor_info[0] == "aggregation" and neighbor_info[1] == pod:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                          ipv4_dst=(pod_prefix, pod_mask))
                    actions = [parser.OFPActionOutput(port)]
                    self.add_flow(datapath, priority=1, match=match, actions=actions)
                    self.logger.info(f"Core s{dpid}: Route to pod {pod} via port {port}")
                    break

    def _install_aggregation_rules(self, datapath, dpid, links, parser, pod, index):
        """Install aggregation switch rules - prefix for intra-pod, suffix for inter-pod."""
        
        # HIGH PRIORITY: Terminating prefixes for subnets in same pod
        for subnet in range(self.k // 2):
            subnet_prefix = f"10.{pod}.{subnet}.0"
            subnet_mask = "255.255.255.0"  # /24 prefix
            
            # Find edge switch for this subnet
            edge_dpid = 1 + (pod * (self.k // 2) + subnet)
            if edge_dpid in links[dpid]:
                port = links[dpid][edge_dpid]
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                      ipv4_dst=(subnet_prefix, subnet_mask))
                actions = [parser.OFPActionOutput(port)]
                self.add_flow(datapath, priority=2, match=match, actions=actions)
                self.logger.info(f"Agg s{dpid}: Intra-pod route to {subnet_prefix}/24 via port {port}")

        # LOWER PRIORITY: Suffix matching for inter-pod traffic (default /0 with suffix)
        core_ports = []
        for neighbor_dpid, port in links[dpid].items():
            if self._get_switch_info(neighbor_dpid)[0] == "core":
                core_ports.append(port)
        
        core_ports.sort()  # Ensure deterministic ordering
        
        # According to paper: use host ID for load balancing
        for host_id in range(2, self.k//2 + 2):  # Host IDs 2,3 for k=4
            if core_ports:
                # Paper formula: (host_id - 2 + switch_index) mod (k/2)
                port_index = (host_id - 2 + index) % (self.k // 2)
                if port_index < len(core_ports):
                    # This creates a /0 prefix with suffix matching on last octet
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                          ipv4_dst=('0.0.0.' + str(host_id), '0.0.0.255'))
                    actions = [parser.OFPActionOutput(core_ports[port_index])]
                    self.add_flow(datapath, priority=1, match=match, actions=actions)
                    self.logger.info(f"Agg s{dpid}: Inter-pod suffix .{host_id} via core port {core_ports[port_index]}")

    def _install_edge_rules(self, datapath, dpid, links, parser, pod, index):
        """Install edge switch rules - suffix matching for inter-pod traffic."""
        
        # Get aggregation ports
        agg_ports = []
        for neighbor_dpid, port in links[dpid].items():
            if self._get_switch_info(neighbor_dpid)[0] == "aggregation":
                agg_ports.append(port)
        
        agg_ports.sort()  # Ensure deterministic ordering
        
        # Suffix matching for inter-pod traffic
        # According to paper: use host ID for load balancing across aggregation switches
        for host_id in range(2, self.k//2 + 2):  # Host IDs 2,3 for k=4
            if agg_ports:
                # Paper formula: (host_id - 2 + switch_index) mod (k/2)
                port_index = (host_id - 2 + index) % (self.k // 2)
                if port_index < len(agg_ports):
                    # Suffix matching on last octet
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                          ipv4_dst=('0.0.0.' + str(host_id), '0.0.0.255'))
                    actions = [parser.OFPActionOutput(agg_ports[port_index])]
                    self.add_flow(datapath, priority=1, match=match, actions=actions)
                    self.logger.info(f"Edge s{dpid}: Inter-pod suffix .{host_id} via agg port {agg_ports[port_index]}")

    def _should_log(self, message_key):
        """Rate limit logging to reduce spam."""
        current_time = time.time()
        if message_key in self.last_log_time:
            if current_time - self.last_log_time[message_key] < 2.0:  # 2 second interval
                return False
        self.last_log_time[message_key] = current_time
        return True

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """Handle packets sent to controller (mainly ARP)."""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)

        # Only handle ARP packets
        if not arp_pkt:
            return

        # Learn host location from ARP
        if arp_pkt.src_ip not in self.host_locations:
            self.host_locations[arp_pkt.src_ip] = (datapath.id, in_port)
            self.arp_table[arp_pkt.src_ip] = eth.src
            
            # Install high-priority host-specific downlink rule
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, 
                                  ipv4_dst=arp_pkt.src_ip)
            actions = [parser.OFPActionOutput(in_port)]
            self.add_flow(datapath, priority=3, match=match, actions=actions)
            if self._should_log(f"host_learned_{arp_pkt.src_ip}"):
                self.logger.info(f"Host learned: {arp_pkt.src_ip} at s{datapath.id} port {in_port}")

        # Handle ARP requests
        if arp_pkt.opcode == arp.ARP_REQUEST:
            dst_ip = arp_pkt.dst_ip
            
            # If we know the destination, send ARP reply
            if dst_ip in self.arp_table:
                src_mac = self.arp_table[dst_ip]
                
                # Create ARP reply
                reply_pkt = packet.Packet()
                reply_pkt.add_protocol(ethernet.ethernet(
                    dst=eth.src, src=src_mac, ethertype=ether_types.ETH_TYPE_ARP))
                reply_pkt.add_protocol(arp.arp(
                    opcode=arp.ARP_REPLY, src_mac=src_mac, src_ip=dst_ip,
                    dst_mac=eth.src, dst_ip=arp_pkt.src_ip))
                reply_pkt.serialize()
                
                actions = [parser.OFPActionOutput(in_port)]
                out = parser.OFPPacketOut(
                    datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=reply_pkt.data)
                datapath.send_msg(out)
                if self._should_log(f"arp_reply_{dst_ip}"):
                    self.logger.info(f"ARP reply sent: {dst_ip} is at {src_mac}")
            else:
                # Flood ARP request
                actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
                out = parser.OFPPacketOut(
                    datapath=datapath, buffer_id=msg.buffer_id,
                    in_port=in_port, actions=actions, data=msg.data)
                datapath.send_msg(out)
                if self._should_log(f"arp_flood_{dst_ip}"):
                    self.logger.info(f"ARP request flooded for {dst_ip}")