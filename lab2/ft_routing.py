"""
 Copyright (c) 2025 Computer Networks Group @ UPB

 Final, Robust Fat-Tree Two-Level Routing Controller (Hybrid Approach)
"""
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ether_types
from ryu.topology.api import get_switch, get_link
from ryu.lib import hub

class FTRouter(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FTRouter, self).__init__(*args, **kwargs)
        self.k = 4
        self.arp_table = {}
        self.rules_installed = False
        self.host_locations = {} # ip -> (dpid, port)
        self.monitor_thread = hub.spawn(self._monitor)

    def _monitor(self):
        """A background thread to wait for topology stability."""
        while not self.rules_installed:
            hub.sleep(4)
            switches = get_switch(self, None)
            links = get_link(self, None)
            
            num_switches_expected = (self.k**2 // 4) + self.k**2
            num_links_expected = self.k**3

            if len(switches) < num_switches_expected or len(links) < num_links_expected:
                continue

            self.logger.info("✅ Full topology discovered. Installing backbone routing rules.")
            if self._install_backbone_rules(switches, links):
                self.rules_installed = True
                self.logger.info("✅✅ Backbone rules installed. Ready for hosts.")
            else:
                self.logger.error("ERROR: Backbone rule installation failed. Retrying...")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        match = datapath.ofproto_parser.OFPMatch()
        actions = [datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_CONTROLLER, datapath.ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, dp, p, m, a):
        inst = [dp.ofproto_parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, a)]
        mod = dp.ofproto_parser.OFPFlowMod(datapath=dp, priority=p, match=m, instructions=inst)
        dp.send_msg(mod)

    def _get_switch_info(self, dpid):
        k, e_start, a_start, c_start = self.k, 1, 1+(self.k**2//2), 1+(self.k**2)
        if dpid>=c_start: return "core", -1, dpid-c_start
        if dpid>=a_start: return "aggregation", *divmod(dpid-a_start, k//2)
        return "edge", *divmod(dpid-e_start, k//2)

    def _install_backbone_rules(self, switches, link_list):
        links = {s.dp.id: {} for s in switches}
        for link in link_list: links[link.src.dpid][link.dst.dpid] = link.src.port_no
        try:
            for dp in [s.dp for s in switches]:
                s_type, pod, index = self._get_switch_info(dp.id)
                if s_type == "core":
                    for p in range(self.k):
                        match = dp.ofproto_parser.OFPMatch(eth_type=0x0800, ipv4_dst=(f"10.{p}.0.0", "255.255.0.0"))
                        for neighbor, port in links[dp.id].items():
                            if self._get_switch_info(neighbor)[1] == p:
                                self.add_flow(dp, 1, match, [dp.ofproto_parser.OFPActionOutput(port)]); break
                elif s_type == "aggregation":
                    for s in range(self.k // 2):
                        match = dp.ofproto_parser.OFPMatch(eth_type=0x0800, ipv4_dst=(f"10.{pod}.{s}.0", "255.255.255.0"))
                        e_dpid = 1 + (pod * (self.k // 2) + s)
                        self.add_flow(dp, 2, match, [dp.ofproto_parser.OFPActionOutput(links[dp.id][e_dpid])])
                    c_links = sorted([p for d, p in links[dp.id].items() if self._get_switch_info(d)[0]=='core'])
                    for i in range(2, self.k//2 + 2):
                        match = dp.ofproto_parser.OFPMatch(eth_type=0x0800, ipv4_dst=(f"0.0.0.{i}", "0.0.0.255"))
                        p_idx = (i - 2 + index) % (self.k//2)
                        self.add_flow(dp, 1, match, [dp.ofproto_parser.OFPActionOutput(c_links[p_idx])])
                elif s_type == "edge":
                    a_links = sorted([p for d, p in links[dp.id].items() if self._get_switch_info(d)[0]=='aggregation'])
                    for i in range(2, self.k//2+2):
                        match = dp.ofproto_parser.OFPMatch(eth_type=0x0800, ipv4_dst=(f"0.0.0.{i}", "0.0.0.255"))
                        p_idx = (i - 2 + index) % (self.k // 2)
                        self.add_flow(dp, 1, match, [dp.ofproto_parser.OFPActionOutput(a_links[p_idx])])
            return True
        except KeyError as e: return False

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg, dp, ofp = ev.msg, ev.msg.datapath, ev.msg.datapath.ofproto
        in_port, pkt = msg.match['in_port'], packet.Packet(msg.data)
        eth, arp_pkt = pkt.get_protocol(ethernet.ethernet), pkt.get_protocol(arp.arp)

        if not arp_pkt: # Ignore non-ARP packets sent to controller
            return

        # Learn host MAC, IP, and location from its ARP packet
        if arp_pkt.src_ip not in self.host_locations:
            self.host_locations[arp_pkt.src_ip] = (dp.id, in_port)
            self.arp_table[arp_pkt.src_ip] = eth.src
            
            # Install high-priority host-specific downlink rule on the edge switch
            match = dp.ofproto_parser.OFPMatch(eth_type=0x0800, ipv4_dst=arp_pkt.src_ip)
            actions = [dp.ofproto_parser.OFPActionOutput(in_port)]
            self.add_flow(dp, 3, match, actions) # Priority 3 is highest
            self.logger.info(f"Host learned: {arp_pkt.src_ip} at s{dp.id} p{in_port}. Downlink rule installed.")
        
        # Handle ARP requests
        if arp_pkt.opcode == arp.ARP_REQUEST:
            dst_ip = arp_pkt.dst_ip
            # If we know the destination, proxy an ARP reply
            if dst_ip in self.arp_table:
                src_mac = self.arp_table[dst_ip]
                p = packet.Packet()
                p.add_protocol(ethernet.ethernet(dst=eth.src, src=src_mac, ethertype=ether_types.ETH_TYPE_ARP))
                p.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=src_mac, src_ip=dst_ip, dst_mac=eth.src, dst_ip=arp_pkt.src_ip))
                p.serialize()
                actions = [dp.ofproto_parser.OFPActionOutput(in_port)]
                out = dp.ofproto_parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=ofp.OFPP_CONTROLLER, actions=actions, data=p.data)
                dp.send_msg(out)
            # If we don't know the destination, flood the original ARP request to find it
            else:
                actions = [dp.ofproto_parser.OFPActionOutput(ofp.OFPP_FLOOD)]
                out = dp.ofproto_parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
                dp.send_msg(out)