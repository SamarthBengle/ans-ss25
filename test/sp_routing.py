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

#!/usr/bin/env python3

import heapq

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase

import topo

class SPRouter(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SPRouter, self).__init__(*args, **kwargs)
        
        # Initialize the topology with #ports=4
        self.topo_net = topo.Fattree(4)
        # dpid -> list of (neighbor_dpid, out_port, weight)
        self.adjacency = {}
        # (src_dpid, dst_dpid) -> out_port
        self.port_map = {}
        # {IPv4: (dpid, in_port)}
        self.host_map = {}
        self.switch_dpids = {}


    # Topology discovery
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):

        # Switches and links in the network
        switches = get_switch(self, None)
        links = get_link(self, None)

        self.switch_dpids = {sw.dp.id: sw.dp for sw in switches}
        self.adjacency = {dpid: [] for dpid in self.switch_dpids}
        self.port_map = {}

        for link in links:
            src = link.src; dst = link.dst
            src_dpid = src.dpid; dst_dpid = dst.dpid
            src_port = src.port_no; dst_port = dst.port_no

            self.port_map[(src_dpid, dst_dpid)] = src_port
            self.port_map[(dst_dpid, src_dpid)] = dst_port

            self.adjacency[src_dpid].append((dst_dpid, src_port, 1))
            self.adjacency[dst_dpid].append((src_dpid, dst_port, 1))

        self.logger.info("topology discovered: %d switches, %d links",
                         len(switches), len(links))


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install entry-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)


    # Add a flow entry to the flow-table
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Construct flow_mod message and send it
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignore LLDP packets
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # --- ARP Packet Handling ---
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip
            
            # Learn source host location (IP -> MAC, and MAC -> Port)
            self.host_map[src_ip] = (dpid, in_port)

            # If destination is unknown, flood the ARP request
            if dst_ip not in self.host_map:
                actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                        in_port=in_port, actions=actions, data=msg.data)
                datapath.send_msg(out)
            # If destination is known, send the ARP reply directly to it
            else:
                dst_dpid, dst_port = self.host_map[dst_ip]
                dp = self.switch_dpids[dst_dpid]
                actions = [parser.OFPActionOutput(dst_port)]
                out = parser.OFPPacketOut(datapath=dp, buffer_id=ofproto.OFP_NO_BUFFER,
                                        in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=msg.data)
                dp.send_msg(out)
            return

        # --- IP Packet Handling ---
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt:
            src_ip = ipv4_pkt.src
            dst_ip = ipv4_pkt.dst

            # Learn source host location
            self.host_map[src_ip] = (dpid, in_port)

            # If destination host is known, install path
            if dst_ip in self.host_map:
                src_dpid, _ = self.host_map[src_ip]
                dst_dpid, dst_port = self.host_map[dst_ip]

                # FIX for same-switch traffic
                if src_dpid == dst_dpid:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=dst_ip)
                    actions = [parser.OFPActionOutput(dst_port)]
                    self.add_flow(datapath, 10, match, actions)
                    # Also send the packet out
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                            in_port=in_port, actions=actions, data=msg.data)
                    datapath.send_msg(out)
                    return

                # Calculate path for inter-switch traffic
                prev = self.dijkstra(src_dpid)
                path = self.get_path(src_dpid, dst_dpid, prev)

                if not path: return

                # Install flow rules along the path (matching only on destination)
                for i in range(len(path) - 1):
                    sw1_dpid = path[i]
                    sw2_dpid = path[i+1]
                    out_port = self.port_map.get((sw1_dpid, sw2_dpid))
                    if out_port:
                        dp = self.switch_dpids[sw1_dpid]
                        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=dst_ip)
                        actions = [parser.OFPActionOutput(out_port)]
                        self.add_flow(dp, 10, match, actions)

                # Install rule for the final hop to the host
                last_dp = self.switch_dpids[dst_dpid]
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=dst_ip)
                actions = [parser.OFPActionOutput(dst_port)]
                self.add_flow(last_dp, 10, match, actions)

                # Send the current packet out along the first hop
                first_hop_port = self.port_map.get((path[0], path[1]))
                if first_hop_port:
                    actions = [parser.OFPActionOutput(first_hop_port)]
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                            in_port=in_port, actions=actions, data=msg.data)
                    datapath.send_msg(out)


    def dijkstra(self, src_dpid):
        dist = {dpid: float('inf') for dpid in self.adjacency}
        prev = {dpid: None for dpid in self.adjacency}

        dist[src_dpid] = 0
        heap = [(0, src_dpid)]

        while heap:
            current_dist, u = heapq.heappop(heap)
            if current_dist > dist[u]: continue

            for neighbor, _, weight in self.adjacency[u]:
                alt = dist[u] + weight
                if alt < dist[neighbor]:
                    dist[neighbor] = alt
                    prev[neighbor] = u
                    heapq.heappush(heap, (alt, neighbor))

        return prev

    def get_path(self, src, dst, prev):
        path = []
        while dst is not None:
            path.insert(0, dst)
            dst = prev[dst]
        return path if path[0] == src else []