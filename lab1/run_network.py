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

#!/bin/env python3

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel


class NetworkTopo(Topo):
    """Network Topology for Advanced Networked Systems Lab1"""

    def __init__(self):
        # Initialize the topology
        Topo.__init__(self)

        # Add hosts with their IP addresses and default gateways
        h1 = self.addHost( 'h1', ip = "10.0.1.2/24", defaultRoute = "via 10.0.1.1" )
        h2 = self.addHost( 'h2', ip = "10.0.1.3/24", defaultRoute = "via 10.0.1.1" )
        ext = self.addHost('ext', ip = "192.168.1.123/24", defaultRoute = "via 192.168.1.1")
        ser = self.addHost('ser', ip = "10.0.2.2/24", defaultRoute = "via 10.0.2.1")

        # Add switches (s1, s2) and router (s3)
        s1 = self.addSwitch('s1', dpid='1')  # Internal network switch
        s2 = self.addSwitch('s2', dpid='2')  # Server network switch
        router = self.addSwitch('s3', dpid='3')  # Router (implemented as a switch)

        # Add links with bandwidth and delay parameters
        # Internal network links
        self.addLink(s1, h1, bw=15, delay='10ms')
        self.addLink(s1, h2, bw=15, delay='10ms')
        
        # Server network link
        self.addLink(ser, s2, bw=15, delay='10ms')
        
        # Router links WITH IP configuration (critical for ARP to work properly)
        self.addLink(router, ext, bw=15, delay='10ms')
        self.addLink(s1, router, bw=15, delay='10ms')
        self.addLink(s2, router, bw=15, delay='10ms')


def run():
    topo = NetworkTopo()
    net = Mininet(topo=topo,
                  switch=OVSKernelSwitch,
                  link=TCLink,
                  controller=None)
    net.addController(
        'c1', 
        controller=RemoteController, 
        ip="127.0.0.1", 
        port=6653)
    net.start()
    CLI(net)
    net.stop()


if __name__ == '__main__':
    # Set log level
    setLogLevel('info')
    # Run the network
    run()