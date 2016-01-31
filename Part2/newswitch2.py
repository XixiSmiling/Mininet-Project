# Copyright 2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
This component is for use with the OpenFlow tutorial.

It acts as a simple hub, but can be modified to act like an L2
learning switch.

It's roughly similar to the one Brandon Heller did for NOX.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as myPkt
import pox.lib.addresses as myAddr

log = core.getLogger()



class Tutorial (object):
  """
  A Tutorial object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

    # Use this table to keep track of which ethernet address is on
    # which switch port (keys are MACs, values are ports).
    self.mac_to_port1 = {}
    self.mac_to_port2 = {}
    # for handle ARP, we need arp cache, ip to port dictionary, routing table
    self.arp_cache1 = {'10.0.1.100': "00:00:00:00:00:01", '10.0.2.100': "00:00:00:00:00:02", '10.0.1.1': "12:12:12:12:12:12", '10.0.2.1': "12:12:12:12:12:12"}
    self.arp_cache2 = {'10.0.3.100': "00:00:00:00:00:03", '10.0.4.100': "00:00:00:00:00:04", '10.0.3.1': "34:34:34:34:34:34", '10.0.4.1': "34:34:34:34:34:34"}
    self.ip_to_port1 = {'10.0.1.100':1, '10.0.2.100':2, '10.0.3.100':3, '10.0.4.100':3}
    self.ip_to_port2 = {'10.0.3.100':1, '10.0.4.100':2, '10.0.1.100':3, '10.0.2.100':3}
    self.routing_table1 = {'10.0.1.100' : ['10.0.1.100/24', 's1-eth1', '10.0.1.1', 1], '10.0.2.100' : ['10.0.2.100/24', 's1-eth2', '10.0.2.1', 2], '10.0.3.100' : ['10.0.3.100/24', 's1-eth3', '10.0.5.1', 3], '10.0.4.100' : ['10.0.4.100/24', 's1-eth3', '10.0.5.1', 3]}
    self.routing_table2 = {'10.0.3.100' : ['10.0.3.100/24', 's2-eth1', '10.0.3.1', 1], '10.0.4.100' : ['10.0.4.100/24', 's2-eth2', '10.0.4.1', 2], '10.0.1.100' : ['10.0.1.100/24', 's2-eth3', '10.0.6.1', 3], '10.0.2.100' : ['10.0.2.100/24', 's2-eth3', '10.0.6.1', 3]}

  def resend_packet (self, packet_in, out_port):
    """
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to the
    controller due to a table-miss.
    """
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)

  def sendFlowMod(self, packet, packet_in, pktport):
    """
    Implement Flow Mod
    """
    # Create a match for the type of packet
    match = of.ofp_match.from_packet(packet)
    match.in_port = packet_in.in_port
    
    # Create an of_flow_mod structure, and set the match attribute to your match
    msg = of.ofp_flow_mod()
    msg.match = match
    msg.cookie = 0
    msg.command = of.OFPFC_ADD
    msg.idle_timeout = 240
    msg.hard_timeout = 30
    msg.flags = of.OFPFF_SEND_FLOW_REM
    msg.priority = of.OFP_DEFAULT_PRIORITY
    msg.buffer_id = packet_in.buffer_id
    
    # Specify the actions to be taken
    # actions = of.ofp_action_output(port = packet_in.in_port)
    
    # Append each action to the flow mod structure
    # for act in actions:
    # msg.actions.append(act)
    msg.actions.append(of.ofp_action_output(port = pktport))
    
    # Send the flow mod back to the router
    log.debug("sending Flow Mod...")
    self.connection.send(msg)
    log.debug("Flow Mod Sent Successfully");

  def act_like_switch (self, event, packet, packet_in):
    """
    Implement router-like behavior.
    """
    # handle ARP
    if packet.type == myPkt.ethernet.ARP_TYPE:
        # ref: pox/pox/proto/arp_helper.py && arp_responder.py && pong.py
        a = packet.payload
        if a.opcode == myPkt.arp.REQUEST:
            log.debug("port %s ARP request %s => %s", str(packet_in.in_port), str(a.protosrc), str(a.protodst))
            r = myPkt.arp()
            r.hwtype = a.hwtype
            r.prototype = a.prototype
            r.hwlen = a.hwlen
            r.protolen = a.protolen
            r.opcode = myPkt.arp.REPLY
            r.hwdst = a.hwsrc
            if str(a.protodst) == '10.0.1.1' or str(a.protodst) == '10.0.2.1':
                r.hwsrc = myAddr.EthAddr("12:12:12:12:12:12")
            elif str(a.protodst) == "10.0.3.1" or str(a.protodst) == "10.0.4.1":
                r.hwsrc = myAddr.EthAddr("34:34:34:34:34:34")
            else:
                return
            r.protodst = a.protosrc
            r.protosrc = a.protodst
            e = myPkt.ethernet()
            e.type = myPkt.ethernet.ARP_TYPE
            e.dst = a.hwsrc
            e.src = r.hwsrc
            e.payload = r
            #log.debug("Answer ARP for " + str(r.protosrc))
            msg = of.ofp_packet_out()
            msg.data = e.pack()
            msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
            msg.in_port = event.port
            event.connection.send(msg)
        elif packet.payload.opcode == myPkt.arp.REPLY:
            log.debug("port %s ARP reply %s => %s", str(packet_in.in_port), str(a.protosrc), str(a.hwsrc))
        else:
            log.debug("Router receive Other ARP packet")
            
    # handle ICMP
    elif packet.type == myPkt.ethernet.IP_TYPE:
        src_ip = packet.payload.srcip
        dst_ip = packet.payload.dstip
        if packet.payload.protocol == myPkt.ipv4.ICMP_PROTOCOL:
            #ref: pox/pox/proto/pong.py && pox/pox/lib/packet/icmp.py
            if str(packet.dst) == "12:12:12:12:12:12":
                if self.arp_cache1.get(dst_ip):
                    #log.debug("packet.src = %s, packet.dst = %s", str(packet.src), str(packet.dst))
                    icmp_reply = myPkt.icmp()
                    icmp_reply.type = myPkt.TYPE_ECHO_REPLY
                    icmp_reply.payload = packet.find("icmp").payload
                    ip_pkt = myPkt.ipv4()
                    ip_pkt.protocol = myPkt.ipv4.ICMP_PROTOCOL
                    ip_pkt.srcip = packet.find("ipv4").dstip
                    ip_pkt.dstip = packet.find("ipv4").srcip
                    icmp_frame = myPkt.ethernet()
                    icmp_frame.type = myPkt.ethernet.IP_TYPE
                    icmp_frame.dst = packet.src
                    icmp_frame.src = packet.dst
                    ip_pkt.payload = icmp_reply
                    icmp_frame.payload = ip_pkt
                    msg = of.ofp_packet_out()
                    msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
                    msg.data = icmp_frame.pack()
                    msg.in_port = event.port
                    event.connection.send(msg)
                    log.debug("%s pinged %s", str(ip_pkt.dstip), str(ip_pkt.srcip))
                else:
                    icmp_reply = myPkt.icmp()
                    icmp_reply.type = myPkt.TYPE_DEST_UNREACH
                    unreach_msg = myPkt.unreach()
                    unreach_msg.payload = packet.payload
                    icmp_reply.payload = unreach_msg
                    ip_pkt = myPkt.ipv4()
                    ip_pkt.protocol = myPkt.ipv4.ICMP_PROTOCOL
                    ip_pkt.srcip = packet.find("ipv4").dstip
                    ip_pkt.dstip = packet.find("ipv4").srcip
                    icmp_frame = myPkt.ethernet()
                    icmp_frame.type = myPkt.ethernet.IP_TYPE
                    icmp_frame.dst = packet.src
                    icmp_frame.src = packet.dst
                    ip_pkt.payload = icmp_reply
                    icmp_frame.payload = ip_pkt
                    msg = of.ofp_packet_out()
                    msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
                    msg.data = icmp_frame.pack()
                    msg.in_port = event.port
                    event.connection.send(msg)
                    log.debug("%s pinged %s failed", str(ip_pkt.dstip), str(ip_pkt.srcip))
            if str(packet.dst) == "34:34:34:34:34:34":
                if self.arp_cache2.get(dst_ip):
                    #log.debug("packet.src = %s, packet.dst = %s", str(packet.src), str(packet.dst))
                    icmp_reply = myPkt.icmp()
                    icmp_reply.type = myPkt.TYPE_ECHO_REPLY
                    icmp_reply.payload = packet.find("icmp").payload
                    ip_pkt = myPkt.ipv4()
                    ip_pkt.protocol = myPkt.ipv4.ICMP_PROTOCOL
                    ip_pkt.srcip = packet.find("ipv4").dstip
                    ip_pkt.dstip = packet.find("ipv4").srcip
                    icmp_frame = myPkt.ethernet()
                    icmp_frame.type = myPkt.ethernet.IP_TYPE
                    icmp_frame.dst = packet.src
                    icmp_frame.src = packet.dst
                    ip_pkt.payload = icmp_reply
                    icmp_frame.payload = ip_pkt
                    msg = of.ofp_packet_out()
                    msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
                    msg.data = icmp_frame.pack()
                    msg.in_port = event.port
                    event.connection.send(msg)
                    log.debug("%s pinged %s", str(ip_pkt.dstip), str(ip_pkt.srcip))
                else:
                    icmp_reply = myPkt.icmp()
                    icmp_reply.type = myPkt.TYPE_DEST_UNREACH
                    unreach_msg = myPkt.unreach()
                    unreach_msg.payload = packet.payload
                    icmp_reply.payload = unreach_msg
                    ip_pkt = myPkt.ipv4()
                    ip_pkt.protocol = myPkt.ipv4.ICMP_PROTOCOL
                    ip_pkt.srcip = packet.find("ipv4").dstip
                    ip_pkt.dstip = packet.find("ipv4").srcip
                    icmp_frame = myPkt.ethernet()
                    icmp_frame.type = myPkt.ethernet.IP_TYPE
                    icmp_frame.dst = packet.src
                    icmp_frame.src = packet.dst
                    ip_pkt.payload = icmp_reply
                    icmp_frame.payload = ip_pkt
                    msg = of.ofp_packet_out()
                    msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
                    msg.data = icmp_frame.pack()
                    msg.in_port = event.port
                    event.connection.send(msg)
                    log.debug("%s pinged %s failed", str(ip_pkt.dstip), str(ip_pkt.srcip))
            
  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.

    # handle static routing
    if packet.type == myPkt.ethernet.IP_TYPE:
        if packet.payload.protocol != myPkt.ipv4.ICMP_PROTOCOL:
            src_ip = packet.payload.srcip
            dst_ip = packet.payload.dstip
            log.debug("Receive a parket from " + str(src_ip) + " to " + str(dst_ip))
            if str(packet.dst) == "12:12:12:12:12:12":
                if self.ip_to_port1.get(dst_ip):
                    #log.debug("sending parket to " + str(dst_ip))
                    log.debug(str(packet.src) + "  " + str(packet.dst))
                    packet.src = packet.dst
                    if str(dst_ip) == "10.0.1.100" or str(dst_ip) == "10.0.2.100":
                        packet.dst = myAddr.EthAddr(self.arp_cache1[str(dst_ip)])
                    else:
                        packet.dst = myAddr.EthAddr("34:34:34:34:34:34")
                    log.debug(str(packet.src) + "  " + str(packet.dst))
                    msg = of.ofp_packet_out()
                    msg.actions.append(of.ofp_action_output(port = self.ip_to_port1[str(dst_ip)]))
                    msg.data = packet.pack()
                    msg.in_port = event.port
                    event.connection.send(msg)
                else:
                    log.debug("Don't know this packet destination IP address")
            if str(packet.dst) == "34:34:34:34:34:34":
                if self.ip_to_port2.get(dst_ip):
                    #log.debug("sending parket to " + str(dst_ip))
                    log.debug(str(packet.src) + "  " + str(packet.dst))
                    packet.src = packet.dst
                    if str(dst_ip) == "10.0.3.100" or str(dst_ip) == "10.0.4.100":
                        packet.dst = myAddr.EthAddr(self.arp_cache2[str(dst_ip)])
                    else:
                        packet.dst = myAddr.EthAddr("12:12:12:12:12:12")
                    log.debug(str(packet.src) + "  " + str(packet.dst))
                    msg = of.ofp_packet_out()
                    msg.actions.append(of.ofp_action_output(port = self.ip_to_port2[str(dst_ip)]))
                    msg.data = packet.pack()
                    msg.in_port = event.port
                    event.connection.send(msg)
                else:
                    log.debug("Don't know this packet destination IP address")
    # Comment out the following line and uncomment the one after
    # when starting the exercise.
    #self.act_like_hub(packet, packet_in)
    self.act_like_switch(event, packet, packet_in)



def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Tutorial(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
