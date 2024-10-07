from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls,CONFIG_DISPATCHER
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet,lldp, ether_types
from ryu.topology import event as topo_event
import time
import logging
class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.logger = logging.getLogger('my_logger')
        self.logger.setLevel(logging.INFO)
        self.links={}

        # stores link delay for every (mac1,mac2) link
        self.link_delays={}
        self.datapaths={}
        self.adj_lists={}

        #stores (switch_dpid,port) to mac address mapping
        self.mac_to_switch_port={}
        self.path={}
        
    def build_lldp_packet(self, src_dpid,src_port,src_mac):
        # Create Ethernet frame
        eth = ethernet.ethernet(
            dst=lldp.LLDP_MAC_NEAREST_BRIDGE,  # Destination MAC for LLDP
            src=src_mac,  # Source MAC is switch port's MAC
            ethertype=ethernet.ether.ETH_TYPE_LLDP  # LLDP EtherType
        )     
        # Create LLDP Chassis ID and Port ID
        chassis_id = lldp.ChassisID(
            subtype=lldp.ChassisID.SUB_LOCALLY_ASSIGNED,
            chassis_id=str(src_dpid).encode('utf-8') ## datapath id
        )
        port_id = lldp.PortID(
            subtype=lldp.PortID.SUB_PORT_COMPONENT,
            port_id= str(src_port).encode('utf-8')## port number
        )
        ttl = lldp.TTL(ttl=120)  # Time-to-live for LLDP packet
        # Build the LLDP packet with Ethernet and LLDP protocols
        
        ## Code Build LLDP packet
        lldp_pkt = packet.Packet()
        lldp_pkt.add_protocol(eth)
        tm=time.time()
        descr=f'SDN-{tm}'
        ldelpkt = lldp.SystemDescription(system_description=descr.encode('utf-8'))
        lldp_pkt.add_protocol(lldp.lldp(tlvs=[chassis_id, port_id, ttl,ldelpkt]))
        lldp_pkt.serialize()
        return lldp_pkt
    def send_for_link_delay(self,link):
        src_dpid=link.src.dpid
        src_port=link.src.port_no
        src_mac=self.datapaths[src_dpid].ports[src_port].hw_addr
        datapath=self.datapaths[src_dpid]
        actions = [datapath.ofproto_parser.OFPActionOutput(port=src_port)]
        pkt=self.build_lldp_packet(src_dpid,src_port,src_mac)
        out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=pkt.data  # The serialized LLDP packet data
        )
        datapath.send_msg(out)
    def set_min_links(self):
        for (sw1,sw2) in self.links:
            all_links=self.links[(sw1,sw2)]
            min_del_link = min(all_links, key=lambda link: self.link_delays[(self.datapaths[sw1].ports[link[0]].hw_addr,self.datapaths[sw2].ports[link[1]].hw_addr)])
            if sw1 in self.adj_lists:
                delay=self.link_delays[(self.datapaths[sw1].ports[min_del_link[0]].hw_addr,self.datapaths[sw2].ports[min_del_link[1]].hw_addr)]
                self.adj_lists[sw1].append((sw2,delay))
            else:
                delay=self.link_delays[(self.datapaths[sw1].ports[min_del_link[0]].hw_addr,self.datapaths[sw2].ports[min_del_link[1]].hw_addr)]
                self.adj_lists[sw1]=[(sw2,delay)]
    def run_floyd_warshall(self):
        self.set_min_links()
        switch_list=list(self.adj_lists.keys())
        dist = {switch: {other: float('inf') for other in switch_list} for switch in switch_list}
        path = {switch: {other: [] for other in switch_list} for switch in switch_list}
        for switch in switch_list:
            dist[switch][switch] = 0
            path[switch][switch]= [switch]
            for (neighbor, weight) in self.adj_lists[switch]:
                dist[switch][neighbor] = weight
                path[switch][neighbor] = [switch,neighbor]
        for sw1 in switch_list:
            for sw2 in switch_list:
                for sw3 in switch_list:
                    if(dist[sw2][sw1] + dist[sw1][sw3] < dist[sw2][sw3]):
                        dist[sw2][sw3] = dist[sw2][sw1] + dist[sw1][sw3] 
                        path[sw2][sw3] = path[sw2][sw1] + path[sw1][sw3][1:] 
        self.path=path
    def add_unicast_flow(self, datapath, dst, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = datapath.ofproto_parser.OFPMatch(
            eth_dst=dst)
        instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
        datapath=datapath,
        priority=ofproto.OFP_DEFAULT_PRIORITY,
        match=match,
        instructions=instructions,
        idle_timeout=300,
        hard_timeout=300
        )
        datapath.send_msg(mod)
    def add_broadcast_flow(self, datapath, dst_mac,actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            eth_dst=dst_mac)

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=300, hard_timeout=300,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, action=actions)
        datapath.send_msg(mod)
    def broadcast_handler(self,ev,dst_mac):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        pkt = packet.Packet(msg.data)
        flood_action = [datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_FLOOD)]
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.match['in_port'],
            actions=flood_action, data=data)
        self.add_broadcast_flow(datapath,dst_mac,flood_action)
        datapath.send_msg(out)
    def unicast_handler(self,ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        dst_mac = eth.dst      
        start_dpid = datapath.id
        end_dpid=self.mac_to_switch_port[dst_mac][0]
        if(start_dpid==end_dpid):
            out_port=self.mac_to_switch_port[dst_mac][1]
        else:
            next_hop=self.path[start_dpid][end_dpid][1]
            min_delay = float('inf')  # Start with an infinitely large delay
            min_del_link = None 
            for link in self.links[(start_dpid,next_hop)]:
                # Get the MAC addresses for the ports on each end of the link
                src_hw_addr = self.datapaths[start_dpid].ports[link[0]].hw_addr
                dst_hw_addr = self.datapaths[next_hop].ports[link[1]].hw_addr
                delay = self.link_delays[(src_hw_addr, dst_hw_addr)]
                if delay < min_delay:
                    min_delay = delay
                    min_del_link = link 
            out_port=min_del_link[0]
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.match['in_port'],
            actions=actions, data=data)
        self.add_unicast_flow(datapath, dst_mac, actions)
        datapath.send_msg(out)
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        recv_time=time.time()   
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        datapath = msg.datapath
        eth = pkt.get_protocol(ethernet.ethernet)
        src_mac=eth.src
        dst_mac=eth.dst
        in_port = msg.match['in_port']
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            lldp_pkt = pkt.get_protocol(lldp.lldp)
            for tlv in lldp_pkt.tlvs:
                if isinstance(tlv, lldp.SystemDescription):
                    descr=tlv.system_description.decode('utf-8')
                    if  descr.startswith('SDN'):
                        src_mac=eth.src
                        dst_mac = datapath.ports[in_port].hw_addr
                        _, send_time = descr.split("-")
                        send_time=float(send_time)
                        link_delay = (recv_time-send_time)*1000
                        self.link_delays[(src_mac,dst_mac)]=link_delay
                        self.logger.info("Source mac : "+str(src_mac)+ " Destination mac : "+str(dst_mac)+" "+str(link_delay))
                        self.run_floyd_warshall()
            return 
        if(src_mac not in self.mac_to_switch_port):
            self.mac_to_switch_port[src_mac]=(datapath.id,in_port)
        if (dst_mac.startswith("33:33") or dst_mac.startswith("01:00:5e") or (dst_mac=='ff:ff:ff:ff:ff:ff')):
            self.broadcast_handler(ev,dst_mac)
        elif(dst_mac in self.mac_to_switch_port):
            self.unicast_handler(ev)
        else:
            actions = [datapath.ofproto_parser.OFPActionOutput(ofproto_v1_3.OFPP_FLOOD)]
            data = None
            if msg.buffer_id == ofproto_v1_3.OFP_NO_BUFFER:
                data = msg.data
            out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
                actions=actions, data=data)
            datapath.send_msg(out)
    @set_ev_cls(topo_event.EventSwitchEnter, MAIN_DISPATCHER)
    def switch_enter_handler(self, ev):
        # Get the datapath object
        datapath = ev.switch.dp
        # Get the DPID (Datapath ID)
        dpid = datapath.id
        self.datapaths[dpid]=datapath
    @set_ev_cls(topo_event.EventLinkAdd, MAIN_DISPATCHER)
    def add_link(self,ev):
        link=ev.link
        sw1=link.src.dpid
        sw2=link.dst.dpid
        p1=link.src.port_no
        p2=link.dst.port_no
        mac1=self.datapaths[sw1].ports[p1].hw_addr
        mac2=self.datapaths[sw2].ports[p2].hw_addr
        self.link_delays[(mac1,mac2)]=float('inf')
        self.send_for_link_delay(link)
        if (sw1,sw2) in self.links:
            self.links[(sw1,sw2)].append((p1,p2))
        else:
            self.links[(sw1,sw2)]=[(p1,p2)]
        return
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)