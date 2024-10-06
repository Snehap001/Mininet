from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet, ethernet,lldp, ether_types
from ryu.topology import event as topo_event
from ryu.topology.api import get_host
import time
import logging
class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.logger = logging.getLogger('my_logger')
        self.logger.setLevel(logging.DEBUG)

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(formatter)

        # Add handler to logger
        self.logger.addHandler(console_handler)
        self.links={}

        # stores link delay for every (mac1,mac2) link
        self.link_delays={}
        self.datapaths={}
        self.adj_lists={}

        #stores (switch_dpid,port) to mac address mapping
        self.hostmac_to_switch_port={}
        self.path={}
        self.sent_timestamps={}
        
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
        ldelpkt = lldp.SystemDescription(system_description=b'SDN')
        lldp_pkt.add_protocol(lldp.lldp(tlvs=[chassis_id, port_id, ttl,ldelpkt]))
        lldp_pkt.serialize()
        return lldp_pkt
    def send_for_link_delay(self,link):
        src_dpid=link.src.dpid
        src_port=link.src.port_no
        dst_dpid=link.dst.dpid
        dst_port=link.dst.port_no
        src_mac=self.datapaths[src_dpid].ports[src_port].hw_addr
        dst_mac=self.datapaths[dst_dpid].ports[dst_port].hw_addr
        pkt=self.build_lldp_packet(src_dpid,src_port,src_mac)
        datapath=self.datapaths[src_dpid]
        actions = [datapath.ofproto_parser.OFPActionOutput(port=src_port)]
        out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=pkt.data  # The serialized LLDP packet data
        )
        self.sent_timestamps[(src_mac,dst_mac)]=time.time()
        datapath.send_msg(out)
    def set_min_links(self):
        # undirected_link_delays={}
        # for (sw1,sw2) in self.links:
        #     for (p1,p2) in self.links[(sw1,sw2)]:
        #         mac1=self.datapaths[(sw1,p1)]
        #         mac2=self.datapaths[(sw2,p2)]
        #         delay=0
        #         count=0
        #         if((mac1,mac2) in self.link_delays):
        #             delay+=self.link_delays[(mac1,mac2)]
        #             count+=1
        #         if((mac2,mac1) in self.link_delays):
        #             delay+=self.link_delays[(mac2,mac1)]
        #             count+=1
        #         if(count==0):
        #             undirected_link_delays[(mac1,mac2)]=float('inf')
        #             continue
        #         delay=(delay/count)
        #         undirected_link_delays[(mac1,mac2)]=delay
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

        match = datapath.ofproto_parser.OFPMatch(
            dl_dst=haddr_to_bin(dst))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=300, hard_timeout=300,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)
    def add_broadcast_flow(self, datapath, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            dl_dst=haddr_to_bin('ff:ff:ff:ff:ff:ff'))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=300, hard_timeout=300,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)
    def broadcast_handler(self,ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        src = eth.src
        dpid = datapath.id
        in_port=msg.in_port

        actions=[]
        selected_ports=set()
        for (dpid_,port) in self.port_to_mac:
            if((dpid==dpid_) and (port!=in_port)):
                selected_ports.add(port)
        for (host,switch) in self.host_to_switch:
            if(switch==dpid):
                port=self.mac_to_switch_port[host]
                if ((host!=src) and (port!=in_port)):
                    selected_ports.add(port)
        for port in selected_ports:
            actions.append(datapath.ofproto_parser.OFPActionOutput(port))
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        self.add_broadcast_flow(datapath,actions)
        datapath.send_msg(out)
    def unicast_handler(self,ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        dst_mac = eth.dst      
        start_dpid = datapath.id
        end_dpid=self.hostmac_to_switch_port[dst_mac][0]
        if(start_dpid==end_dpid):
            out_port=self.hostmac_to_switch_port[dst_mac][1]
        else:
            next_hop=self.path[start_dpid][end_dpid][1]
            if((start_dpid,next_hop) in self.links):
                min_del_link = min(self.links[start_dpid][next_hop], key=lambda link: self.link_delays[(self.dpset.get_port(start_dpid,link[0]),self.dpset.get_port(next_hop,link[1]))])
                out_port=min_del_link[0]
            else:
                min_del_link = min(self.links[next_hop][start_dpid], key=lambda link: self.link_delays[(self.dpset.get_port(next_hop,link[0]),self.dpset.get_port(start_dpid,link[1]))])
                out_port=min_del_link[1]
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
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
        in_port = msg.match['in_port']
        dst_mac = datapath.ports[in_port].hw_addr
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            lldp_pkt = pkt.get_protocol(lldp.lldp)
            for tlv in lldp_pkt.tlvs:
                if isinstance(tlv, lldp.SystemDescription):
                    if tlv.system_description == b'SDN':
                        send_time = self.sent_timestamps.get((src_mac,dst_mac))
                        link_delay = recv_time-send_time  
                        del self.sent_timestamps[(src_mac,dst_mac)]
                        self.link_delays[(src_mac,dst_mac)]=link_delay
                        self.logger.info(link_delay)
                        self.run_floyd_warshall()
            return 
        if dst_mac=='ff:ff:ff:ff:ff:ff':
            self.broadcast_handler(ev)
        else:
            self.unicast_handler(ev)
    @set_ev_cls(topo_event.EventSwitchEnter, MAIN_DISPATCHER)
    def switch_enter_handler(self, ev):
        # Get the datapath object
        datapath = ev.switch.dp
        # Get the DPID (Datapath ID)
        dpid = datapath.id
        self.logger.info("Added switch")
        self.datapaths[dpid]=datapath
    @set_ev_cls(topo_event.EventHostAdd, MAIN_DISPATCHER)
    def host_add_handler(self, ev):
        self.logger.info("Host added")
        hosts=get_host(self,None)
        mac_addresses=[]
        for host in hosts:
            mac_addresses.append(host.hw_addr)
            self.logger.info("Address : "+str(host.hw_addr))
        host = ev.host  # Get the host object from the event
        self.hosts.add(host.hw_addr)  # Add the host to the list
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