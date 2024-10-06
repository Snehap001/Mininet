from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet, ethernet,lldp
from ryu.topology import event as topo_event
import time
class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        print("p3 instantiated")

        self.links={}

        # stores link delay for every (mac1,mac2) link
        self.link_delays={}

        self.adj_lists={}

        #stores (switch_dpid,port) to mac address mapping
        self.port_to_mac={}
        self.hostmac_to_switch_port={}
        self.path={}

        #stores link (mac1,mac2) to sent time mapping
        self.sent_timestamps={}

        self.mac_to_switch_port={}
        
    def build_lldp_packet(self, datapath, port_no):
        timestamp = time.time()
        # Create Ethernet frame
        eth = ethernet.ethernet(
            dst=lldp.LLDP_MAC_NEAREST_BRIDGE,  # Destination MAC for LLDP
            src=datapath.ports[port_no].hw_addr,  # Source MAC is switch port's MAC
            ethertype=ethernet.ether.ETH_TYPE_LLDP  # LLDP EtherType
        )     
        # Create LLDP Chassis ID and Port ID
        chassis_id = lldp.ChassisID(
            subtype=lldp.ChassisID.SUB_LOCALLY_ASSIGNED,
            chassis_id= ## datapath id
        )
        port_id = lldp.PortID(
            subtype=lldp.PortID.SUB_PORT_COMPONENT,
            port_id= ## port number
        )
        ttl = lldp.TTL(ttl=120)  # Time-to-live for LLDP packet
        # Build the LLDP packet with Ethernet and LLDP protocols
        
        ## Code Build LLDP packet
        lldp_pkt = packet.Packet()
        lldp_pkt.add_protocol(eth)
        lldp_pkt.add_protocol(lldp.lldp(tlvs=[chassis_id, port_id, ttl]))
        lldp_pkt.serialize()
        
        ## log the timestamp somewher
        return lldp_pkt
    def set_min_links(self):
        for (sw1,sw2) in self.links:
            all_links=self.links[(sw1,sw2)]
            min_del_link = min(all_links, key=lambda link: self.link_delays[(sw1,sw2,link[0],link[1])])
            if sw1 in self.adj_lists:
                self.adj_lists[sw1].append((sw2,min_del_link))
            else:
                self.adj_lists[sw1]=[(sw2,min_del_link)]
            if sw2 in self.adj_lists:
                self.adj_lists[sw2].append((sw1,min_del_link))
            else:
                self.adj_lists[sw2]=[(sw1,min_del_link)]
    def run_floyd_warshall(self):
        self.set_min_links()
        switch_list=list(self.adj_lists.keys())
        dist = {switch: {other: float('inf') for other in switch_list} for switch in switch_list}
        path = {switch: {other: [] for other in switch_list} for switch in switch_list}
        for switch in switch_list:
            dist[switch][switch] = 0
            path[switch][switch]= switch
            for neighbor, weight in self.adj_lists[switch].items():
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
        end_dpid=self.host_to_switch[dst_mac]
        if(start_dpid==end_dpid):
            out_port=self.mac_to_switch_port[dst_mac]
        else:
            next_hop=self.path[start_dpid][end_dpid][1]
            min_del_link = min(self.links[start_dpid][next_hop], key=lambda link: self.link_delays[(start_dpid,next_hop,link[0],link[1])])
            out_port=min_del_link[2]
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
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        dst_mac = eth.dst
        lldp_pkt = pkt.get_protocol(lldp.lldp)
        in_port = msg.match['in_port']
        if(lldp_pkt):
            send_time = self.sent_timestamps.get(in_port)
            link_delay = time.time() - send_time  
            del self.sent_timestamps[in_port]
            self.link_delays[()]
            return 
        if dst_mac=='ff:ff:ff:ff:ff:ff':
            self.broadcast_handler(ev)

        else:
            self.unicast_handler(ev)
    @set_ev_cls(topo_event.EventLinkAdd, MAIN_DISPATCHER)
    def add_link(self,ev):
        print("Link added")
        link=ev.link
        if(hasattr(link.src,'mac')):
            self.hostmac_to_switch_port[link.src.mac]=(link.dst.dpid,link.dst.port_no)
            return
        if(hasattr(link.dst,'mac')):
            self.hostmac_to_switch_port[link.dst.mac]=(link.src.dpid,link.src.port_no)
            return  
        sw1=link.src.dpid
        sw2=link.dst.dpid
        p1=link.src.port_no
        p2=link.dst.port_no
        mac1=link.src.mac
        delay=self.measure_link_delay(link)
        if (sw1,sw2) in self.links:
            self.port_to_mac[]
            self.links[(sw1,sw2)].append((p1,p2))
            self.link_delays[(sw1,sw2,p1,p2)]=delay
        elif (sw2,sw1) in self.links:
            self.links[(sw2,sw1)].append((p2,p1))
            self.link_delays[(sw2,sw1,p2,p1)]=delay
        else:
            self.links[(sw1,sw2)]=[(p1,p2)]
            self.link_delays[(sw1,sw2,p1,p2)]=delay
        self.run_floyd_warshall()
