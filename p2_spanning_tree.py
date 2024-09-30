from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import hub  # Import hub for threading
from ryu.topology.api import get_switch, get_link,get_host  # Import topology API
from ryu.lib.packet import icmp
import heapq
class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.links ={}  
        self.spanning_tree_ports = {}
        self.host_links={}
        hub.spawn(self.monitor_topology)
    def monitor_topology(self):
        while len(self.links)==0:
            self.links = self.get_links()
            hub.sleep(5)
    def get_links(self):
        # Retrieve the current topology state
        link_list = get_link(self, None)
        links={}
        for link in link_list:
            src = link.src
            dst = link.dst
            if (src.dpid,dst.dpid) not in links and  (dst.dpid,src.dpid) not in links:
                links[(src.dpid,dst.dpid)]=(src.port_no,dst.port_no)
        host_list = get_host(self, None)
        host_links = {}
        for host in host_list:
            # Each host object has port information about the switch it is connected to
            host_mac = host.mac
            host_ip = host.ipv4 if host.ipv4 else host.ipv6
            switch_dpid = host.port.dpid
            switch_port_no = host.port.port_no

            # Store the host-switch link
            host_links[switch_dpid] = {
                'host': host_mac,
                'switch_port': switch_port_no
            }
        self.host_links=host_links
        
        return links

    def get_neighbors(self):
        neighbor_list={}
        for (s1, s2), (p1, p2) in self.links.items():
            if s1 not in neighbor_list:
                neighbor_list[s1]=[]
            if s2 not in neighbor_list:
                neighbor_list[s2]=[]
            if  s2 not in neighbor_list[s1]:
                neighbor_list[s1].append(s2)
            if s1 not in neighbor_list[s2]:
                neighbor_list[s2].append(s1)
        return neighbor_list
        

    

    def construct_spanning_tree(self):
        links=self.links
        self.spanning_tree_ports={}
        if len(links)==0:
            return
        switches=set()
        for (s1, s2), (p1, p2) in links.items():
            self.spanning_tree_ports[s1]=[]
            self.spanning_tree_ports[s2]=[]
            switches.add(s1)
            switches.add(s2)

        neighbors=self.get_neighbors()
        (sw1,sw2),(p1,p2)=next(iter(links.items()))
        minheap=[(0,sw1,None)]
        visited=set()
        
        while len(visited)!=len(switches):
            cost,current,parent=heapq.heappop(minheap)
            if parent!=None:
                if current not in self.spanning_tree_ports[parent]:
                    self.spanning_tree_ports[parent].append(current)
                if parent not in self.spanning_tree_ports[current]:
                    self.spanning_tree_ports[current].append(parent)
            if current in visited:
                continue
            visited.add(current)
            for adj in neighbors[current]:
                if adj not in visited:
                    heapq.heappush(minheap,(cost+1,adj,current))
        


    def add_flow(self, datapath, in_port, dst, src, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port,
            dl_dst=haddr_to_bin(dst), dl_src=haddr_to_bin(src))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=300, hard_timeout=300,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if len(self.spanning_tree_ports)==0:
            
            return
        # self.logger.info(f"spanning tree is : {self.spanning_tree_ports}")
        # self.logger.info(f"links: {self.links}")
        # self.logger.info(f"host links: {self.host_links} ")
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = msg.in_port
        self.logger.info(f"packet from {src} to {dst} at {dpid}")
        
        if dst=='ff:ff:ff:ff:ff:ff' or dst=='33:33:00:00:00:02':
            actions=[]
            neighbor_switches=self.spanning_tree_ports[dpid]
            selected_ports=[]
            for sw in neighbor_switches:
                if (dpid,sw) in self.links:
                    p1,p2=self.links[(dpid,sw)]
                else:
                    p2,p1=self.links[(sw,dpid)]
                if p1!=msg.in_port and p1 not in selected_ports:
                    selected_ports.append(p1)
            
            if dpid in self.host_links:
                host_mac,switch_port = self.host_links[dpid]['host'],self.host_links[dpid]['switch_port']
                if host_mac!=src and switch_port!=-msg.in_port and switch_port not in selected_ports:
                    selected_ports.append(switch_port)

            self.logger.info(f"ports of {dpid} are : {selected_ports}")
            for port in selected_ports:
                actions.append(datapath.ofproto_parser.OFPActionOutput(port))
            data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
                actions=actions, data=data)

            datapath.send_msg(out)

            return



        if dst in self.mac_to_port[dpid]:
            out_port=self.mac_to_port[dpid][dst]
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            self.logger.info(f"out port: {out_port}")

        else:
            actions=[]
            neighbor_switches=self.spanning_tree_ports[dpid]
            selected_ports=[]
            for sw in neighbor_switches:
                if (dpid,sw) in self.links:
                    p1,p2=self.links[(dpid,sw)]
                else:
                    p2,p1=self.links[(sw,dpid)]
                if p1!=msg.in_port:
                    selected_ports.append(p1)
            if dpid in self.host_links:
                host_mac,switch_port = self.host_links[dpid]['host'],self.host_links[dpid]['switch_port']
                if host_mac!=src and switch_port!=-msg.in_port and switch_port not in selected_ports:
                    selected_ports.append(switch_port)
            self.logger.info(f"ports of {dpid} are : {selected_ports}")
            for port in selected_ports:
                actions.append(datapath.ofproto_parser.OFPActionOutput(port))

            out_port=-1
            
        
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        if out_port != -1:
            self.add_flow(datapath, msg.in_port, dst, src, actions)

        datapath.send_msg(out)

       


    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)
        
        hub.sleep(1)
        self.construct_spanning_tree()

        