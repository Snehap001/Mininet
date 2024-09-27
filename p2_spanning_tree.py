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
from ryu.topology.api import get_switch, get_link  # Import topology API
import heapq
class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.links = []  # List to store links
        self.spanning_tree_ports = {}
        # Start a separate thread to monitor topology changes
        hub.spawn(self.monitor_topology)
    def monitor_topology(self):
        while True:
            self.links = self.get_links()
              # Adjust the interval as needed
    def get_links(self):
        # Retrieve the current topology state
        links = []
        switch_list = get_switch(self)
        for switch in switch_list:
            for port in switch.ports:
                # Only consider links where the port is connected
                links.append((switch.dp.id, port.port_no))
        return links

    # Implement get_neighbors based on the links stored
    def get_neighbors(self, dpid):
        neighbor_list=[]
        for node,neighbor in self.links:
            if node==dpid and neighbor !=dpid and neighbor not in neighbor_list:
                neighbor_list.append(neighbor)
            # elif neighbor==dpid and node !=dpid and node not in neighbor_list:
            #     neighbor_list.append(node)
        return neighbor_list
        

    

    def construct_spanning_tree(self):
        # Use Prim's algorithm to create a spanning tree
        links = self.get_links() # Implement this method to get current links
        # self.logger.info(links)
        
        # Initialize spanning tree
        self.spanning_tree_ports = {}

        # Assuming you have a way to get the switches (dpids)
        for dpid in self.mac_to_port.keys():
            self.spanning_tree_ports[dpid] = []

        # Start Prim's algorithm
        if not self.mac_to_port:
            return
        visited = set()
        start_node = list(self.mac_to_port.keys())[0]
        min_heap=[(0, start_node,None)]
    
        while len(visited) !=len(list(self.mac_to_port.keys())):
            visited.add(start_node)
            if(min_heap):
                cost, node,parent= heapq.heappop(min_heap)
                # self.logger.info(f"node {node}")
                
                added=False
                for n in self.get_neighbors(node):
                    if n not in visited:
                        # self.logger.info(f"neighbor {n}")
                        added=True
                        visited.add(n)
                        if n not in self.spanning_tree_ports[node]:
                            self.spanning_tree_ports[node].append(n)
                        if node not in self.spanning_tree_ports[n]:
                            self.spanning_tree_ports[n].append(node)
                        heapq.heappush(min_heap, (1, n,node))
                        
                            
                if not added and len(self.get_neighbors(node))!=0 and cost==0:
                    n=self.get_neighbors(node)[0]
                    if n not in self.spanning_tree_ports[node]:
                        self.spanning_tree_ports[node].append(n)
                    if node not in self.spanning_tree_ports[n]:
                        self.spanning_tree_ports[n].append(node)

            else:
                for start_node in list(self.mac_to_port.keys()):
                    if start_node not in visited:
                        min_heap=[(0, start_node,None)]
                        
                        break


        
        self.logger.info("Spanning tree constructed: %s", self.spanning_tree_ports)


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
        

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)

        self.mac_to_port[dpid][src] = msg.in_port

        # Check if the dst is in the spanning tree
        out_port = ofproto.OFPP_FLOOD  # Default action is to flood
        # if dst in self.mac_to_port[dpid]:
        #     out_port = self.mac_to_port[dpid][dst]

        # Check if out_port is part of the spanning tree
        if out_port not in self.spanning_tree_ports.get(dpid, []):
            out_port = ofproto.OFPP_FLOOD  # Block if not part of the spanning tree
        # self.logger.info(f"Out port for packet: {out_port}, dst: {dst}, src: {src}")
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # Install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, msg.in_port, dst, src, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        datapath.send_msg(out)


    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        if reason in [msg.datapath.ofproto.OFPPR_ADD, msg.datapath.ofproto.OFPPR_DELETE]:
            self.construct_spanning_tree()  # Reconstruct the spanning tree
