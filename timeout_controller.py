import time  # used to track time for flow lifetime

from ryu.base import app_manager  # base class for Ryu apps
from ryu.controller import ofp_event  # OpenFlow events

from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER  # states of switch
from ryu.controller.handler import set_ev_cls  # decorator for event handling

from ryu.lib.packet import ethernet  # ethernet packet parsing
from ryu.lib.packet import ether_types  # ethernet types like LLDP
from ryu.lib.packet import packet  # packet parser

from ryu.ofproto import ofproto_v1_3  # OpenFlow 1.3 protocol


class TimeoutController(app_manager.RyuApp):  # main controller class

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]  # set OpenFlow version

    IDLE_TIMEOUT = 10  # flow removed if no traffic for 10 sec
    HARD_TIMEOUT = 30  # flow removed after 30 sec no matter what
    FLOW_PRIORITY = 10  # priority of flow rules

    def __init__(self, *args, **kwargs):
        super(TimeoutController, self).__init__(*args, **kwargs)  # call parent constructor

        self.mac_to_port = {}  # stores MAC to port mapping
        self.active_flows = {}  # stores active flows using cookie
        self.flow_index = {}  # maps flow key to cookie
        self.cookie_counter = 1  # unique id generator for flows


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)  # triggered when switch connects
    def switch_features_handler(self, ev):

        datapath = ev.msg.datapath  # get switch object

        self.mac_to_port.setdefault(datapath.id, {})  # initialize mac table for this switch

        self.install_table_miss_flow(datapath)  # install default rule


    def install_table_miss_flow(self, datapath):

        ofproto = datapath.ofproto  # OpenFlow protocol
        parser = datapath.ofproto_parser  # message parser

        match = parser.OFPMatch()  # match all packets

        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]  # send to controller

        instructions = [
            parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)  # apply actions
        ]

        mod = parser.OFPFlowMod(
            datapath=datapath,  # switch
            priority=0,  # lowest priority
            match=match,  # match all
            instructions=instructions,  # action instructions
        )

        datapath.send_msg(mod)  # send rule to switch

        self.logger.info(
            "Installed permanent table-miss rule on switch %s",
            datapath.id,
        )


    def add_timed_flow(self, datapath, match, actions, flow_key):

        ofproto = datapath.ofproto  # protocol
        parser = datapath.ofproto_parser  # parser

        instructions = [
            parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)  # apply actions
        ]

        previous_cookie = self.flow_index.pop(flow_key, None)  # check if flow already exists

        if previous_cookie is not None:
            self.active_flows.pop(previous_cookie, None)  # remove old flow
            self.logger.info(
                "Refreshing timed flow on switch %s for %s",
                datapath.id,
                self.describe_flow_key(flow_key),
            )

        cookie = self.cookie_counter  # assign new cookie
        self.cookie_counter += 1  # increment counter

        mod = parser.OFPFlowMod(
            datapath=datapath,  # switch
            cookie=cookie,  # unique flow id
            priority=self.FLOW_PRIORITY,  # priority
            match=match,  # match condition
            instructions=instructions,  # actions
            idle_timeout=self.IDLE_TIMEOUT,  # idle timeout
            hard_timeout=self.HARD_TIMEOUT,  # hard timeout
            flags=ofproto.OFPFF_SEND_FLOW_REM,  # notify when flow removed
        )

        datapath.send_msg(mod)  # install flow

        self.active_flows[cookie] = {  # store flow info
            "flow_key": flow_key,
            "installed_at": time.time(),
        }

        self.flow_index[flow_key] = cookie  # map key to cookie

        self.logger.info(
            "Installed timed flow on switch %s for %s with idle_timeout=%ss hard_timeout=%ss",
            datapath.id,
            self.describe_flow_key(flow_key),
            self.IDLE_TIMEOUT,
            self.HARD_TIMEOUT,
        )


    def describe_flow_key(self, flow_key):
        dpid, in_port, src, dst = flow_key  # unpack values
        return "dpid=%s in_port=%s src=%s dst=%s" % (dpid, in_port, src, dst)  # return string


    def flow_removed_reason(self, msg):

        ofproto = msg.datapath.ofproto  # protocol

        reasons = {
            ofproto.OFPRR_IDLE_TIMEOUT: "idle timeout",  # removed due to idle
            ofproto.OFPRR_HARD_TIMEOUT: "hard timeout",  # removed due to hard timeout
            getattr(ofproto, "OFPRR_DELETE", None): "controller delete",  # manual delete
            getattr(ofproto, "OFPRR_GROUP_DELETE", None): "group delete",  # group delete
        }

        return reasons.get(msg.reason, "unknown reason")  # return reason


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)  # packet received event
    def packet_in_handler(self, ev):

        msg = ev.msg  # message
        datapath = msg.datapath  # switch
        ofproto = datapath.ofproto  # protocol
        parser = datapath.ofproto_parser  # parser

        in_port = msg.match["in_port"]  # incoming port

        pkt = packet.Packet(msg.data)  # parse packet
        eth = pkt.get_protocol(ethernet.ethernet)  # extract ethernet header

        if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:  # ignore LLDP
            return

        dpid = datapath.id  # switch id

        self.mac_to_port.setdefault(dpid, {})  # initialize if not exists
        self.mac_to_port[dpid][eth.src] = in_port  # learn source MAC

        out_port = self.mac_to_port[dpid].get(eth.dst, ofproto.OFPP_FLOOD)  # find destination

        actions = [parser.OFPActionOutput(out_port)]  # action = send to port

        if out_port != ofproto.OFPP_FLOOD:  # if destination known

            match = parser.OFPMatch(
                in_port=in_port,
                eth_src=eth.src,
                eth_dst=eth.dst,
            )

            flow_key = (dpid, in_port, eth.src, eth.dst)  # unique flow id

            self.add_timed_flow(datapath, match, actions, flow_key)  # install flow

        out = parser.OFPPacketOut(
            datapath=datapath,  # switch
            buffer_id=msg.buffer_id,  # buffer id
            in_port=in_port,  # input port
            actions=actions,  # actions
            data=msg.data,  # actual packet
        )

        datapath.send_msg(out)  # send packet


    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)  # flow removed event
    def flow_removed_handler(self, ev):

        msg = ev.msg  # message

        flow_state = self.active_flows.pop(msg.cookie, None)  # remove from active flows

        reason = self.flow_removed_reason(msg)  # get reason

        if flow_state is None:  # if not found
            self.logger.info(
                "Observed expired flow on switch %s with cookie=%s (%s), but it was not tracked",
                msg.datapath.id,
                msg.cookie,
                reason,
            )
            return

        flow_key = flow_state["flow_key"]  # get flow details

        self.flow_index.pop(flow_key, None)  # remove mapping

        lifetime = time.time() - flow_state["installed_at"]  # calculate time

        self.logger.info(
            "Flow lifecycle complete on switch %s for %s: removed due to %s after %.2fs, packets=%s, bytes=%s",
            msg.datapath.id,
            self.describe_flow_key(flow_key),
            reason,
            lifetime,
            msg.packet_count,
            msg.byte_count,
        )