import unittest  # used for writing test cases
from types import SimpleNamespace  # simple object to store attributes
from unittest import mock  # used for mocking objects

import eventlet.wsgi  # required for Ryu compatibility

# fix for missing attribute in some versions
if not hasattr(eventlet.wsgi, "ALREADY_HANDLED"):
    eventlet.wsgi.ALREADY_HANDLED = object()

# import your controller
from controller.timeout_controller import TimeoutController


# fake OpenFlow constants (simulate switch behavior)
class FakeOfproto:
    OFPP_CONTROLLER = 0xFFFFFFFD  # send to controller
    OFPP_FLOOD = 0xFFFFFFFB  # flood to all ports
    OFPIT_APPLY_ACTIONS = 4  # apply action instruction
    OFPFF_SEND_FLOW_REM = 1  # notify when flow removed
    OFPRR_IDLE_TIMEOUT = 0  # idle timeout reason
    OFPRR_HARD_TIMEOUT = 1  # hard timeout reason


# fake parser to create OpenFlow messages
class FakeParser:
    def OFPMatch(self, **kwargs):
        return SimpleNamespace(**kwargs)  # store match fields

    def OFPActionOutput(self, port):
        return SimpleNamespace(port=port)  # action = output to port

    def OFPInstructionActions(self, instruction_type, actions):
        return SimpleNamespace(
            instruction_type=instruction_type,
            actions=actions,
        )  # instruction object

    def OFPFlowMod(self, **kwargs):
        return SimpleNamespace(**kwargs)  # flow mod message

    def OFPPacketOut(self, **kwargs):
        return SimpleNamespace(**kwargs)  # packet out message


# fake switch (datapath)
class FakeDatapath:
    def __init__(self, dpid=1):
        self.id = dpid  # switch id
        self.ofproto = FakeOfproto()  # protocol constants
        self.ofproto_parser = FakeParser()  # parser
        self.sent_msgs = []  # store sent messages

    def send_msg(self, msg):
        self.sent_msgs.append(msg)  # store message instead of sending


# test class
class TimeoutControllerTest(unittest.TestCase):

    def setUp(self):
        self.controller = TimeoutController()  # create controller object
        self.datapath = FakeDatapath()  # create fake switch

    # test 1: check table-miss rule installation
    def test_switch_features_installs_permanent_table_miss_rule(self):

        event = SimpleNamespace(msg=SimpleNamespace(datapath=self.datapath))  # fake event

        self.controller.switch_features_handler(event)  # call handler

        self.assertEqual(len(self.datapath.sent_msgs), 1)  # one message sent

        flow_mod = self.datapath.sent_msgs[0]  # get flow rule

        self.assertEqual(flow_mod.priority, 0)  # priority should be 0
        self.assertFalse(hasattr(flow_mod, "idle_timeout"))  # no idle timeout
        self.assertFalse(hasattr(flow_mod, "hard_timeout"))  # no hard timeout

        # action should send to controller
        self.assertEqual(flow_mod.instructions[0].actions[0].port, FakeOfproto.OFPP_CONTROLLER)

    # test 2: packet_in installs flow for known destination
    def test_packet_in_installs_timed_rule_for_known_destination(self):

        # pre-learn destination MAC
        self.controller.mac_to_port[1] = {"00:00:00:00:00:02": 2}

        # fake ethernet frame
        ethernet_frame = SimpleNamespace(
            src="00:00:00:00:00:01",
            dst="00:00:00:00:00:02",
            ethertype=0x0800,
        )

        # fake packet_in message
        packet_in = SimpleNamespace(
            datapath=self.datapath,
            match={"in_port": 1},
            buffer_id=7,
            data=b"frame-bytes",
        )

        event = SimpleNamespace(msg=packet_in)  # wrap in event

        # mock packet parsing
        with mock.patch("controller.timeout_controller.packet.Packet") as packet_cls:
            packet_cls.return_value.get_protocol.return_value = ethernet_frame

            self.controller.packet_in_handler(event)  # call handler

        self.assertEqual(len(self.datapath.sent_msgs), 2)  # flow_mod + packet_out

        flow_mod = self.datapath.sent_msgs[0]  # first message
        packet_out = self.datapath.sent_msgs[1]  # second message

        # check timeout values
        self.assertEqual(flow_mod.idle_timeout, self.controller.IDLE_TIMEOUT)
        self.assertEqual(flow_mod.hard_timeout, self.controller.HARD_TIMEOUT)

        # check flag
        self.assertEqual(flow_mod.flags, FakeOfproto.OFPFF_SEND_FLOW_REM)

        # check match fields
        self.assertEqual(flow_mod.match.in_port, 1)
        self.assertEqual(flow_mod.match.eth_src, ethernet_frame.src)
        self.assertEqual(flow_mod.match.eth_dst, ethernet_frame.dst)

        # check output port
        self.assertEqual(packet_out.actions[0].port, 2)

        # ensure flow stored
        self.assertEqual(len(self.controller.active_flows), 1)

    # test 3: flow removal clears state
    def test_flow_removed_cleans_tracked_state(self):

        flow_key = (1, 1, "00:00:00:00:00:01", "00:00:00:00:00:02")  # flow id

        # create match
        match = self.datapath.ofproto_parser.OFPMatch(
            in_port=1,
            eth_src=flow_key[2],
            eth_dst=flow_key[3],
        )

        # action = output to port 2
        actions = [self.datapath.ofproto_parser.OFPActionOutput(2)]

        # install flow
        self.controller.add_timed_flow(self.datapath, match, actions, flow_key)

        cookie = next(iter(self.controller.active_flows))  # get cookie

        # simulate flow removal event
        removal_event = SimpleNamespace(
            msg=SimpleNamespace(
                datapath=self.datapath,
                cookie=cookie,
                reason=FakeOfproto.OFPRR_IDLE_TIMEOUT,
                packet_count=3,
                byte_count=210,
            )
        )

        self.controller.flow_removed_handler(removal_event)  # call handler

        # check cleanup
        self.assertNotIn(cookie, self.controller.active_flows)
        self.assertNotIn(flow_key, self.controller.flow_index)


# run tests
if __name__ == "__main__":
    unittest.main()