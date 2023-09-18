"""This verifies zeekclient.controller.Controller's behavior."""
import io
import os
import re
import ssl
import sys
import unittest

TESTS = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.normpath(os.path.join(TESTS, ".."))

# Prepend this folder so we can load our mocks
sys.path.insert(0, TESTS)

# Prepend the tree's root folder to the module searchpath so we find zeekclient
# via it. This allows tests to run without package installation.
sys.path.insert(0, ROOT)

import zeekclient  # pylint: disable=wrong-import-position

# This is the mock, not the real one
import websocket  # pylint: disable=wrong-import-position,wrong-import-order


class TestController(unittest.TestCase):
    def setUp(self):
        # A buffer receiving any created log messages, for validation. We could
        # also assertLogs(), but with the latter it's more work to get exactly
        # the output the user would see.
        self.logbuf = io.StringIO()
        zeekclient.logs.configure(verbosity=2, stream=self.logbuf)

    def assertLogLines(self, *patterns):
        buflines = self.logbuf.getvalue().split("\n")
        todo = list(patterns)
        for line in buflines:
            if todo and re.search(todo[0], line) is not None:
                todo.pop(0)
        msg = None
        if todo:
            msg = f"log pattern '{todo[0]}' not found; have:\n{self.logbuf.getvalue().strip()}"
        self.assertEqual(len(todo), 0, msg)

    def test_connect_successful(self):
        controller = zeekclient.controller.Controller()
        self.assertTrue(controller.connect())
        self.assertEqual(
            controller.controller_broker_id, controller.wsock.mock_broker_id
        )
        self.assertLogLines(
            "info: connecting to controller 127.0.0.1:2149",
            "info: peered with controller 127.0.0.1:2149",
        )

    def test_connect_successful_custom_controller(self):
        controller = zeekclient.controller.Controller("example.com", 1234)
        self.assertTrue(controller.connect())
        self.assertLogLines(
            "info: connecting to controller example.com:1234",
            "info: peered with controller example.com:1234",
        )

    def test_connect_successful_no_tls(self):
        zeekclient.CONFIG.set("ssl", "disable", "true")
        controller = zeekclient.controller.Controller()
        self.assertTrue(controller.connect())
        self.assertTrue(controller.wsock.mock_url.startswith("ws://"))
        self.assertLogLines(
            "info: connecting to controller 127.0.0.1:2149",
            "info: peered with controller 127.0.0.1:2149",
        )

    def test_connect_successful_authenticated_tls(self):
        zeekclient.CONFIG.set(
            "ssl", "certificate", os.path.join(TESTS, "certs", "cert.1.pem")
        )
        zeekclient.CONFIG.set(
            "ssl", "keyfile", os.path.join(TESTS, "certs", "key.1.pem")
        )
        zeekclient.CONFIG.set("ssl", "cafile", os.path.join(TESTS, "certs", "ca.pem"))
        controller = zeekclient.controller.Controller()
        self.assertTrue(controller.connect())
        self.assertTrue(controller.wsock.mock_url.startswith("wss://"))
        self.assertLogLines(
            "info: connecting to controller 127.0.0.1:2149",
            "info: peered with controller 127.0.0.1:2149",
        )

    def test_connect_successful_authenticated_tls_pw(self):
        zeekclient.CONFIG.set(
            "ssl", "certificate", os.path.join(TESTS, "certs", "cert.1.pem")
        )
        zeekclient.CONFIG.set(
            "ssl", "keyfile", os.path.join(TESTS, "certs", "key.1.pem")
        )
        zeekclient.CONFIG.set("ssl", "cafile", os.path.join(TESTS, "certs", "ca.pem"))
        zeekclient.CONFIG.set("ssl", "passphrase", "12345")
        controller = zeekclient.controller.Controller()
        self.assertTrue(controller.connect())
        self.assertLogLines(
            "info: connecting to controller 127.0.0.1:2149",
            "info: peered with controller 127.0.0.1:2149",
        )

    def test_connect_successful_authenticated_tls_file_config_errors(self):
        for error in ("certificate", "keyfile", "cafile"):
            zeekclient.CONFIG.set(
                "ssl", "certificate", os.path.join(TESTS, "certs", "cert.1.pem")
            )
            zeekclient.CONFIG.set(
                "ssl", "keyfile", os.path.join(TESTS, "certs", "key.1.pem")
            )
            zeekclient.CONFIG.set(
                "ssl", "cafile", os.path.join(TESTS, "certs", "ca.pem")
            )
            # Break the configuration:
            zeekclient.CONFIG.set("ssl", error, "not-a-file")

            with self.assertRaises(zeekclient.controller.ConfigError):
                _ = zeekclient.controller.Controller()

    def test_connect_fails_with_refused(self):
        controller = zeekclient.controller.Controller()
        controller.wsock.mock_connect_exc = ConnectionRefusedError()
        # Dial down attempts and waits to make this fast:
        zeekclient.CONFIG.set("client", "peering_attempts", "2")
        zeekclient.CONFIG.set("client", "peering_retry_delay_secs", "0.1")
        self.assertFalse(controller.connect())
        self.assertLogLines(
            "info: connecting to controller 127.0.0.1:2149",
            r"error: websocket connection to 127.0.0.1:2149 timed out in connect\(\)",
        )

    def test_connect_fails_with_timeout(self):
        controller = zeekclient.controller.Controller()
        controller.wsock.mock_connect_exc = websocket.WebSocketTimeoutException(
            "connection timed out"
        )
        # Dial down attempts and waits to make this fast:
        zeekclient.CONFIG.set("client", "peering_attempts", "2")
        zeekclient.CONFIG.set("client", "peering_retry_delay_secs", "0.1")
        self.assertFalse(controller.connect())
        self.assertLogLines(
            "info: connecting to controller 127.0.0.1:2149",
            r"error: websocket connection to 127.0.0.1:2149 timed out in connect\(\)",
        )

    def test_connect_fails_with_websocket_error(self):
        controller = zeekclient.controller.Controller()
        controller.wsock.mock_connect_exc = websocket.WebSocketException("uh-oh")
        self.assertFalse(controller.connect())
        self.assertLogLines(
            "info: connecting to controller 127.0.0.1:2149",
            r"error: websocket error in connect\(\) with controller 127.0.0.1:2149: uh-oh",
        )

    def test_connect_fails_with_sslerror(self):
        controller = zeekclient.controller.Controller()
        controller.wsock.mock_connect_exc = ssl.SSLError(
            "dummy library version", "uh-oh"
        )
        self.assertFalse(controller.connect())
        self.assertLogLines(
            "info: connecting to controller 127.0.0.1:2149",
            r"error: socket TLS error in connect\(\) with controller 127.0.0.1:2149: uh-oh",
        )

    def test_connect_fails_with_oserror(self):
        controller = zeekclient.controller.Controller()
        controller.wsock.mock_connect_exc = OSError("uh-oh")
        self.assertFalse(controller.connect())
        self.assertLogLines(
            "info: connecting to controller 127.0.0.1:2149",
            r"error: socket error in connect\(\) with controller 127.0.0.1:2149: uh-oh",
        )

    def test_connect_fails_with_unknown_error(self):
        controller = zeekclient.controller.Controller()
        controller.wsock.mock_connect_exc = websocket.UnknownException("surprise")
        self.assertFalse(controller.connect())
        self.assertLogLines(
            "info: connecting to controller 127.0.0.1:2149",
            r"error: unexpected error in connect\(\) with controller 127.0.0.1:2149: surprise",
        )

    def test_handshake_fails_with_timeout(self):
        controller = zeekclient.controller.Controller()
        controller.wsock.mock_recv_exc = websocket.WebSocketTimeoutException(
            "connection timed out"
        )
        self.assertFalse(controller.connect())
        self.assertLogLines("error: websocket connection to .+ timed out in handshake")

    def test_handshake_fails_with_oserror(self):
        controller = zeekclient.controller.Controller()
        controller.wsock.mock_recv_exc = OSError("uh-oh")
        self.assertFalse(controller.connect())
        self.assertLogLines(
            "error: socket error in handshake with controller .+: uh-oh"
        )

    def test_handshake_fails_with_unknown_error(self):
        controller = zeekclient.controller.Controller()
        controller.wsock.mock_recv_exc = websocket.UnknownException("surprise")
        self.assertFalse(controller.connect())
        self.assertLogLines(
            "error: unexpected error in handshake with controller .+: surprise"
        )

    def test_handshake_fails_with_protocol_data_error(self):
        controller = zeekclient.controller.Controller()
        # Not a Handshake ACK message:
        controller.wsock.mock_recv_queue = [zeekclient.brokertypes.Count(1).serialize()]
        self.assertFalse(controller.connect())
        self.assertLogLines("error: protocol data error")

    def test_publish(self):
        controller = zeekclient.controller.Controller()
        self.assertTrue(controller.connect())

        reqid = zeekclient.utils.make_uuid()
        event = zeekclient.events.GetConfigurationRequest(reqid, True)

        controller.publish(event)

        # The event gets transmitted via the controller object's websocket, so
        # verify it's as expected: a DataMessage containing our event. This is
        # the first message after the initial handshake, so the second in the
        # queue.
        message = zeekclient.brokertypes.DataMessage.unserialize(
            controller.wsock.mock_send_queue[1]
        )
        self.assertEqual(event.to_brokertype().serialize(), message.data.serialize())

    def test_receive(self):
        controller = zeekclient.controller.Controller()
        self.assertTrue(controller.connect())

        event = zeekclient.events.GetConfigurationResponse(
            zeekclient.utils.make_uuid(), ()
        )

        # Mock an event in the receive queue, so we can receive something:
        controller.wsock.mock_recv_queue.append(
            zeekclient.brokertypes.DataMessage(
                "dummy/topic", event.to_brokertype()
            ).serialize()
        )

        event, error = controller.receive()

        self.assertIsInstance(event, zeekclient.events.GetConfigurationResponse)
        self.assertEqual(error, "")

    def test_receive_fails_with_protocol_data_error(self):
        controller = zeekclient.controller.Controller()
        self.assertTrue(controller.connect())
        # Not a DataMessage:
        controller.wsock.mock_recv_queue.append(
            zeekclient.brokertypes.Count(1).serialize()
        )
        res, msg = controller.receive()
        self.assertIsNone(res)
        self.assertRegex(
            msg, "protocol data error .+: invalid data layout for Broker MessageType"
        )

    def test_receive_fails_with_timeout(self):
        controller = zeekclient.controller.Controller()
        self.assertTrue(controller.connect())
        controller.wsock.mock_recv_exc = websocket.WebSocketTimeoutException(
            "connection timed out"
        )
        res, msg = controller.receive()
        self.assertIsNone(res)
        self.assertRegex(msg, "websocket connection .+ timed out")

    def test_receive_fails_with_unknown_error(self):
        controller = zeekclient.controller.Controller()
        self.assertTrue(controller.connect())
        controller.wsock.mock_recv_exc = websocket.UnknownException("surprise")
        res, msg = controller.receive()
        self.assertIsNone(res)
        self.assertRegex(msg, "unexpected error .+: surprise")

    def test_receive_fails_with_event_error(self):
        controller = zeekclient.controller.Controller()
        self.assertTrue(controller.connect())
        # A DataMessage, but not with an event:
        controller.wsock.mock_recv_queue.append(
            zeekclient.brokertypes.DataMessage(
                "dummy/topic", zeekclient.brokertypes.Vector()
            ).serialize()
        )
        res, msg = controller.receive()
        self.assertIsNone(res)
        self.assertRegex(msg, "protocol data error .+: invalid event data")

    def test_transact(self):
        controller = zeekclient.controller.Controller()
        self.assertTrue(controller.connect())

        reqid = zeekclient.utils.make_uuid()
        event = zeekclient.events.DeployResponse(reqid, ())

        # Mock an event in the receive queue, so we can receive something:
        controller.wsock.mock_recv_queue.append(
            zeekclient.brokertypes.DataMessage(
                "dummy/topic", event.to_brokertype()
            ).serialize()
        )

        event, error = controller.transact(
            zeekclient.events.DeployRequest,
            zeekclient.events.DeployResponse,
            reqid=reqid,
        )

        self.assertIsInstance(event, zeekclient.events.DeployResponse)
        self.assertEqual(error, "")
        self.assertEqual(event.reqid.to_py(), reqid)

    def test_transact_data_mismatches(self):
        controller = zeekclient.controller.Controller()
        self.assertTrue(controller.connect())

        reqid = zeekclient.utils.make_uuid()

        # Fill the receive queue with events. The first response mismatches in
        # its name, the second in its first argument (not reqid), the third
        # passes.
        events = [
            zeekclient.events.GetConfigurationResponse(reqid, ()),
            zeekclient.events.DeployResponse("xxxx", ()),
            zeekclient.events.DeployResponse(reqid, ()),
        ]

        for evt in events:
            controller.wsock.mock_recv_queue.append(
                zeekclient.brokertypes.DataMessage(
                    "dummy/topic", evt.to_brokertype()
                ).serialize()
            )

        event, error = controller.transact(
            zeekclient.events.DeployRequest,
            zeekclient.events.DeployResponse,
            reqid=reqid,
        )

        self.assertIsInstance(event, zeekclient.events.DeployResponse)
        self.assertEqual(error, "")
        self.assertEqual(event.reqid.to_py(), reqid)
