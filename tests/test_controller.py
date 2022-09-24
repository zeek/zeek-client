#! /usr/bin/env python
"""This verifies zeekclient.controller.Controller's behavior."""
import configparser
import io
import json
import logging
import os
import select
import sys
import unittest

from unittest.mock import patch

TESTS = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.normpath(os.path.join(TESTS, '..'))

# Prepend this folder so we can load our mocks
sys.path.insert(0, TESTS)

# Prepend the tree's root folder to the module searchpath so we find zeekclient
# via it. This allows tests to run without package installation.
sys.path.insert(0, ROOT)

# This is the mock, not the real one
import websocket

import zeekclient

class TestController(unittest.TestCase):
    def setUp(self):
        # A buffer receiving any created log messages, for validation. We could
        # also assertLogs(), but with the latter it's more work to get exactly
        # the output the user would see.
        self.logbuf = io.StringIO()
        zeekclient.logs.configure(verbosity=2, stream=self.logbuf)

    def assertEqualStripped(self, str1, str2):
        self.assertEqual(str1.strip(), str2.strip())

    def test_connect_successful(self):
        controller = zeekclient.controller.Controller('127.0.0.1', 2150)
        self.assertTrue(controller.connect())
        self.assertEqualStripped(
            self.logbuf.getvalue(),
            'info: connecting to controller 127.0.0.1:2150\n' +
            'info: peered with controller 127.0.0.1:2150')

    def test_connect_fails_with_timeout(self):
        controller = zeekclient.controller.Controller('127.0.0.1', 2150)
        controller.wsock.keep_timing_out = True
        # Dial down attempts and waits to make this fast:
        zeekclient.CONFIG.set('client', 'peering_attempts', '2')
        zeekclient.CONFIG.set('client', 'peering_retry_delay_secs', '0.1')
        self.assertFalse(controller.connect())
        self.assertEqualStripped(
            self.logbuf.getvalue(),
            'info: connecting to controller 127.0.0.1:2150\n' +
            'error: websocket connection to 127.0.0.1:2150 timed out')

    def test_connect_fails_with_websocket_error(self):
        controller = zeekclient.controller.Controller('127.0.0.1', 2150)
        controller.wsock.websocket_exception = True
        self.assertFalse(controller.connect())
        self.assertEqualStripped(
            self.logbuf.getvalue(),
            'info: connecting to controller 127.0.0.1:2150\n' +
            'error: websocket error with controller 127.0.0.1:2150: uh-oh')

    def test_connect_fails_with_unknown_error(self):
        controller = zeekclient.controller.Controller('127.0.0.1', 2150)
        controller.wsock.unknown_exception = True
        self.assertFalse(controller.connect())
        # logbuf's content contains a backtrace. We focus on first
        # two lines for comparison and trim the rest..
        buf = self.logbuf.getvalue().split('\n')
        self.assertEqualStripped(
            '\n'.join(buf[0:2]),
            'info: connecting to controller 127.0.0.1:2150\n' +
            'error: unexpected error with controller 127.0.0.1:2150: surprise')

    def test_publish(self):
        controller = zeekclient.controller.Controller('127.0.0.1', 2150)
        self.assertTrue(controller.connect())

        reqid = zeekclient.utils.make_uuid()
        event = zeekclient.events.GetConfigurationRequest(reqid, True)

        controller.publish(event)

        # The event gets transmitted via the controller object's websocket, so
        # verify it's as expected: a DataMessage containing our event. This is
        # the first message after the initial handshake, so the second in the
        # queue.
        message = zeekclient.brokertypes.DataMessage.unserialize(controller.wsock.send_queue[1])
        self.assertEqual(event.to_brokertype().serialize(), message.data.serialize())

    def test_receive(self):
        controller = zeekclient.controller.Controller('127.0.0.1', 2150)
        self.assertTrue(controller.connect())

        event = zeekclient.events.GetConfigurationResponse(zeekclient.utils.make_uuid(), ())

        # Mock an event in the receive queue, so we can receive something:
        controller.wsock.recv_queue.append(
            zeekclient.brokertypes.DataMessage(
                'dummy/topic', event.to_brokertype()).serialize())

        event, error = controller.receive()

        self.assertIsInstance(event, zeekclient.events.GetConfigurationResponse)
        self.assertEqual(error, '')

    def test_transact(self):
        controller = zeekclient.controller.Controller('127.0.0.1', 2150)
        self.assertTrue(controller.connect())

        reqid = zeekclient.utils.make_uuid()
        event = zeekclient.events.DeployResponse(reqid, ())

        # Mock an event in the receive queue, so we can receive something:
        controller.wsock.recv_queue.append(
            zeekclient.brokertypes.DataMessage(
                'dummy/topic', event.to_brokertype()).serialize())

        event, error = controller.transact(zeekclient.events.DeployRequest,
                                           zeekclient.events.DeployResponse,
                                           reqid=reqid)

        self.assertIsInstance(event, zeekclient.events.DeployResponse)
        self.assertEqual(error, '')
        self.assertEqual(event.reqid.to_py(), reqid)

    def test_transact_data_mismatches(self):
        controller = zeekclient.controller.Controller('127.0.0.1', 2150)
        self.assertTrue(controller.connect())

        reqid = zeekclient.utils.make_uuid()

        # Fill the receive queue with events. The first response mismatches in
        # its name, the second in its first argument (not reqid), the third
        # passes.
        events = [
            zeekclient.events.GetConfigurationResponse(reqid, ()),
            zeekclient.events.DeployResponse('xxxx', ()),
            zeekclient.events.DeployResponse(reqid, ()),
        ]

        for evt in events:
            controller.wsock.recv_queue.append(
                zeekclient.brokertypes.DataMessage(
                    'dummy/topic', evt.to_brokertype()).serialize())

        event, error = controller.transact(zeekclient.events.DeployRequest,
                                           zeekclient.events.DeployResponse,
                                           reqid=reqid)

        self.assertIsInstance(event, zeekclient.events.DeployResponse)
        self.assertEqual(error, '')
        self.assertEqual(event.reqid.to_py(), reqid)


def test():
    """Entry point for testing this module.

    Returns True if successful, False otherwise.
    """
    res = unittest.main(sys.modules[__name__], verbosity=0, exit=False)
    # This is how unittest.main() implements the exit code itself:
    return res.result.wasSuccessful()

if __name__ == '__main__':
    sys.exit(not test())
