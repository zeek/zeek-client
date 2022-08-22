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

# This is the Broker mock, not the real one
import broker

# Prepend the tree's root folder to the module searchpath so we find zeekclient
# via it. This allows tests to run without package installation.
sys.path.insert(0, ROOT)

import zeekclient

# Mock out some select/poll functionality in the Controller class
class Poll:
    def __init__(self, resps=None):
        # Each resps member is a (fd, event) tuple, where event is a combo of
        # select.POLLIN and related codes.
        self.resps = resps or []

    def register(self, fd):
        pass

    def poll(self, timeout):
        return self.resps


def mock_poll():
    res = Poll([(0, select.POLLIN)])
    return res


class TestRendering(unittest.TestCase):
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

    def test_connect_fails(self):
        controller = zeekclient.controller.Controller('127.0.0.1', 2150)
        # Ensure the connects keep failing:
        controller.ssub.status = broker.Status(broker.SC.Unspecified)
        # Dial down attempts to make this fast:
        zeekclient.CONFIG.set('client', 'peering_status_attempts', '2')
        self.assertFalse(controller.connect())
        self.assertEqualStripped(
            self.logbuf.getvalue(),
            'info: connecting to controller 127.0.0.1:2150\n' +
            'error: could not peer with controller 127.0.0.1:2150')

    def test_publish(self):
        controller = zeekclient.controller.Controller('127.0.0.1', 2150)
        event = zeekclient.Registry.make_event(
            ('Management::Controller::API::get_configuration_request',
             zeekclient.utils.make_uuid(), True))

        controller.publish(event)

        # The event should be propagated through to Broker's endpoint -- our
        # mock in this case, which just collects topic and event:
        self.assertEqual(controller.ept.events[0],
                         (controller.controller_topic, event))

    @patch('zeekclient.controller.select.poll', mock_poll)
    def test_receive(self):
        controller = zeekclient.controller.Controller('127.0.0.1', 2150)

        # Fill the subscriber with data:
        controller.sub.mock_data.append(
            ('dummy/topic',
             ('Management::Controller::API::get_configuration_response',
              zeekclient.utils.make_uuid(), ())))

        event, error = controller.receive()

        self.assertIsInstance(event, zeekclient.events.GetConfigurationResponse)
        self.assertEqual(error, '')

    @patch('zeekclient.controller.select.poll', mock_poll)
    def test_transact(self):
        controller = zeekclient.controller.Controller('127.0.0.1', 2150)
        reqid = zeekclient.utils.make_uuid()

        # Fill the subscriber with data:
        controller.sub.mock_data.append(
            ('dummy/topic',
             ('Management::Controller::API::deploy_response', reqid, ())))

        event, error = controller.transact(zeekclient.events.DeployRequest,
                                           zeekclient.events.DeployResponse,
                                           reqid=reqid)

        self.assertIsInstance(event, zeekclient.events.DeployResponse)
        self.assertEqual(error, '')
        self.assertEqual(event.reqid, reqid)

    @patch('zeekclient.controller.select.poll', mock_poll)
    def test_transact_data_mismatches(self):
        controller = zeekclient.controller.Controller('127.0.0.1', 2150)
        reqid = zeekclient.utils.make_uuid()

        # Fill the subscriber with data. The first response mismatches in its
        # type, the second in its reqid, the third checks out.
        controller.sub.mock_data.extend([
            ('dummy/topic', ('Management::Controller::API::mismatched_response', reqid, ())),
            ('dummy/topic', ('Management::Controller::API::deploy_response', 'xxxx', ())),
            ('dummy/topic', ('Management::Controller::API::deploy_response', reqid, ())),
        ])

        event, error = controller.transact(zeekclient.events.DeployRequest,
                                           zeekclient.events.DeployResponse,
                                           reqid=reqid)

        self.assertIsInstance(event, zeekclient.events.DeployResponse)
        self.assertEqual(error, '')
        self.assertEqual(event.reqid, reqid)


def test():
    """Entry point for testing this module.

    Returns True if successful, False otherwise.
    """
    res = unittest.main(sys.modules[__name__], verbosity=0, exit=False)
    # This is how unittest.main() implements the exit code itself:
    return res.result.wasSuccessful()

if __name__ == '__main__':
    sys.exit(not test())
