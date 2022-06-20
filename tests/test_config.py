#! /usr/bin/env python
"""This verifies zeekclient's ability to ingest configurations and their related
data structures from INI, and render them back to INI/JSON as expected.
"""
import configparser
import io
import json
import logging
import os
import shutil
import sys
import tempfile
import unittest

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


class TestConfig(unittest.TestCase):
    def setUp(self):
        self.config = zeekclient.Config()

    def test_basics(self):
        # One of each type:
        self.assertEqual(self.config.getint('client', 'request_timeout_secs'), 20)
        self.assertEqual(self.config.getfloat('client', 'peering_status_retry_delay_secs'), 0.5)
        self.assertEqual(self.config.getboolean('client', 'rich_logging_format'), False)

    def test_update_from_file(self):
        with tempfile.NamedTemporaryFile('w', delete=False) as hdl:
            hdl.write('[client]\nrequest_timeout_secs = 10\n')
            hdl.close()
            self.config.update_from_file(hdl.name)
            self.assertEqual(self.config.getint('client', 'request_timeout_secs'), 10)

    def test_update_from_env(self):
        old = os.getenv('ZEEK_CLIENT_CONFIG_SETTINGS')
        os.environ['ZEEK_CLIENT_CONFIG_SETTINGS'] = 'client.request_timeout_secs=23 server.FOO="1 2 3"'
        self.config.update_from_env()
        self.assertEqual(self.config.getint('client', 'request_timeout_secs'), 23)
        self.assertEqual(self.config.get('server', 'FOO'), '1 2 3')

    def test_update_from_args(self):
        parser = zeekclient.cli.create_parser()
        args = parser.parse_args([
            '--set', 'client.request_timeout_secs=42',
            '--set', 'server.FOO=1 2 3'])
        self.config.update_from_args(args)
        self.assertEqual(self.config.getint('client', 'request_timeout_secs'), 42)
        self.assertEqual(self.config.get('server', 'FOO'), '1 2 3')

    def test_update_from_args_controller_host(self):
        parser = zeekclient.cli.create_parser()
        args = parser.parse_args(['--controller', 'foo'])
        self.config.update_from_args(args)
        self.assertEqual(self.config.get('controller', 'host'), 'foo')
        self.assertEqual(self.config.getint('controller', 'port'), 2150)

        parser = zeekclient.cli.create_parser()
        args = parser.parse_args(['--controller', 'foo:'])
        self.config.update_from_args(args)
        self.assertEqual(self.config.get('controller', 'host'), 'foo')
        self.assertEqual(self.config.getint('controller', 'port'), 2150)

    def test_update_from_args_controller_port(self):
        parser = zeekclient.cli.create_parser()
        args = parser.parse_args(['--controller', ':2222'])
        self.config.update_from_args(args)
        self.assertEqual(self.config.get('controller', 'host'), '127.0.0.1')
        self.assertEqual(self.config.getint('controller', 'port'), 2222)

    def test_update_from_args_controller_hostport(self):
        parser = zeekclient.cli.create_parser()
        args = parser.parse_args(['--controller', 'foo:2222'])
        self.config.update_from_args(args)
        self.assertEqual(self.config.get('controller', 'host'), 'foo')
        self.assertEqual(self.config.getint('controller', 'port'), 2222)


def test():
    """Entry point for testing this module.

    Returns True if successful, False otherwise.
    """
    res = unittest.main(sys.modules[__name__], verbosity=0, exit=False)
    # This is how unittest.main() implements the exit code itself:
    return res.result.wasSuccessful()

if __name__ == '__main__':
    sys.exit(not test())
