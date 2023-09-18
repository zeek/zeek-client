"""This verifies zeekclient's ability to load configurations and update
individual settings via command-line arguments, environment variables, and
files.
"""
import os
import sys
import tempfile
import unittest

TESTS = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.normpath(os.path.join(TESTS, ".."))

# Prepend the tree's root folder to the module searchpath so we find zeekclient
# via it. This allows tests to run without package installation.
sys.path.insert(0, ROOT)

import zeekclient  # pylint: disable=wrong-import-position


class TestConfig(unittest.TestCase):
    def setUp(self):
        self.config = zeekclient.config.Config()

    def test_basics(self):
        # One of each type:
        self.assertEqual(self.config.getint("client", "request_timeout_secs"), 20)
        self.assertEqual(
            self.config.getfloat("client", "peering_retry_delay_secs"), 1.0
        )
        self.assertEqual(self.config.getboolean("client", "rich_logging_format"), False)

    def test_update_from_file(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as hdl:
            hdl.write("[client]\nrequest_timeout_secs = 10\n")
            hdl.close()
            self.config.update_from_file(hdl.name)
            self.assertEqual(self.config.getint("client", "request_timeout_secs"), 10)

    @unittest.mock.patch.dict(
        os.environ,
        {
            "ZEEK_CLIENT_CONFIG_SETTINGS": 'client.request_timeout_secs=23 server.FOO="1 2 3"'
        },
    )
    def test_update_from_env(self):
        self.config.update_from_env()
        self.assertEqual(self.config.getint("client", "request_timeout_secs"), 23)
        self.assertEqual(self.config.get("server", "FOO"), "1 2 3")

    def test_update_from_args(self):
        parser = zeekclient.cli.create_parser()
        args = parser.parse_args(
            ["--set", "client.request_timeout_secs=42", "--set", "server.FOO=1 2 3"]
        )
        self.config.update_from_args(args)
        self.assertEqual(self.config.getint("client", "request_timeout_secs"), 42)
        self.assertEqual(self.config.get("server", "FOO"), "1 2 3")

    def test_update_from_args_controller_host(self):
        parser = zeekclient.cli.create_parser()
        args = parser.parse_args(["--controller", "foo"])
        self.config.update_from_args(args)
        self.assertEqual(self.config.get("controller", "host"), "foo")
        self.assertEqual(self.config.getint("controller", "port"), 2149)

        parser = zeekclient.cli.create_parser()
        args = parser.parse_args(["--controller", "foo:"])
        self.config.update_from_args(args)
        self.assertEqual(self.config.get("controller", "host"), "foo")
        self.assertEqual(self.config.getint("controller", "port"), 2149)

    def test_update_from_args_controller_port(self):
        parser = zeekclient.cli.create_parser()
        args = parser.parse_args(["--controller", ":2222"])
        self.config.update_from_args(args)
        self.assertEqual(self.config.get("controller", "host"), "127.0.0.1")
        self.assertEqual(self.config.getint("controller", "port"), 2222)

    def test_update_from_args_controller_hostport(self):
        parser = zeekclient.cli.create_parser()
        args = parser.parse_args(["--controller", "foo:2222"])
        self.config.update_from_args(args)
        self.assertEqual(self.config.get("controller", "host"), "foo")
        self.assertEqual(self.config.getint("controller", "port"), 2222)
