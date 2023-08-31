"""This verifies zeekclient's ability to ingest cluster configurations, validate
their content (excluding deeper validations happening in the cluster
controller), and serialize them correctly to INI/JSON.
"""
import configparser
import io
import json
import os
import sys
import unittest

from unittest.mock import patch, MagicMock

TESTS = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.normpath(os.path.join(TESTS, ".."))

# Prepend the tree's root folder to the module searchpath so we find zeekclient
# via it. This allows tests to run without package installation.
sys.path.insert(0, ROOT)

import zeekclient  # pylint: disable=wrong-import-position


class TestRendering(unittest.TestCase):
    INI_INPUT = """# A sample ini using all available keys.
[instances]
agent

[manager]
instance = agent
port = 5000
role = manager

[logger-01]
instance = agent
port = 5001
role = logger
scripts = foo/bar/baz

[worker-01]
instance = agent
role = worker
interface = lo
env = FOO=BAR BLUM=frub
cpu_affinity = 4

[worker-02]
instance = agent
role = worker
interface = enp3s0
cpu_affinity = 8
"""
    INI_EXPECTED = """[instances]
agent

[logger-01]
instance = agent
role = LOGGER
port = 5001
scripts = foo/bar/baz

[manager]
instance = agent
role = MANAGER
port = 5000

[worker-01]
instance = agent
role = WORKER
interface = lo
cpu_affinity = 4
env = BLUM=frub FOO=BAR

[worker-02]
instance = agent
role = WORKER
interface = enp3s0
cpu_affinity = 8
"""
    JSON_EXPECTED = """{
    "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "instances": [
        {
            "name": "agent"
        }
    ],
    "nodes": [
        {
            "cpu_affinity": null,
            "env": {},
            "instance": "agent",
            "interface": null,
            "name": "logger-01",
            "options": null,
            "port": 5001,
            "role": "LOGGER",
            "scripts": [
                "foo/bar/baz"
            ]
        },
        {
            "cpu_affinity": null,
            "env": {},
            "instance": "agent",
            "interface": null,
            "name": "manager",
            "options": null,
            "port": 5000,
            "role": "MANAGER",
            "scripts": null
        },
        {
            "cpu_affinity": 4,
            "env": {
                "BLUM": "frub",
                "FOO": "BAR"
            },
            "instance": "agent",
            "interface": "lo",
            "name": "worker-01",
            "options": null,
            "port": null,
            "role": "WORKER",
            "scripts": null
        },
        {
            "cpu_affinity": 8,
            "env": {},
            "instance": "agent",
            "interface": "enp3s0",
            "name": "worker-02",
            "options": null,
            "port": null,
            "role": "WORKER",
            "scripts": null
        }
    ]
}"""

    def assertEqualStripped(self, str1, str2):
        self.assertEqual(str1.strip(), str2.strip())

    def parser_from_string(self, content):
        cfp = configparser.ConfigParser(allow_no_value=True)
        cfp.read_string(content)
        return cfp

    def setUp(self):
        # A buffer receiving any created log messages, for validation. We could
        # also assertLogs(), but with the latter it's more work to get exactly
        # the output the user would see.
        self.logbuf = io.StringIO()
        zeekclient.logs.configure(verbosity=3, stream=self.logbuf)

    def test_full_config_ini(self):
        # This test parses a feature-complete configuration from an INI file,
        # and verifies that writing it back out to an INI yields expected
        # content.

        # Parse the input into a config parser, and create a Configuration
        # object from it.
        cfp = self.parser_from_string(self.INI_INPUT)
        config = zeekclient.types.Configuration.from_config_parser(cfp)
        self.assertTrue(config is not None)

        # Turning that back into a config parser should have expected content:
        cfp = config.to_config_parser()
        with io.StringIO() as buf:
            cfp.write(buf)
            self.assertEqualStripped(buf.getvalue(), self.INI_EXPECTED)

        # Another roundtrip: the content should not change.
        config = zeekclient.types.Configuration.from_config_parser(cfp)
        self.assertTrue(config is not None)

        cfp = config.to_config_parser()
        with io.StringIO() as buf:
            cfp.write(buf)
            self.assertEqualStripped(buf.getvalue(), self.INI_EXPECTED)

    def test_full_config_json(self):
        # This test parses a feature-complete configuration from an INI file,
        # and verifies that writing it to JSON yields expected content.

        # Parse the input into a config parser, and create a Configuration
        # object from it.
        cfp = self.parser_from_string(self.INI_INPUT)
        config = zeekclient.types.Configuration.from_config_parser(cfp)
        self.assertTrue(config is not None)

        jdata = config.to_json_data()

        def canon(c):
            """Canonicalize the ID"""
            return "-" if c == "-" else "x"

        jdata["id"] = "".join([canon(c) for c in jdata["id"]])

        self.assertEqual(
            json.dumps(jdata, sort_keys=True, indent=4), self.JSON_EXPECTED
        )

    def test_config_addl_key(self):
        # This test creates a Configuration from an INI file with additional
        # keys that should get ignored in the instantiated object, but trigger
        # log warnings.

        ini_input = """
[instances]
agent

[manager]
instance = agent
port = 5000
role = manager
not_a_key = mhmmm
also_not_a_key = uh oh
"""
        ini_expected = """[instances]
agent

[manager]
instance = agent
role = MANAGER
port = 5000
"""
        cfp = self.parser_from_string(ini_input)
        config = zeekclient.types.Configuration.from_config_parser(cfp)
        self.assertTrue(config is not None)

        cfp = config.to_config_parser()
        with io.StringIO() as buf:
            cfp.write(buf)
            self.assertEqualStripped(buf.getvalue(), ini_expected)

        self.assertEqualStripped(
            self.logbuf.getvalue(),
            "warning: ignoring unexpected keys: also_not_a_key, not_a_key",
        )

    def test_config_invalid_instances(self):
        ini_input = """
[instances]
agent = foo:

[manager]
instance = agent
port = 80
role = manager
"""
        cfp = self.parser_from_string(ini_input)
        config = zeekclient.types.Configuration.from_config_parser(cfp)
        self.assertFalse(config)

        self.assertEqualStripped(
            self.logbuf.getvalue(),
            'error: invalid spec for instance "agent": "foo:" should be <host>:<port>',
        )

    def test_config_missing_instance(self):
        ini_input = """
[instances]
agent

[manager]
role = manager
"""
        cfp = self.parser_from_string(ini_input)
        config = zeekclient.types.Configuration.from_config_parser(cfp)
        self.assertFalse(config)

        self.assertEqualStripped(
            self.logbuf.getvalue(),
            "error: omit instances section when skipping instances in node definitions",
        )

    def test_config_mixed_instances(self):
        ini_input = """
[manager]
role = manager

[worker]
role = worker
instance = agent1
"""
        cfp = self.parser_from_string(ini_input)
        config = zeekclient.types.Configuration.from_config_parser(cfp)
        self.assertFalse(config)

        self.assertEqualStripped(
            self.logbuf.getvalue(), "error: either all or no nodes must state instances"
        )

    def test_config_missing_role(self):
        ini_input = """
[instances]
agent

[manager]
instance = agent
port = 80
"""
        cfp = self.parser_from_string(ini_input)
        config = zeekclient.types.Configuration.from_config_parser(cfp)
        self.assertFalse(config)

        self.assertEqualStripped(
            self.logbuf.getvalue(),
            'error: invalid node "manager" configuration: node requires a role',
        )

    def test_config_invalid_role(self):
        ini_input = """
[instances]
agent

[manager]
instance = agent
port = 80
role = superintendent
"""
        cfp = self.parser_from_string(ini_input)
        config = zeekclient.types.Configuration.from_config_parser(cfp)
        self.assertFalse(config)

        self.assertEqualStripped(
            self.logbuf.getvalue(),
            'error: invalid node "manager" configuration: role "superintendent" is invalid',
        )

    def test_config_invalid_port_string(self):
        ini_input = """
[instances]
agent

[manager]
instance = agent
port = eighty
role = manager
"""
        cfp = self.parser_from_string(ini_input)
        config = zeekclient.types.Configuration.from_config_parser(cfp)
        self.assertFalse(config)

        self.assertEqualStripped(
            self.logbuf.getvalue(),
            'error: invalid node "manager" configuration: '
            'cannot convert "manager.port" value "eighty" to int',
        )

    def test_config_invalid_port_number(self):
        ini_input = """
[instances]
agent

[manager]
instance = agent
port = 70000
role = manager
"""
        cfp = self.parser_from_string(ini_input)
        config = zeekclient.types.Configuration.from_config_parser(cfp)
        self.assertFalse(config)

        self.assertEqualStripped(
            self.logbuf.getvalue(),
            'error: invalid node "manager" configuration: port 70000 outside valid range',
        )

    @patch("zeekclient.types.socket.gethostname", new=MagicMock(return_value="testbox"))
    def test_config_no_instances(self):
        ini_input = """
[manager]
role = manager
"""
        ini_expected = """
[instances]
agent-testbox

[manager]
instance = agent-testbox
role = MANAGER
"""
        cfp = self.parser_from_string(ini_input)
        config = zeekclient.types.Configuration.from_config_parser(cfp)
        self.assertTrue(config is not None)

        cfp = config.to_config_parser()
        with io.StringIO() as buf:
            cfp.write(buf)
            self.assertEqualStripped(buf.getvalue(), ini_expected)

    def test_config_missing_instance_section(self):
        ini_input = """
[manager]
instance = agent
role = manager

[logger]
instance = agent2
role = logger

[worker]
instance = agent
role = worker
"""
        ini_expected = """
[instances]
agent
agent2

[logger]
instance = agent2
role = LOGGER

[manager]
instance = agent
role = MANAGER

[worker]
instance = agent
role = WORKER
"""
        cfp = self.parser_from_string(ini_input)
        config = zeekclient.types.Configuration.from_config_parser(cfp)
        self.assertTrue(config is not None)

        cfp = config.to_config_parser()
        with io.StringIO() as buf:
            cfp.write(buf)
            self.assertEqualStripped(buf.getvalue(), ini_expected)
