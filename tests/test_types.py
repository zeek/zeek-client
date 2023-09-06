"""This verifies the Python-level representations of Zeek records in types module."""
import os.path
import sys
import unittest

TESTS = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.normpath(os.path.join(TESTS, ".."))

# Prepend the tree's root folder to the module searchpath so we find zeekclient
# via it. This allows tests to run without package installation.
sys.path.insert(0, ROOT)

import zeekclient.brokertypes as bt  # pylint: disable=wrong-import-position
from zeekclient.types import *  # pylint: disable=wrong-import-position,unused-wildcard-import,wildcard-import


class TestTypes(unittest.TestCase):
    def assertHash(self, val):
        d = {val: 1}
        self.assertEqual(d[val], 1)

    def brokertype_roundtrip(self, data):
        return type(data).from_brokertype(data.to_brokertype())

    def test_cluster_role(self):
        val0 = ClusterRole.LOGGER
        val1 = self.brokertype_roundtrip(val0)
        self.assertEqual(val0, val1)

        self.assertTrue(ClusterRole.LOGGER < ClusterRole.MANAGER)
        with self.assertRaises(TypeError):
            _ = ClusterRole.LOGGER < State.PENDING

        val0_bt = val0.to_brokertype()
        self.assertEqual(val0_bt.to_py(), val0.qualified_name())

        self.assertHash(val0)

        with self.assertRaises(TypeError):
            ClusterRole.from_brokertype(bt.String("Oopsie::WORKER"))
        with self.assertRaises(TypeError):
            ClusterRole.from_brokertype(bt.String("Supervisor::OOPSIE"))

    def test_management_role(self):
        val0 = ManagementRole.AGENT
        val1 = self.brokertype_roundtrip(val0)
        self.assertEqual(val0, val1)

        val0_bt = val0.to_brokertype()
        self.assertEqual(val0_bt.to_py(), val0.qualified_name())

        self.assertHash(val0)

    def test_state(self):
        val0 = State.FAILED
        val1 = self.brokertype_roundtrip(val0)
        self.assertEqual(val0, val1)

        val0_bt = val0.to_brokertype()
        self.assertEqual(val0_bt.to_py(), val0.qualified_name())

        self.assertHash(val0)

    def test_option(self):
        val0 = Option("foo", "bar")
        val1 = self.brokertype_roundtrip(val0)
        self.assertEqual(val0, val1)

        self.assertHash(val0)

    def test_instance(self):
        val0 = Instance("instance1")
        val1 = self.brokertype_roundtrip(val0)
        self.assertEqual(val0, val1)
        self.assertEqual(val0.to_json_data(), {"name": "instance1"})

        val0 = Instance("instance1", "10.0.0.1")
        self.assertEqual(val0.to_json_data(), {"name": "instance1", "host": "10.0.0.1"})

        val0 = Instance("instance1", "10.0.0.1", 1234)
        val1 = self.brokertype_roundtrip(val0)
        self.assertEqual(val0, val1)
        self.assertEqual(
            val0.to_json_data(), {"name": "instance1", "host": "10.0.0.1", "port": 1234}
        )

        self.assertHash(val0)

        with self.assertRaisesRegex(TypeError, "unexpected Broker data"):
            Instance.from_brokertype(bt.String("not a vector..."))

    def test_node(self):
        val0 = Node("worker1", "instance1", ClusterRole.WORKER)
        val1 = self.brokertype_roundtrip(val0)
        self.assertEqual(val0, val1)

        val0 = Node(
            "worker1",
            "instance1",
            ClusterRole.WORKER,
            State.PENDING,
            port=1234,
            scripts=["foo/bar/baz.zeek"],
            options=[Option("foo", "bar")],
            interface="eth0",
            cpu_affinity=13,
            env={"FOO": "BAR"},
        )
        val1 = self.brokertype_roundtrip(val0)
        self.assertEqual(val0, val1)

        self.assertHash(val0)

        with self.assertRaisesRegex(TypeError, "unexpected Broker data"):
            Node.from_brokertype(bt.String("not a vector..."))

    def test_configuration(self):
        val0 = Configuration()
        val0.instances.append(Instance("instance1"))
        val0.nodes.append(Node("worker1", "instance1", ClusterRole.WORKER))

        val1 = self.brokertype_roundtrip(val0)
        self.assertEqual(val0, val1)

        self.assertHash(val0)

    def test_node_status(self):
        # NodeStatus is not a SendableZeekType, so we make up the Brokertype
        # representation and only test instantiation from it. Same for the next
        # few types below.
        val0 = NodeStatus(
            "worker1",
            State.RUNNING,
            ManagementRole.NONE,
            ClusterRole.WORKER,
            pid=123,
            port=1234,
        )

        val1 = NodeStatus.from_brokertype(
            bt.Vector(
                [
                    bt.String("worker1"),
                    bt.Enum("Management::RUNNING"),
                    bt.Enum("Management::NONE"),
                    bt.Enum("Supervisor::WORKER"),
                    bt.Integer(123),
                    bt.Port(1234),
                ]
            )
        )

        self.assertEqual(val0, val1)
        self.assertHash(val0)

    def test_result(self):
        val0 = Result(
            "reqid-1234",
            success=False,
            instance="instance1",
            data=bt.String("data"),
            error="an error",
            node="worker1",
        )

        val1 = Result.from_brokertype(
            bt.Vector(
                [
                    bt.String("reqid-1234"),
                    bt.Boolean(False),
                    bt.String("instance1"),
                    bt.String("data"),
                    bt.String("an error"),
                    bt.String("worker1"),
                ]
            )
        )

        self.assertEqual(val0, val1)

    def test_node_outputs(self):
        val0 = NodeOutputs("stdout content", "stderr content")

        val1 = NodeOutputs.from_brokertype(
            bt.Vector(
                [
                    bt.String("stdout content"),
                    bt.String("stderr content"),
                ]
            )
        )

        self.assertEqual(val0, val1)
