"""This verifies the behavior of the types provied by the brokertypes module."""
import datetime
import os.path
import sys
import unittest

TESTS = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.normpath(os.path.join(TESTS, ".."))

# Prepend the tree's root folder to the module searchpath so we find zeekclient
# via it. This allows tests to run without package installation.
sys.path.insert(0, ROOT)

from zeekclient.brokertypes import *  # pylint: disable=wrong-import-position,unused-wildcard-import,wildcard-import


class TestBrokertypes(unittest.TestCase):
    def assertEqualRoundtrip(self, data):
        # This verifies for the given Brokertype object that it can serialize
        # into Broker's wire format, unserialize, and yield an identical object.
        output = type(data).unserialize(data.serialize())
        self.assertEqual(data, output)

    def assertHash(self, val):
        d = {val: 1}
        self.assertEqual(d[val], 1)

    def test_none(self):
        self.assertEqual(NoneType(None), NoneType())
        self.assertEqual(NoneType().to_py(), None)
        self.assertEqual(NoneType(), from_py(None))

        self.assertNotEqual(NoneType, None)

        self.assertEqualRoundtrip(NoneType())

        self.assertFalse(NoneType() < NoneType())
        self.assertHash(NoneType())

    def test_boolean(self):
        self.assertEqual(Boolean(True), Boolean(True))
        self.assertEqual(Boolean(True), Boolean("true"))
        self.assertEqual(Boolean(True).to_py(), True)
        self.assertEqual(Boolean(True), from_py(True))

        self.assertNotEqual(Boolean(True), Boolean(False))
        self.assertNotEqual(Boolean(True), True)

        self.assertEqualRoundtrip(Boolean(True))
        self.assertEqualRoundtrip(Boolean(False))

        self.assertTrue(Boolean(False) < Boolean(True))
        self.assertFalse(Boolean(False) > Boolean(True))
        self.assertHash(Boolean(True))

    def test_count(self):
        self.assertEqual(Count(10), Count(10))
        self.assertEqual(Count(10), Count("10"))
        self.assertEqual(Count(10).to_py(), 10)
        self.assertEqual(Count(10), from_py(10, Count))

        self.assertNotEqual(Count(10), Count(1))
        self.assertNotEqual(Count(10), 10)

        self.assertEqualRoundtrip(Count(10))

        for val in (-10, "hello"):
            with self.assertRaises(ValueError):
                Count(val)

        self.assertTrue(Count(1) < Count(10))
        self.assertTrue(Count(10) > Count(1))
        self.assertHash(Count(10))

    def test_integer(self):
        self.assertEqual(Integer(10), Integer(10))
        self.assertEqual(Integer(10), Integer("10"))
        self.assertEqual(Integer(10).to_py(), 10)
        self.assertEqual(Integer(10), from_py(10))

        self.assertNotEqual(Integer(10), Integer(1))
        self.assertNotEqual(Integer(10), 10)

        self.assertEqualRoundtrip(Integer(10))

        self.assertTrue(Integer(1) < Integer(10))
        self.assertTrue(Integer(10) > Integer(1))
        self.assertHash(Integer(10))

    def test_real(self):
        self.assertEqual(Real(10.1), Real(10.1))
        self.assertEqual(Real(10.1), Real("10.1"))
        self.assertEqual(Real(10.1).to_py(), 10.1)
        self.assertEqual(Real(10.1), from_py(10.1))

        self.assertNotEqual(Real(10.0), Real(10.1))
        self.assertNotEqual(Real(1.1), 1.1)

        self.assertEqualRoundtrip(Real(1.1))

        with self.assertRaises(ValueError):
            Real("hello")

        self.assertTrue(Real(1) < Real(10))
        self.assertTrue(Real(10) > Real(1))
        self.assertHash(Real(10.1))

    def test_timespan(self):
        self.assertEqual(Timespan("10s"), Timespan("10s"))
        self.assertEqual(Timespan("10s").to_py(), datetime.timedelta(seconds=10))

        self.assertEqual(
            Timespan("10.5d").to_py(), datetime.timedelta(days=10, hours=12)
        )
        self.assertEqual(
            Timespan(datetime.timedelta(microseconds=1)), Timespan("1000ns")
        )
        self.assertEqual(Timespan(datetime.timedelta(milliseconds=1)), Timespan("1ms"))
        self.assertEqual(Timespan(datetime.timedelta(seconds=1)), Timespan("1000ms"))
        self.assertEqual(Timespan(datetime.timedelta(seconds=1)), Timespan("1s"))
        self.assertEqual(Timespan(datetime.timedelta(minutes=1)), Timespan("1min"))
        self.assertEqual(Timespan(datetime.timedelta(hours=1)), Timespan("1h"))
        self.assertEqual(Timespan(datetime.timedelta(days=1)), Timespan("1d"))
        self.assertEqual(Timespan(datetime.timedelta(weeks=1)), Timespan("7d"))

        self.assertNotEqual(Timespan("10s"), Timespan("20s"))
        self.assertNotEqual(Timespan("10s"), Timespan("10ms"))
        self.assertNotEqual(Timespan("10s"), 10)

        self.assertEqualRoundtrip(Timespan("10h"))

        for val in "oops", "10nano", "1a":
            with self.assertRaises(ValueError):
                Timespan(val)

        self.assertTrue(Timespan("1ns") < Timespan("1ms"))
        self.assertTrue(Timespan("1ms") < Timespan("1s"))
        self.assertTrue(Timespan("1s") < Timespan("1h"))
        self.assertTrue(Timespan("1h") < Timespan("1d"))

        self.assertHash(Timespan("10d"))

    def test_timestamp(self):
        ts1, ts2 = "2022-10-20T01:02:03.004", "2022-10-21T00:00:00.000"
        self.assertEqual(Timestamp(ts1), Timestamp(ts1))
        self.assertEqual(Timestamp(ts1).to_py(), datetime.datetime.fromisoformat(ts1))
        self.assertEqual(
            Timestamp(ts1), Timestamp(datetime.datetime.fromisoformat(ts1))
        )

        self.assertNotEqual(Timestamp(ts1), Timestamp(ts2))
        self.assertNotEqual(Timestamp(ts1).to_py(), ts1)

        self.assertEqualRoundtrip(Timestamp(ts1))

        with self.assertRaises(ValueError):
            Timestamp("oops")

        self.assertTrue(Timestamp(ts1) < Timestamp(ts2))

    def test_string(self):
        self.assertEqual(String("10"), String("10"))
        self.assertEqual(String(True), String(True))
        self.assertEqual(String("23"), String(23))
        self.assertEqual(String("23").to_py(), "23")
        self.assertEqual(String("foo"), from_py("foo"))

        self.assertNotEqual(String("10"), String("20"))

        self.assertEqualRoundtrip(String("foo"))

        self.assertTrue(String("bar") < String("foo"))
        self.assertTrue(String("foo") > String("bar"))
        self.assertHash(String("foo"))

    def test_enum(self):
        self.assertEqual(Enum("Foo"), Enum("Foo"))
        self.assertEqual(Enum("Foo").to_py(), "Foo")

        self.assertNotEqual(Enum("Foo"), Enum("FOO"))
        self.assertNotEqual(Enum("Foo"), Enum("Bar"))

        self.assertEqualRoundtrip(Enum("Foo::bar"))

        self.assertTrue(Enum("FOO::bar") < Enum("FOO::baz"))
        self.assertTrue(Enum("FOO::baz") > Enum("FOO::bar"))
        self.assertHash(Enum("Foo::bar"))

    def test_address(self):
        self.assertEqual(Address("127.0.0.1"), Address("127.0.0.1"))
        self.assertEqual(
            Address(ipaddress.ip_address("127.0.0.1")), Address("127.0.0.1")
        )
        self.assertEqual(
            Address(ipaddress.ip_address("2001:db8::")), Address("2001:db8::")
        )
        self.assertEqual(
            Address("127.0.0.1").to_py(), ipaddress.ip_address("127.0.0.1")
        )
        self.assertEqual(
            Address("127.0.0.1"), from_py(ipaddress.ip_address("127.0.0.1"))
        )

        self.assertNotEqual(Address("127.0.0.1"), Address("10.0.0.1"))

        self.assertEqualRoundtrip(Address("10.0.0.1"))

        for val in ("foo", "10.0.0.0/8"):
            with self.assertRaises(ValueError):
                Address(val)

        self.assertTrue(Address("1.0.0.1") < Address("1.0.0.2"))
        self.assertTrue(Address("1.0.0.2") > Address("1.0.0.1"))
        self.assertHash(Address("127.0.0.1"))

    def test_subnet(self):
        self.assertEqual(Subnet("10.0.0.0/8"), Subnet("10.0.0.0/8"))
        self.assertEqual(
            Subnet(ipaddress.ip_network("10.0.0.0/8")), Subnet("10.0.0.0/8")
        )
        self.assertEqual(
            Subnet(ipaddress.ip_network("2001:db8::/32")), Subnet("2001:db8::/32")
        )
        self.assertEqual(
            Subnet("10.0.0.0/8").to_py(), ipaddress.ip_network("10.0.0.0/8")
        )
        self.assertEqual(
            Subnet("10.0.0.0/8"), from_py(ipaddress.ip_network("10.0.0.0/8"))
        )

        self.assertNotEqual(Subnet("10.0.0.0/8"), Subnet("10.0.0.1"))

        self.assertEqualRoundtrip(Subnet("10.0.0.0/8"))

        for val in ("foo", "10.0.0.0/64", "10.0.0.1/8"):
            with self.assertRaises(ValueError):
                Subnet(val)

        self.assertTrue(Subnet("10.0.0.0/8") < Subnet("10.0.0.0/16"))
        self.assertTrue(Subnet("10.0.0.0/16") > Subnet("10.0.0.0/8"))
        self.assertHash(Subnet("10.0.0.0/8"))

    def test_port(self):
        self.assertEqual(Port(10), Port(10))
        self.assertEqual(Port(10), Port("10"))
        self.assertEqual(Port(10, Port.Proto.TCP), Port(10, Port.Proto.TCP))
        self.assertEqual(Port(10, Port.Proto.UDP), Port(10, Port.Proto.UDP))
        self.assertEqual(Port(10, Port.Proto.ICMP), Port(10, Port.Proto.ICMP))
        self.assertEqual(Port(10, Port.Proto.UNKNOWN), Port(10, Port.Proto.UNKNOWN))
        self.assertEqual(Port(10).to_py(), Port(10))

        self.assertEqualRoundtrip(Port(443))
        self.assertEqualRoundtrip(Port(53, Port.Proto.UDP))

        self.assertNotEqual(Port(10), Port(20))
        self.assertNotEqual(Port(10), Port(10, Port.Proto.UDP))
        self.assertNotEqual(Port(10, Port.Proto.UDP), Port(10, Port.Proto.ICMP))
        self.assertNotEqual(Port(10, Port.Proto.UDP), Port(10, Port.Proto.UNKNOWN))

        with self.assertRaises(ValueError):
            Port("oops", Port.Proto.TCP)
        with self.assertRaises(ValueError):
            Port(70000)
        with self.assertRaises(TypeError):
            Port(10, "tcp")

        self.assertTrue(Port(10) < Port(20))
        self.assertTrue(Port(20) > Port(10))
        self.assertTrue(Port(20, Port.Proto.TCP) < Port(10, Port.Proto.UDP))
        self.assertTrue(Port(20, Port.Proto.UDP) < Port(10, Port.Proto.ICMP))
        self.assertHash(Port(10))

    def test_vector(self):
        val = Vector([from_py(1), from_py("foo"), from_py(True)])

        self.assertEqual(val, val)
        self.assertEqual(Vector([String("foo")]).to_py(), ["foo"])
        self.assertEqual(Vector([String("foo")]), from_py(["foo"]))

        self.assertNotEqual(Vector([from_py(1), from_py("foo")]), Vector([from_py(1)]))
        self.assertNotEqual(
            Vector([from_py(1), from_py("foo")]), Vector([from_py(1), from_py("noo")])
        )

        self.assertEqualRoundtrip(Vector([from_py(1), from_py("foo"), from_py(True)]))

        for _ in val:
            pass
        self.assertEqual(len(val), 3)
        self.assertEqual(val[0], Integer(1))

        self.assertTrue(Vector([from_py(1)]) < Vector([from_py(2)]))
        self.assertTrue(Vector([from_py(1)]) < Vector([from_py(1), from_py("foo")]))
        self.assertHash(val)

        for val in (23, [23]):
            with self.assertRaises(TypeError):
                Vector(val)

    def test_set(self):
        val = Set({from_py(1), from_py("foo"), from_py(True)})

        self.assertEqual(val, val)
        self.assertEqual(Set({String("foo")}).to_py(), {"foo"})
        self.assertEqual(Set({String("foo")}), from_py({"foo"}))

        self.assertNotEqual(Set({from_py(1), from_py("foo")}), Set({from_py(1)}))
        self.assertNotEqual(
            Set({from_py(1), from_py("foo")}), Set({from_py(1), from_py("noo")})
        )

        self.assertEqualRoundtrip(Set({from_py(1), from_py("foo"), from_py(True)}))

        for _ in val:
            pass
        self.assertEqual(len(val), 3)
        self.assertTrue(Integer(1) in val)

        self.assertTrue(Set({from_py(1)}) < Set({from_py(2)}))
        self.assertTrue(Set({from_py(1)}) < Set({from_py(1), from_py("foo")}))
        self.assertHash(val)

        for val in (23, {23}):
            with self.assertRaises(TypeError):
                Set(val)

    def test_table(self):
        val = Table({from_py("foo"): from_py(1), from_py("bar"): from_py(2)})

        self.assertEqual(val, val)
        self.assertEqual(
            Table({from_py("foo"): from_py(1), from_py("bar"): from_py(2)}).to_py(),
            {"foo": 1, "bar": 2},
        )
        self.assertEqual(Table({from_py("foo"): from_py(1)}), from_py({"foo": 1}))

        self.assertNotEqual(
            Table({from_py("foo"): from_py(1), from_py("bar"): from_py(2)}),
            Table({from_py("foo"): from_py(1), from_py("bar"): from_py(3)}),
        )
        self.assertNotEqual(
            Table({from_py("foo"): from_py(1), from_py("bar"): from_py(2)}),
            Table({from_py("foo"): from_py(1), from_py("baz"): from_py(2)}),
        )

        self.assertEqualRoundtrip(
            Table({from_py("foo"): from_py(1), from_py("bar"): from_py(2)})
        )
        for _ in val:
            pass
        for _ in val.keys():
            pass
        for _ in val.values():
            pass
        for _, _ in val.items():
            pass
        self.assertEqual(len(val), 2)
        self.assertTrue(String("foo") in val)

        self.assertFalse(
            Table({from_py("foo"): from_py(1)}) < Table({from_py("foo"): from_py(1)})
        )
        self.assertTrue(
            Table({from_py("foo"): from_py(1)}) < Table({from_py("foo"): from_py(2)})
        )
        self.assertTrue(
            Table({from_py("bar"): from_py(1)})
            < Table({from_py("foo"): from_py(1), from_py("bar"): from_py(1)})
        )
        self.assertTrue(
            Table({from_py("foo"): from_py(1)})
            < Table({from_py("foo"): from_py(1), from_py("bar"): from_py(2)})
        )
        self.assertTrue(
            Table({from_py("aaa"): from_py(1)})
            < Table({from_py("foo"): from_py(1), from_py("bar"): from_py(2)})
        )
        self.assertHash(val)

        for val in (23, {"foo": 23}):
            with self.assertRaises(TypeError):
                Table(val)

    def test_zeek_event(self):
        evt = ZeekEvent("Test::event", from_py("hello"), from_py(42), from_py(True))
        self.assertTrue(isinstance(evt, Vector))
        self.assertEqual(
            ZeekEvent("Test::event", from_py("hello"), from_py(42), from_py(True)),
            ZeekEvent("Test::event", from_py("hello"), from_py(42), from_py(True)),
        )
        self.assertNotEqual(
            ZeekEvent("Test::event", from_py("hello"), from_py(42), from_py(True)),
            ZeekEvent("Test::event2", from_py("hello"), from_py(42), from_py(True)),
        )
        self.assertNotEqual(
            ZeekEvent("Test::event", from_py("hello"), from_py(42), from_py(True)),
            ZeekEvent("Test::event", from_py("hello"), from_py(42)),
        )
        self.assertNotEqual(
            ZeekEvent("Test::event", from_py("hello"), from_py(43)),
            ZeekEvent("Test::event", from_py("hello"), from_py(42)),
        )

        self.assertEqualRoundtrip(evt)

        vec = Vector.unserialize(evt.serialize())
        evt2 = ZeekEvent.from_vector(vec)
        self.assertEqual(evt, evt2)

        with self.assertRaises(TypeError):
            ZeekEvent.from_vector(String("not a vector"))

        with self.assertRaises(TypeError):
            ZeekEvent("foo", 1)

    def test_zeek_event_from_vector_metadata(self):
        md_vec = Vector([Vector([from_py(12344242), from_py("truth")])])
        args_vec = Vector()
        ev_vec = Vector([from_py("Test::event"), args_vec, md_vec])
        vec = Vector([from_py(1), from_py(1), ev_vec])

        ev = ZeekEvent.from_vector(vec)
        self.assertEqual(ev.name, "Test::event")
        self.assertEqual(ev.args, [])

    def test_zeek_event_from_vector_invalid(self):
        test_cases = [
            ("missing args", Vector([from_py("Test::event")])),
            ("wrong name type", Vector([from_py(1), Vector()])),
            ("wrong args type", Vector([from_py("Test::event"), from_py("string")])),
        ]

        for name, ev_vec in test_cases:
            with self.subTest(msg=name):
                vec = Vector([from_py(1), from_py(1), ev_vec])
                with self.assertRaises(TypeError):
                    ZeekEvent.from_vector(vec)

    def test_handshake_message(self):
        self.assertEqual(
            HandshakeMessage(["foo", "bar"]), HandshakeMessage(["foo", String("bar")])
        )
        self.assertNotEqual(HandshakeMessage(["foo", "bar"]), HandshakeMessage(["foo"]))
        self.assertEqualRoundtrip(HandshakeMessage(["foo", "bar"]))

    def test_handshake_ack_message(self):
        self.assertEqual(
            HandshakeAckMessage("aaaa", "1.0"), HandshakeAckMessage("aaaa", "1.0")
        )
        self.assertNotEqual(
            HandshakeAckMessage("aaaa", "1.0"), HandshakeAckMessage("bbbb", "1.0")
        )
        self.assertEqualRoundtrip(HandshakeAckMessage("aaaa", "1.0"))

    def test_data_message(self):
        self.assertEqual(
            DataMessage("foo", String("test")), DataMessage("foo", String("test"))
        )
        self.assertNotEqual(
            DataMessage("foo", String("test")), DataMessage("foo", String("other"))
        )
        self.assertEqualRoundtrip(DataMessage("foo", String("test")))

    def test_error_message(self):
        msg1 = ErrorMessage("deserialization_failed", "this is where you failed")
        msg2 = ErrorMessage("deserialization_failed", "this is where you also failed")
        self.assertEqual(msg1, msg1)
        self.assertNotEqual(msg1, msg2)
        self.assertEqualRoundtrip(msg1)

    def test_type_lt(self):
        # Any brokertyped data value can be compared to any other, but not to
        # unrelated types.
        self.assertTrue(Address("127.0.0.1") < Boolean(True))
        self.assertTrue(Boolean(True) < Count(1))
        self.assertTrue(Count(1) < Integer(1))
        self.assertTrue(Integer(1) < Real(1))
        self.assertTrue(Real(1) < Set())
        self.assertTrue(Set() < String("foo"))
        self.assertTrue(String("foo") < Subnet("10.0.0.0/8"))
        self.assertTrue(Subnet("10.0.0.0/8") < Timespan("10d"))
        self.assertTrue(Timespan("10d") < Timestamp(datetime.datetime.now()))

        with self.assertRaises(TypeError):
            _ = Boolean(True) < True
        with self.assertRaises(TypeError):
            _ = Boolean(True) < HandshakeMessage  # Not a data type

        self.assertTrue(Boolean(True) < Count(10))

    def test_unserialize_not_json(self):
        data = b"\x00\x00\x00"

        with self.assertRaisesRegex(TypeError, "cannot parse JSON data"):
            _ = unserialize(data)
        with self.assertRaisesRegex(TypeError, "cannot parse JSON data"):
            _ = Count.unserialize(data)

    def test_unserialize_invalid_json(self):
        data = b"[ 1,2,3 ]"
        with self.assertRaisesRegex(TypeError, "invalid data layout"):
            _ = unserialize(data)
        with self.assertRaisesRegex(TypeError, "invalid data layout"):
            _ = Count.unserialize(data)

        data = b'{ "data": "foobar" }'
        with self.assertRaisesRegex(TypeError, "unrecognized Broker type"):
            _ = unserialize(data)
        with self.assertRaisesRegex(TypeError, "invalid data layout"):
            _ = Count.unserialize(data)

        data = b'{ "data": "foobar", "@data-type": "count" }'
        with self.assertRaisesRegex(TypeError, "invalid data for Count"):
            _ = Count.unserialize(data)

    def test_container_from_broker(self):
        s = Set.from_broker({"data": [{"@data-type": "string", "data": "s"}]})
        self.assertEqual(1, len(s))

        v = Vector.from_broker({"data": [{"@data-type": "string", "data": "s"}]})
        self.assertEqual(1, len(v))

        t = Table.from_broker(
            {
                "data": [
                    {
                        "key": {"@data-type": "string", "data": "s"},
                        "value": {
                            "@data-type": "integer",
                            "data": "42",
                        },
                    }
                ]
            }
        )
        self.assertEqual(1, len(t))
