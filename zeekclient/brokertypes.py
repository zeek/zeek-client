"""A Python type hierarchy representing Broker's data model.

Supported types are placed in a type hierarchy, with each type supporting
serialization to Broker's WebSocket wire format, unserialization from it, and
creation from "native" Python values, meaning of the closest typically used
Python type.

For reference, see: https://docs.zeek.org/projects/broker/en/current/web-socket.html

"""

import abc
import datetime
import enum
import ipaddress
import json
import re
from collections.abc import ItemsView, Iterator, KeysView, ValuesView
from typing import Any


class Type(abc.ABC):
    """Base class for types we can instantiate from or render to Broker's JSON
    data model. For details, see:
    https://docs.zeek.org/projects/broker/en/current/web-socket.html
    """

    def serialize(self, pretty: bool = False) -> str:
        """Serializes the object to Broker-compatible wire data.

        pretty: When True, pretty-prints the resulting JSON.

        Returns: raw message data ready to transmit.
        """
        indent = 4 if pretty else None
        return json.dumps(self.to_broker(), indent=indent, sort_keys=True)

    def __eq__(self, other: object) -> bool:
        """The default equality method for brokertypes.

        This implements member-by-member comparison based on the object's
        __dict__. The types complement this by each implementing their own
        __hash__() method.
        """
        if self.__class__ != other.__class__:
            return NotImplemented
        if len(self.__dict__) != len(other.__dict__):
            return False

        return self.__dict__ == other.__dict__

    def __repr__(self) -> str:
        return self.serialize()

    def __str__(self) -> str:
        return self.serialize(pretty=True)

    @classmethod
    def unserialize(cls, data: Any) -> Any:
        """Instantiates an object of this class from Broker wire data.

        This assumes the message content in JSON and first unserializes it into
        a Python data structure. It then calls from_broker() to instantiate an
        object of this class from it.

        data: raw wire WebSocket message content

        Returns: the resulting brokertype object.

        Raises: TypeError in case of invalid data. The exception's message
        provides details.
        """
        try:
            obj = json.loads(data)
        except json.JSONDecodeError as err:
            raise TypeError(
                f"cannot parse JSON data for {cls.__name__}: {err.msg} -- {data}",
            ) from err

        cls.check_broker_data(obj)

        try:
            # This may raise TypeError directly, which we pass on to the caller
            return cls.from_broker(obj)
        except (IndexError, KeyError, ValueError) as err:
            raise TypeError(f"invalid data for {cls.__name__}: {data}") from err

    @abc.abstractmethod
    def to_py(self) -> Any:
        """Returns a Python-"native" rendering of the object.

        For most brokertypes this will be a native Python type (such as int or
        str), but for some types the closest thing to a natural rendering of the
        value in Python will be the object itself.

        Return: a Python value
        """
        return None

    @abc.abstractmethod
    def to_broker(self) -> Any:
        """Returns a Broker-JSON-compatible Python data structure representing
        a value of this type.
        """
        ...

    @classmethod
    @abc.abstractmethod
    def check_broker_data(cls, data: Any) -> None:
        """Checks the Broker data for compliance with the expected type.

        If you use unserialize() to obtain objects, you can ignore this
        method. The module invokes it under the hood.

        data: a Python data structure resulting from json.loads().

        Raises TypeError in case of problems.
        """

    @classmethod
    @abc.abstractmethod
    def from_broker(cls, data: Any) -> Any:
        """Returns an instance of the type given Broker's JSON data.

        This is a low-level method that you likely don't want to use. Consider
        unserialize() instead: it handles raw wire data unserialization,
        type-checking, and exception canonicalization.

        data: a JSON-unserialized Python data structure.

        Raises: type-specific exceptions resulting from value construction, such
        as TypeError, KeyError, or ValueError.
        """
        return None


# ---- Basic types -----------------------------------------------------


class DataType(Type):
    """Base class for data types known to Broker."""

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, DataType):
            raise TypeError(
                f"'<' comparison not supported between instances "
                f"of '{type(self).__name__}' and '{type(other).__name__}'",
            )
        # Supporting comparison accross data types allows us to sort the members
        # of a set or table keys. We simply compare the type names:
        if self.__class__ != other.__class__:
            return type(self).__name__ < type(other).__name__

        return NotImplemented

    @classmethod
    def check_broker_data(cls, data: Any) -> None:
        if not isinstance(data, dict):
            raise TypeError("invalid data layout for Broker data: not an object")
        if "@data-type" not in data or "data" not in data:
            raise TypeError(
                "invalid data layout for Broker data: required keys missing",
            )


class NoneType(DataType):
    """Broker's representation of an absent value."""

    def __init__(self, _: None = None) -> None:
        # It helps to have a constructor that can be passed None explicitly, for
        # symmetry with other constructors below.
        pass

    def __lt__(self, other: object) -> bool:
        res = super().__lt__(other)
        if res != NotImplemented:
            return res
        return False

    def __hash__(self) -> int:
        return hash(None)

    def to_py(self) -> None:
        return None

    def to_broker(self) -> Any:
        return {
            "@data-type": "none",
            "data": {},
        }

    @classmethod
    def from_broker(cls, data: Any) -> Any:
        return NoneType()


class Boolean(DataType):
    def __init__(self, value: Any) -> None:
        self._value = bool(value)

    def __lt__(self, other: object) -> bool:
        res = super().__lt__(other)
        if res != NotImplemented:
            return res

        if not isinstance(other, Boolean):
            return False

        return self._value < other._value

    def __hash__(self) -> int:
        return hash(self._value)

    def to_py(self) -> bool:
        return self._value

    def to_broker(self) -> Any:
        return {
            "@data-type": "boolean",
            "data": self._value,
        }

    @classmethod
    def from_broker(cls, data: Any) -> "Boolean":
        return Boolean(data["data"])


class Count(DataType):
    def __init__(self, value: Any) -> None:
        self._value = int(value)
        if self._value < 0:
            raise ValueError("Count can only hold non-negative values")

    def __lt__(self, other: object) -> bool:
        res = super().__lt__(other)
        if res != NotImplemented:
            return res

        if not isinstance(other, Count):
            return False

        return self._value < other._value

    def __hash__(self) -> int:
        return hash(self._value)

    def to_py(self) -> int:
        return self._value

    def to_broker(self) -> Any:
        return {
            "@data-type": "count",
            "data": self._value,
        }

    @classmethod
    def from_broker(cls, data: Any) -> "Count":
        return Count(data["data"])


class Integer(DataType):
    def __init__(self, value: Any) -> None:
        self._value = int(value)

    def __lt__(self, other: object) -> bool:
        res = super().__lt__(other)
        if res != NotImplemented:
            return res

        if not isinstance(other, Integer):
            return False

        return self._value < other._value

    def __hash__(self) -> int:
        return hash(self._value)

    def to_py(self) -> int:
        return self._value

    def to_broker(self) -> Any:
        return {
            "@data-type": "integer",
            "data": self._value,
        }

    @classmethod
    def from_broker(cls, data: Any) -> "Integer":
        return Integer(data["data"])


class Real(DataType):
    def __init__(self, value: Any) -> None:
        self._value = float(value)

    def __lt__(self, other: object) -> bool:
        res = super().__lt__(other)
        if res != NotImplemented:
            return res

        if not isinstance(other, Real):
            return False

        return self._value < other._value

    def __hash__(self) -> int:
        return hash(self._value)

    def to_py(self) -> float:
        return self._value

    def to_broker(self) -> Any:
        return {
            "@data-type": "real",
            "data": self._value,
        }

    @classmethod
    def from_broker(cls, data: Any) -> "Real":
        return Real(data["data"])


class Timespan(DataType):
    REGEX = re.compile(r"(\d+(\.\d+)?)(ns|ms|s|min|h|d)")

    class Unit(enum.Enum):
        """The time unit shorthands supported by Broker."""

        NS = "ns"
        MS = "ms"
        S = "s"
        MIN = "min"
        H = "h"
        D = "d"

    def __init__(self, value: Any) -> None:
        if isinstance(value, datetime.timedelta):
            self._value = Timespan.timedelta_to_broker_timespan(value)
            self._td = value
        else:
            self._value = str(value)
            self._td = Timespan.broker_to_timedelta(self._value)

    def __eq__(self, other: object) -> bool:
        # Make equality defined by the timedelta instances, not the
        # more variable string data (e.g. 1000ms == 1s):
        if self.__class__ != other.__class__:
            return False

        if not isinstance(other, Timespan):
            return False

        return self._td == other._td

    def __lt__(self, other: object) -> bool:
        res = super().__lt__(other)
        if res != NotImplemented:
            return res

        if not isinstance(other, Timespan):
            return False

        return self._td < other._td

    def __hash__(self) -> int:
        return hash(self._value)

    def to_py(self) -> datetime.timedelta:
        return self._td

    def to_broker(self) -> Any:
        return {
            "@data-type": "timespan",
            "data": Timespan.timedelta_to_broker_timespan(self._td),
        }

    @classmethod
    def from_broker(cls, data: Any) -> "Timespan":
        return Timespan(cls.broker_to_timedelta(data["data"]))

    @classmethod
    def broker_to_timedelta(cls, data: Any) -> datetime.timedelta:
        """Converts Broker-compatible timespan string into timedelta object."""
        mob = cls.REGEX.fullmatch(data)
        if mob is None:
            raise ValueError(f"'{data}' is not an acceptable Timespan value")

        counter = float(mob[1])
        unit = Timespan.Unit(mob[3])

        if unit == Timespan.Unit.NS:
            return datetime.timedelta(microseconds=counter / 1e3)
        if unit == Timespan.Unit.MS:
            return datetime.timedelta(milliseconds=counter)
        if unit == Timespan.Unit.S:
            return datetime.timedelta(seconds=counter)
        if unit == Timespan.Unit.MIN:
            return datetime.timedelta(minutes=counter)
        if unit == Timespan.Unit.H:
            return datetime.timedelta(hours=counter)
        if unit == Timespan.Unit.D:
            if counter % 7 == 0:
                return datetime.timedelta(weeks=counter / 7)
            return datetime.timedelta(days=counter)

        raise AssertionError(f"unhandled timespan unit '{unit}'")

    @classmethod
    def timedelta_to_broker_timespan(cls, tdelta: datetime.timedelta) -> str:
        """Converts timedelta object to Broker-compatible timespan string."""
        # We use the smallest unit that's non-zero in the timespan (which has
        # only three relevant members: .microseconds, .seconds, and .days)
        # and map it to the closest Broker unit.

        def fmt(val: float, unit: str) -> str:
            # Don't say 10.0, say 10:
            val = int(val) if float(val).is_integer() else val
            return f"{val}{unit}"

        if tdelta.microseconds != 0:
            if tdelta.microseconds % 1000 == 0:
                return fmt(
                    tdelta.microseconds / 1e3
                    + tdelta.seconds * 1e3
                    + tdelta.days * 86400 * 1e3,
                    "ms",
                )
            # There are no microseconds in the Broker data model,
            # so go full plaid to nanoseconds.
            return fmt(
                tdelta.microseconds * 1e3
                + tdelta.seconds * 1e9
                + tdelta.days * 86400 * 1e9,
                "ns",
            )
        if tdelta.seconds != 0:
            if tdelta.seconds % 3600 == 0:
                return fmt(tdelta.seconds / 3600 + tdelta.days * 24, "h")
            if tdelta.seconds % 60 == 0:
                return fmt(tdelta.seconds / 60 + tdelta.days * 1440, "min")
            return fmt(tdelta.seconds + tdelta.days * 86400, "s")

        return fmt(tdelta.days, "d")


class Timestamp(DataType):
    def __init__(self, value: Any) -> None:
        if isinstance(value, datetime.datetime):
            self._value = Timestamp.to_broker_iso8601(value)
            self._ts = value
        else:
            self._value = str(value)
            # Raise value error if not formatted acceptably
            self._ts = datetime.datetime.fromisoformat(self._value)

    def __eq__(self, other: object) -> bool:
        # Make equality defined by the timestamp instances, not the
        # more variable ISO 8601 data:
        if self.__class__ != other.__class__:
            return False

        if not isinstance(other, Timestamp):
            return False

        return self._ts == other._ts

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Timestamp):
            return False

        return self._ts < other._ts

    def __hash__(self) -> int:
        return hash(self._value)

    def to_py(self) -> datetime.datetime:
        return self._ts

    def to_broker(self) -> Any:
        return {
            "@data-type": "timestamp",
            "data": Timestamp.to_broker_iso8601(self._ts),
        }

    @classmethod
    def from_broker(cls, data: Any) -> "Timestamp":
        return Timestamp(data["data"])

    @classmethod
    def to_broker_iso8601(cls, dtime: datetime.datetime) -> str:
        # The Broker docs say the timestamp looks like this:
        # "2022-04-10T07:00:00.000" -- meaning that given Python's
        # microseconds-granularity rendering we need to chop off the last
        # three digits:
        return dtime.isoformat(sep="T", timespec="microseconds")[:-3]


class String(DataType):
    def __init__(self, value: Any) -> None:
        self._value = str(value)

    def __lt__(self, other: object) -> bool:
        res = super().__lt__(other)
        if res != NotImplemented:
            return res

        if not isinstance(other, String):
            return False

        return self._value < other._value

    def __hash__(self) -> int:
        return hash(self._value)

    def to_py(self) -> str:
        return self._value

    def to_broker(self) -> Any:
        return {
            "@data-type": "string",
            "data": self._value,
        }

    @classmethod
    def from_broker(cls, data: Any) -> "String":
        return String(data["data"])


class Enum(DataType):
    def __init__(self, value: Any) -> None:
        self._value = str(value)

    def __lt__(self, other: object) -> bool:
        res = super().__lt__(other)
        if res != NotImplemented:
            return res

        if not isinstance(other, Enum):
            return False

        return self._value < other._value

    def __hash__(self) -> int:
        return hash(self._value)

    def to_py(self) -> str:
        return self._value

    def to_broker(self) -> Any:
        return {
            "@data-type": "enum-value",
            "data": self._value,
        }

    @classmethod
    def from_broker(cls, data: Any) -> "Enum":
        return Enum(data["data"])


class Address(DataType):
    def __init__(self, value: Any) -> None:
        self._value = str(value)  # A str or ipaddress.IPv[46]Address
        # Throws a derivative of ValueError when not v4/v6 address:
        self._addr = ipaddress.ip_address(self._value)

    def __lt__(self, other: object) -> bool:
        res = super().__lt__(other)
        if res != NotImplemented:
            return res

        if not isinstance(other, Address):
            return False

        if self._addr.version == other._addr.version:
            return self._addr < other._addr  # type: ignore

        # Make a blanket assumption that an IPv4 address is "less than" an IPv6 address
        return self._addr.version < other._addr.version

    def __hash__(self) -> int:
        return hash(self._value)

    def to_py(self) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        return self._addr

    def to_broker(self) -> Any:
        return {
            "@data-type": "address",
            "data": self._value,
        }

    @classmethod
    def from_broker(cls, data: Any) -> "Address":
        return Address(data["data"])


class Subnet(DataType):
    def __init__(self, value: Any) -> None:
        self._value = str(value)  # A str or ipaddress.IPv[46]Network
        # Throws a derivative of ValueError when not v4/v6 network:
        self._subnet = ipaddress.ip_network(self._value)

    def __lt__(self, other: object) -> bool:
        res = super().__lt__(other)
        if res != NotImplemented:
            return res

        if not isinstance(other, Subnet):
            return False

        if self._subnet.version == other._subnet.version:
            return self._subnet < other._subnet  # type: ignore

        # Make a blanket assumption that an IPv4 subnet is "less than" an IPv6 subnet.
        return self._subnet.version < other._subnet.version

    def __hash__(self) -> int:
        return hash(self._value)

    def to_py(self) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
        return self._subnet

    def to_broker(self) -> Any:
        return {
            "@data-type": "subnet",
            "data": str(self._subnet),
        }

    @classmethod
    def from_broker(cls, data: Any) -> "Subnet":
        return Subnet(data["data"])


class Port(DataType):
    class Proto(enum.Enum):
        UNKNOWN = "?"
        TCP = "tcp"
        UDP = "udp"
        ICMP = "icmp"

    def __init__(self, number: str | int, proto: Any = Proto.TCP) -> None:
        self.number = int(number)
        self.proto = proto
        if not isinstance(proto, self.Proto):
            raise TypeError("Port constructor requires Proto enum")
        if self.number < 1 or self.number > 65535:
            raise ValueError(f"Port number '{self.number}' invalid")

    def __lt__(self, other: object) -> bool:
        res = super().__lt__(other)
        if res != NotImplemented:
            return res
        order = ["?", "tcp", "udp", "icmp"]

        if not isinstance(other, Port):
            return False

        if order.index(self.proto.value) < order.index(other.proto.value):
            return True
        return self.number < other.number

    def __hash__(self) -> int:
        return hash((self.number, self.proto))

    def to_py(self) -> "Port":
        return self

    def to_broker(self) -> Any:
        return {
            "@data-type": "port",
            "data": f"{self.number}/{self.proto.value}",
        }

    @classmethod
    def from_broker(cls, data: Any) -> "Port":
        return Port(
            data["data"].split("/", 1)[0],
            Port.Proto(data["data"].split("/", 1)[1]),
        )


class Vector(DataType):
    def __init__(self, elements: list[Any] | None = None) -> None:
        self._elements = elements or []
        if not isinstance(self._elements, tuple) and not isinstance(
            self._elements,
            list,
        ):
            raise TypeError("Vector initialization requires tuple or list data")
        if not all(isinstance(elem, Type) for elem in self._elements):
            raise TypeError("Non-empty Vector construction requires brokertype values.")

    def __lt__(self, other: object) -> bool:
        res = super().__lt__(other)
        if res != NotImplemented:
            return res

        if not isinstance(other, Vector):
            return False

        for el1, el2 in zip(self._elements, other._elements, strict=False):
            if el1 < el2:
                return True
        if len(self._elements) < len(other._elements):
            return True
        return False

    def __hash__(self) -> int:
        return hash(tuple(self._elements))

    def __iter__(self) -> Iterator[Any]:
        return iter(self._elements)

    def __len__(self) -> int:
        return len(self._elements)

    def __getitem__(self, idx: int) -> Any:
        return self._elements[idx]

    def to_py(self) -> list[Any]:
        return [elem.to_py() for elem in self._elements]

    def to_broker(self) -> Any:
        return {
            "@data-type": "vector",
            "data": [elem.to_broker() for elem in self._elements],
        }

    @classmethod
    def from_broker(cls, data: Any) -> "Vector":
        return Vector([from_broker(elem) for elem in data["data"]])


class Set(DataType):
    def __init__(self, elements: set[Any] | Any = None) -> None:
        self._elements = elements or set()
        if not isinstance(self._elements, set):
            raise TypeError("Set initialization requires set data")
        if not all(isinstance(elem, Type) for elem in self._elements):
            raise TypeError("Non-empty Set construction requires brokertype values.")

    def __lt__(self, other: object) -> bool:
        res = super().__lt__(other)
        if res != NotImplemented:
            return res

        if not isinstance(other, Set):
            return False

        for el1, el2 in zip(
            sorted(self._elements), sorted(other._elements), strict=False
        ):
            if el1 < el2:
                return True
        if len(self._elements) < len(other._elements):
            return True
        return False

    def __hash__(self) -> int:
        return hash(tuple(sorted(self._elements)))

    def __iter__(self) -> Iterator[Any]:
        return iter(self._elements)

    def __len__(self) -> int:
        return len(self._elements)

    def __contains__(self, key: Any) -> bool:
        return key in self._elements

    def to_py(self) -> set[Any]:
        return {elem.to_py() for elem in self._elements}

    def to_broker(self) -> Any:
        return {
            "@data-type": "set",
            "data": [elem.to_broker() for elem in sorted(self._elements)],
        }

    @classmethod
    def from_broker(cls, data: Any) -> "Set":
        return Set({from_broker(elem) for elem in data["data"]})


class Table(DataType):
    def __init__(self, elements: dict[Any, Any] | None = None) -> None:
        self._elements = elements or {}
        if not isinstance(self._elements, dict):
            raise TypeError("Table initialization requires dict data")
        keys_ok = all(isinstance(elem, Type) for elem in self._elements.keys())
        vals_ok = all(isinstance(elem, Type) for elem in self._elements.values())
        if not keys_ok or not vals_ok:
            raise TypeError("Non-empty Table construction requires brokertype values.")

    def __lt__(self, other: object) -> bool:
        res = super().__lt__(other)
        if res != NotImplemented:
            return res

        if not isinstance(other, Table):
            return False

        for key1, key2 in zip(
            sorted(self._elements), sorted(other._elements), strict=False
        ):
            if key1 < key2:
                return True
            if self._elements[key1] < other._elements[key2]:
                return True
        if len(self._elements) < len(other._elements):
            return True
        return False

    def __hash__(self) -> int:
        return hash((key, self._elements[key]) for key in sorted(self._elements))

    def __iter__(self) -> Iterator[Any]:
        return iter(self._elements)

    def __len__(self) -> int:
        return len(self._elements)

    def __contains__(self, key: Any) -> bool:
        return key in self._elements

    def keys(self) -> KeysView[Any]:
        return self._elements.keys()

    def values(self) -> ValuesView[Any]:
        return self._elements.values()

    def items(self) -> ItemsView[Any, Any]:
        return self._elements.items()

    def to_py(self) -> dict[Any, Any]:
        res = {}
        for key, val in self._elements.items():
            res[key.to_py()] = val.to_py()
        return res

    def to_broker(self) -> Any:
        return {
            "@data-type": "table",
            "data": [
                {"key": key.to_broker(), "value": self._elements[key].to_broker()}
                for key in sorted(self._elements)
            ],
        }

    @classmethod
    def from_broker(cls, data: Any) -> "Table":
        return Table(
            {
                from_broker(elem["key"]): from_broker(elem["value"])
                for elem in data["data"]
            },
        )


# ---- Special types ---------------------------------------------------


class ZeekEvent(Vector):
    """Broker's event representation, as a vector of vectors.

    This specialization isn't an official type in Broker's hierarchy: there's no
    distinguishing @data-type for it. Zeek events are a specific interpretation
    of nested vectors.

    See Broker's websockets docs for an example:

    https://docs.zeek.org/projects/broker/en/current/web-socket.html#encoding-of-zeek-events
    """

    def __init__(self, name: str, *args: Any) -> None:
        super().__init__()

        self.name = name.to_py() if isinstance(name, String) else str(name)
        self.args = list(args) or []  # list here is to avoid tuple/list type confusion

        for arg in self.args:
            if not isinstance(arg, Type):
                raise TypeError("ZeekEvent constructor requires brokertype arguments")

    def to_broker(self) -> Any:
        return {
            "@data-type": "vector",
            "data": [
                {"@data-type": "count", "data": 1},
                {"@data-type": "count", "data": 1},
                {
                    "@data-type": "vector",
                    "data": [
                        String(self.name).to_broker(),
                        {
                            "@data-type": "vector",
                            "data": [arg.to_broker() for arg in self.args],
                        },
                    ],
                },
            ],
        }

    @classmethod
    def from_vector(cls, vec: Vector | Any) -> "ZeekEvent":
        """Special case for an existing Vector instance: recast as Zeek event."""
        if not isinstance(vec, Vector):
            raise TypeError("cannot convert non-vector to Zeek event")

        if (
            len(vec) < 3
            or not isinstance(vec[2], Vector)
            or len(vec[2]) < 2
            or not isinstance(vec[2][0], String)
            or not isinstance(vec[2][1], Vector)
        ):
            raise TypeError("invalid vector layout for Zeek event")

        name = vec[2][0].to_py()
        args = vec[2][1]

        # TODO: Extend to handle metadata

        return ZeekEvent(name, *args._elements)

    @classmethod
    def from_broker(cls, data: Any) -> "ZeekEvent":
        name = data["data"][2]["data"][0]["data"]
        res = ZeekEvent(name)
        for argdata in data["data"][2]["data"][1]["data"]:
            res.args.append(from_broker(argdata))
        return res


# ---- Message types ---------------------------------------------------


class MessageType(Type):
    """Base class for Broker messages."""

    @classmethod
    def check_broker_data(cls, data: Any) -> None:
        if not isinstance(data, dict):
            raise TypeError(
                f"invalid data layout for Broker {cls.__name__}: not an object",
            )
        if "type" not in data:
            raise TypeError(
                f"invalid data layout for Broker {cls.__name__}: required keys missing",
            )


class HandshakeMessage(MessageType):
    """The handshake message sent by the client.

    This is just a list of topics to subscribe to. Clients won't receive it.
    """

    def __init__(self, topics: Any = None) -> None:
        self.topics = []

        if topics:
            if not isinstance(topics, tuple) and not isinstance(topics, list):
                raise TypeError("HandshakeMessage construction requires a topics list")
            for topic in topics:
                if isinstance(topic, str):
                    self.topics.append(topic)
                    continue
                if isinstance(topic, String):
                    self.topics.append(topic.to_py())
                    continue
                raise TypeError(
                    "topics for HandshakeMessage must be Python or brokertype strings",
                )

    def to_py(self) -> "HandshakeMessage":
        return self

    def to_broker(self) -> Any:
        return self.topics

    @classmethod
    def check_broker_data(cls, data: Any) -> None:
        if not isinstance(data, tuple) and not isinstance(data, list):
            raise TypeError("invalid data layout for HandshakeMessage: not an object")

    @classmethod
    def from_broker(cls, data: Any) -> "HandshakeMessage":
        return HandshakeMessage(data)


class HandshakeAckMessage(MessageType):
    """The ACK message returned to the client in response to the handshake.

    Clients won't need to send this.
    """

    def __init__(self, endpoint: str, version: str) -> None:
        self.endpoint = endpoint
        self.version = version

    def to_py(self) -> "HandshakeAckMessage":
        return self

    def to_broker(self) -> Any:
        return {
            "type": "ack",
            "endpoint": self.endpoint,
            "version": self.version,
        }

    @classmethod
    def check_broker_data(cls, data: Any) -> None:
        MessageType.check_broker_data(data)
        for key in ("type", "endpoint", "version"):
            if key not in data:
                raise TypeError(
                    f"invalid data layout for HandshakeAckMessage: "
                    f'required key "{key}" missing',
                )

    @classmethod
    def from_broker(cls, data: Any) -> "HandshakeAckMessage":
        return HandshakeAckMessage(data["endpoint"], data["version"])


class DataMessage(MessageType):
    def __init__(self, topic: str, data: Any) -> None:
        self.topic = topic
        self.data = data

    def to_py(self) -> "DataMessage":
        return self

    def to_broker(self) -> Any:
        bdata = self.data.to_broker()

        return {
            "type": "data-message",
            "topic": self.topic,
            "@data-type": bdata["@data-type"],
            "data": bdata["data"],
        }

    @classmethod
    def check_broker_data(cls, data: Any) -> None:
        MessageType.check_broker_data(data)
        for key in ("type", "topic", "@data-type", "data"):
            if key not in data:
                raise TypeError(
                    f"invalid data layout for DataMessage: "
                    f'required key "{key}" missing',
                )

    @classmethod
    def from_broker(cls, data: Any) -> "DataMessage":
        return DataMessage(
            data["topic"],
            from_broker({"@data-type": data["@data-type"], "data": data["data"]}),
        )


class ErrorMessage(Type):
    def __init__(self, code: str, context: str) -> None:
        self.code = code  # A string representation of a Broker error code
        self.context = context

    def to_py(self) -> "ErrorMessage":
        return self

    def to_broker(self) -> Any:
        return {
            "type": "error",
            "code": self.code,
            "context": self.context,
        }

    @classmethod
    def check_broker_data(cls, data: Any) -> None:
        MessageType.check_broker_data(data)
        for key in ("type", "code", "context"):
            if key not in data:
                raise TypeError(
                    f"invalid data layout for ErrorMessage: "
                    f'required key "{key}" missing',
                )

    @classmethod
    def from_broker(cls, data: Any) -> "ErrorMessage":
        return ErrorMessage(data["code"], data["context"])


# ---- Factory functions -----------------------------------------------

# This maps the types expressed in Broker's JSON representation to those
# implemented in this module.
_broker_typemap: dict[str, type[DataType]] = {
    "none": NoneType,
    "address": Address,
    "boolean": Boolean,
    "count": Count,
    "enum-value": Enum,
    "integer": Integer,
    "port": Port,
    "real": Real,
    "set": Set,
    "string": String,
    "subnet": Subnet,
    "table": Table,
    "timespan": Timespan,
    "timestamp": Timestamp,
    "vector": Vector,
}

# This maps Broker's message types to ones implemented in this module.  A
# separate map, because Broker expresses the type information differently from
# the above.
_broker_messagemap = {
    "data-message": DataMessage,
    "error": ErrorMessage,
}


def unserialize(data: Any) -> DataType:
    """A factory that instantiates a brokertype value from Broker wire data.

    This assumes the message content in JSON and first unserializes it into a
    Python data structure. It then calls from_python() to instantiate an object
    of the appropriate class from it.
    """
    try:
        obj = json.loads(data)
    except json.JSONDecodeError as err:
        raise TypeError(f"cannot parse JSON data: {err.msg} -- {data}") from err

    return from_broker(obj)


def from_broker(data: Any) -> DataType:
    """A factory that turns Python-level data into brokertype instances.

    Consider using unserialize() instead, it starts from raw message data, and
    provides better error handling.

    data: a JSON-unserialized Python data structure.

    Returns: a brokerval instance

    Raises: TypeError in case of invalid input data.
    """
    if not isinstance(data, dict):
        raise TypeError("invalid data layout for Broker data: not an object")

    try:
        typ = _broker_messagemap[data["type"]]
        typ.check_broker_data(data)
        return typ.from_broker(data)  # type: ignore
    except KeyError:
        pass

    try:
        typ = _broker_typemap[data["@data-type"]]
        typ.check_broker_data(data)
        return typ.from_broker(data)  # type: ignore
    except KeyError as err:
        raise TypeError(f"unrecognized Broker type: {data}") from err


# Python types we can directly map to ones in this module, used by
# from_py(). This is imperfect since, for example, no non-negative integer type
# exists that maps to Count, but a generic factory adds convenience in many
# situations. Callers who need different mappings need to implement code that
# converts their data structures explicitly.
_python_typemap = {
    type(None): NoneType,
    bool: Boolean,
    datetime.timedelta: Timespan,
    datetime.datetime: Timestamp,
    dict: Table,
    float: Real,
    int: Integer,
    ipaddress.IPv4Address: Address,
    ipaddress.IPv6Address: Address,
    ipaddress.IPv4Network: Subnet,
    ipaddress.IPv6Network: Subnet,
    list: Vector,
    set: Set,
    str: String,
    tuple: Vector,
}


def from_py(
    data: Any, typ: type[Any] | None = None, check_none: bool = True
) -> DataType:
    """Instantiates a brokertype object from the given Python data.

    Some Python types map naturally to Broker ones, such as bools and strs. For
    those, you can simply provide a value and the function will return the
    appropriate brokertype value. For some types this mapping isn't clear, and
    you need to specify the type explicitly. For composite types like
    sets or dicts the approach applies recursively to their member elements.

    When no type match is found, or the type conversion isn't feasible, this
    raises a TypeError. This can happen for types that don't have an immediate
    equivalent (e.g., Python has no unsigned integers).

    This function currently supports only types constructed from a single
    argument.

    data: a Python-"native" value, such as a str, int, or bool.

    typ (Type): if provided, the function attempts to instantiate an object of
        this type with the given data. By default, the function attempts type
        inference.

    check_none (bool): when True (the default), the function checks whether data
        is None, and shortcuts to returning a NoneType instance.

    Returns: a brokertype instance.

    Raises: TypeError in case problems arise in the type mapping or value
        construction.
    """
    if data is None and check_none:
        return NoneType()

    if typ is not None:
        if not issubclass(typ, Type):
            raise TypeError(f"not a brokertype: {typ.__name__}")
    else:
        try:
            typ = _python_typemap[type(data)]
        except KeyError as err:
            raise TypeError(
                f"cannot map Python type {type(data)} to Broker type",
            ) from err

    res: DataType

    if typ == Table:
        res = Table()
        for key, val in data.items():
            res._elements[from_py(key)] = from_py(
                val,
            )
        return res

    if typ == Vector:
        res = Vector()
        for elem in data:
            res._elements.append(from_py(elem))
        return res

    if typ == Set:
        res = Set()
        for elem in data:
            res._elements.add(from_py(elem))
        return res

    # For others the constructors of the types in this module should naturally
    # work with the provided value.
    return typ(data)  # type: ignore
