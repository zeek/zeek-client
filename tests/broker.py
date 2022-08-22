"""An fairly minimal shim/mock to pose as Broker to our unit tests.

Since the real Broker package is expensive to build we'd like to get by without
it. That aside, we also want to mock its functionality to isolate the unit
tests.
"""
import enum


class Enum:
    def __init__(self, name):
        self.name = name


class Port:
    Unknown = 0
    TCP = 1
    UDP = 2
    ICMP = 3

    def __init__(self, port, proto):
        self.port = port
        self.proto = proto

    def __str__(self):
        return str(self.port)


class Endpoint:
    def __init__(self):
        self.events = []

    def peer_nosync(self, host, port, retry_secs):
        pass

    def publish(self, topic, event):
        self.events.append((topic, event))

    def make_safe_subscriber(self, topic):
        return Subscriber()

    def make_status_subscriber(self, receive_statuses):
        return StatusSubscriber()


class Subscriber:
    def __init__(self):
        # A sequence of (topic, data) tuples, that iterative
        # get() calls will retrieve tuple by tuple.
        self.mock_data = []

    def available(self):
        return True

    def fd(self):
        return 0

    def get(self, secs=None, num=None):
        assert self.mock_data, 'subscriber mock ran out of data'
        return self.mock_data.pop(0)


class SafeSubscriber(Subscriber):
    pass


class StatusSubscriber:
    def __init__(self):
        self.fd_val = 0
        self.status = Status()

    def available(self):
        return True

    def fd(self):
        return self.fd_val

    def get(self):
        return self.status


class SC(enum.Enum):
    Unspecified = enum.auto()
    PeerAdded = enum.auto()
    PeerRemoved = enum.auto()
    PeerLost = enum.auto()
    EndpointDiscovered = enum.auto()
    EndpointUnreachable = enum.auto()


class Status:
    def __init__(self, code=SC.PeerAdded):
        self.code_val = code

    def code(self):
        return self.code_val


class zeek:
    class Event:
        def __init__(self, *args):
            # This mirrors the funky logic in Broker's zeek.py:
            if len(args) == 1 and not isinstance(args[0], str):
                # Parse raw broker message as event.
                self.ev_name = args[0][0]
                self.ev_args = args[0][1:]
            else:
                # (name, arg1, arg2, ...)
                self.ev_name = args[0]
                self.ev_args = args[1:]

        def name(self):
            return self.ev_name

        def args(self):
            return self.ev_args

    class SafeEvent(Event):
        pass
