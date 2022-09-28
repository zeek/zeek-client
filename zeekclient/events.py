"""Infrastructure for typed Zeek events."""
from .logs import LOG

from .brokertypes import (
    Boolean,
    Set,
    String,
    Type,
    Vector,
    ZeekEvent,
    from_py,
)

from .types import (
    SerializableZeekType,
)

class Event(SerializableZeekType):
    NAME = None # Name of the event, e.g. "Management::Controller::API::deploy_request"
    ARG_NAMES = [] # Names of the arguments, e.g. "reqid"
    ARG_TYPES = [] # Types in Python, e.g. str

    def __init__(self, *args):
        """Creates a Zeek event object.

        This expects the number of arguments contextualized above. The event
        name is not required since it's defined implicitly via the event class
        receiving the arguments.

        Raises:
            TypeError: when the given arguments, or number of arguments, don't
                match the expected ARG_TYPES or their number.
        """
        if len(args) != len(self.ARG_NAMES):
            raise TypeError('event argument length mismatch: have %d, expected %d'
                            % (len(args), len(self.ARG_NAMES)))

        self.args = []

        for idx, arg in enumerate(args):
            # If the argument's type matches the required Broker type, we're done.
            if isinstance(arg, self.ARG_TYPES[idx]):
                self.args.append(arg)
                continue

            try:
                # When creating an event it can be convenient for the caller to
                # pass Python-native types. See if we can create brokertypes
                # types from them, to match the types actually specified when we
                # created the event classes.
                maybe_arg = from_py(arg)
            except TypeError as err:
                raise TypeError('event argument type mismatch: argument '
                                '{} is {}, {}'.format(idx+1, type(arg), err)) from err

            # Again: if we now have a type match, we're done.
            if isinstance(maybe_arg, self.ARG_TYPES[idx]):
                self.args.append(maybe_arg)
                continue

            raise TypeError('event argument type mismatch: argument '
                            '{} is {}, should be {}'.format(
                                idx+1, type(arg), self.ARG_TYPES[idx]))

    def __getattr__(self, name):
        """Allow attribute-like access to event arguments."""
        try:
            idx = self.ARG_NAMES.index(name)
            return self.args[idx]
        except ValueError as err:
            raise AttributeError('event type {} has no "{}" argument'.format(
                self.NAME, name)) from err

    def __str__(self):
        # A list of pairs (argument name, typename)
        zeek_style_args = zip(self.ARG_NAMES, [str(type(arg)) for arg in self.args])
        # That list, with each item now a string "<name>: <typename"
        zeek_style_arg_strings = [': '.join(arg) for arg in zeek_style_args]
        # A Zeek-looking event signature
        return self.NAME + '(' + ', '.join(zeek_style_arg_strings) + ')'

    def to_brokertype(self):
        return ZeekEvent(self.NAME, *self.args)

    @classmethod
    def from_brokertype(cls, data):
        # Verify that data is an event
        return Registry.make_event(data.name, data.args)


class Registry:
    """Functionality for event types and to instantiate typed events from data."""

    # Map from Zeek-level event names to Event classes. The make_event()
    # function uses this map to instantiate the right event class from
    # received Broker data.
    EVENT_TYPES = {}

    @staticmethod
    def make_event_class(name, arg_names, arg_types):
        """Factory function to generate a Zeek event class.

        Given an event name, event arguments, and corresponding argument types,
        the function generates a new Event class, registers it, and returns it.
        """
        res = type(name, (Event,), {})

        if len(arg_names) != len(arg_types):
            raise TypeError('error creating event type {}: number of event '
                            'argument names and types must match ({}/{})'.format(
                                name, len(arg_names), len(arg_types)))

        for idx, typ in enumerate(arg_types):
            if not issubclass(typ, Type):
                raise TypeError('event type creation error: argument {}, '
                                '"{}", is not a brokertype class'.format(
                                    idx+1, arg_names[idx]))
        res.NAME = name
        res.ARG_NAMES = arg_names
        res.ARG_TYPES = arg_types

        # Register the new event type
        Registry.EVENT_TYPES[name] = res

        return res

    @staticmethod
    def make_event(name, *args):
        """This method allows constructing an Event instance from its name."""
        if name not in Registry.EVENT_TYPES:
            LOG.warning('received unexpected event "%s", skipping', name)
            return None

        LOG.debug('received event "%s"', name)
        return Registry.EVENT_TYPES[name](*args)


# Any Zeek object/record that's an event argument gets represented as a
# tuple below, reflecting Broker's representation thereof.

DeployRequest = Registry.make_event_class(
    'Management::Controller::API::deploy_request',
    ('reqid',), (String,))

DeployResponse = Registry.make_event_class(
    'Management::Controller::API::deploy_response',
    ('reqid', 'results'), (String, Vector))

GetConfigurationRequest = Registry.make_event_class(
    'Management::Controller::API::get_configuration_request',
    ('reqid', 'deployed'), (String, Boolean))

GetConfigurationResponse = Registry.make_event_class(
    'Management::Controller::API::get_configuration_response',
    ('reqid', 'result'), (String, Vector))

GetIdValueRequest = Registry.make_event_class(
    'Management::Controller::API::get_id_value_request',
    ('reqid', 'id', 'nodes'), (String, String, Set))

GetIdValueResponse = Registry.make_event_class(
    'Management::Controller::API::get_id_value_response',
    ('reqid', 'results'), (String, Vector))

GetInstancesRequest = Registry.make_event_class(
    'Management::Controller::API::get_instances_request',
    ('reqid',), (String,))

GetInstancesResponse = Registry.make_event_class(
    'Management::Controller::API::get_instances_response',
    ('reqid', 'result'), (String, Vector))

GetNodesRequest = Registry.make_event_class(
    'Management::Controller::API::get_nodes_request',
    ('reqid',), (String,))

GetNodesResponse = Registry.make_event_class(
    'Management::Controller::API::get_nodes_response',
    ('reqid', 'results'), (String, Vector))

RestartRequest = Registry.make_event_class(
    'Management::Controller::API::restart_request',
    ('reqid', 'nodes'), (String, Set))

RestartResponse = Registry.make_event_class(
    'Management::Controller::API::restart_response',
    ('reqid', 'results'), (String, Vector))

StageConfigurationRequest = Registry.make_event_class(
    'Management::Controller::API::stage_configuration_request',
    ('reqid', 'config'), (String, Vector))

StageConfigurationResponse = Registry.make_event_class(
    'Management::Controller::API::stage_configuration_response',
    ('reqid', 'results'), (String, Vector))

TestNoopRequest = Registry.make_event_class(
    'Management::Controller::API::test_noop_request',
    ('reqid',), (String,))

TestTimeoutRequest = Registry.make_event_class(
    'Management::Controller::API::test_timeout_request',
    ('reqid', 'with_state'), (String, Boolean))

TestTimeoutResponse = Registry.make_event_class(
    'Management::Controller::API::test_timeout_response',
    ('reqid', 'result'), (String, Vector))
