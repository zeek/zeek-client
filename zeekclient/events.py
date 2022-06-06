"""Convenience infrastructure for easier Zeek event handling via Broker."""
import broker

from .logs import LOG


class Event(broker.zeek.SafeEvent):
    """A specialization of Broker's Event class to make it printable, make arguments
    and their types explicit, and allow us to register instances as known event
    types."""
    # XXX at least the printability could go into Broker bindings

    # Contextualize the event: name, argument names, and argument types (in
    # Broker rendition).
    NAME = None
    ARG_NAMES = []
    ARG_TYPES = []

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
        if len(self.ARG_NAMES) != len(self.ARG_TYPES):
            raise TypeError('number of event argument names and types must match')

        for tpl in zip(args, self.ARG_TYPES, range(len(self.ARG_TYPES))):
            # The data model is permissive regarding list vs tuple, so accept
            # lists in stead of tuple:
            typ0, typ1 = type(tpl[0]), tpl[1]
            if typ1 == list and typ0 == tuple:
                typ0 = list
            if typ0 != typ1:
                raise TypeError('event type mismatch: argument %d is %s, should be %s'
                                % (tpl[2]+1, typ0, typ1))
        args = [self.NAME] + list(args)
        super().__init__(*args)

    def __getattr__(self, name):
        try:
            idx = self.ARG_NAMES.index(name)
            return self.args()[idx]
        except ValueError as err:
            raise AttributeError from err

    def __str__(self):
        # A list of pairs (argument name, typename)
        zeek_style_args = zip(self.ARG_NAMES, [str(type(arg)) for arg in self.args()])
        # That list, with each item now a string "<name>: <typename"
        zeek_style_arg_strings = [': '.join(arg) for arg in zeek_style_args]
        # A Zeek-looking event signature
        return self.name() + '(' + ', '.join(zeek_style_arg_strings) + ')'


class Registry:
    """Functionality for event types and to instantiate events from data."""

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

        res.NAME = name
        res.ARG_NAMES = arg_names
        res.ARG_TYPES = arg_types

        # Register the new event type
        Registry.EVENT_TYPES[name] = res

        return res

    @staticmethod
    def make_event(args):
        """Transform Broker-level data into Zeek event instance.

        The function takes received Broker-level data, instantiates a
        Broker-level event object from them, and uses the identified name to
        create a new Zeek event instance. Returns None if the event wasn't
        understood.
        """
        evt = broker.zeek.SafeEvent(args)
        args = evt.args()

        if evt.name() not in Registry.EVENT_TYPES:
            LOG.warning('received unexpected event "%s", skipping', evt.name())
            return None

        LOG.debug('received event "%s"', evt.name())
        return Registry.EVENT_TYPES[evt.name()](*args)


# Any Zeek object/record that's an event argument gets represented as a
# tuple below, reflecting Broker's representation thereof.

GetConfigurationRequest = Registry.make_event_class(
    'Management::Controller::API::get_configuration_request',
    ('reqid',), (str,))

GetConfigurationResponse = Registry.make_event_class(
    'Management::Controller::API::get_configuration_response',
    ('reqid', 'result'), (str, tuple))

GetIdValueRequest = Registry.make_event_class(
    'Management::Controller::API::get_id_value_request',
    ('reqid', 'id', 'nodes'), (str, str, set))

GetIdValueResponse = Registry.make_event_class(
    'Management::Controller::API::get_id_value_response',
    ('reqid', 'results'), (str, tuple))

GetInstancesRequest = Registry.make_event_class(
    'Management::Controller::API::get_instances_request',
    ('reqid',), (str,))

GetInstancesResponse = Registry.make_event_class(
    'Management::Controller::API::get_instances_response',
    ('reqid', 'result'), (str, tuple))

GetNodesRequest = Registry.make_event_class(
    'Management::Controller::API::get_nodes_request',
    ('reqid',), (str,))

GetNodesResponse = Registry.make_event_class(
    'Management::Controller::API::get_nodes_response',
    ('reqid', 'results'), (str, tuple))

SetConfigurationRequest = Registry.make_event_class(
    'Management::Controller::API::set_configuration_request',
    ('reqid', 'config'), (str, tuple))

SetConfigurationResponse = Registry.make_event_class(
    'Management::Controller::API::set_configuration_response',
    ('reqid', 'results'), (str, tuple))

TestNoopRequest = Registry.make_event_class(
    'Management::Controller::API::test_noop_request',
    ('reqid',), (str,))

TestTimeoutRequest = Registry.make_event_class(
    'Management::Controller::API::test_timeout_request',
    ('reqid', 'with_state'), (str, bool))

TestTimeoutResponse = Registry.make_event_class(
    'Management::Controller::API::test_timeout_response',
    ('reqid', 'result'), (str, tuple))
