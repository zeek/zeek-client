"""Infrastructure for typed Zeek events."""

from typing import Any

from .brokertypes import (
    Boolean,
    DataType,
    Set,
    String,
    Type,
    Vector,
    ZeekEvent,
    from_py,
)
from .logs import LOG
from .types import (
    SerializableZeekType,
)


class Event(SerializableZeekType):
    NAME: str  # Name of the event, e.g. "Management::Controller::API::deploy_request"
    ARG_NAMES: list[str] = []  # Names of the arguments, e.g. "reqid"
    ARG_TYPES: list[type[DataType]] = []  # Types in Python, e.g. str

    def __init__(self, *args: Any) -> None:
        """Creates a Zeek event object.

        This expects the number of arguments contextualized above. The event
        name is not required since it's defined implicitly via the event class
        receiving the arguments.

        Raises:
            TypeError: when the given arguments, or number of arguments, don't
                match the expected ARG_TYPES or their number.
        """
        if len(args) != len(self.ARG_NAMES):
            raise TypeError(
                f"event argument length mismatch: have {len(args)}, expected {len(self.ARG_NAMES)}",
            )

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
                raise TypeError(
                    f"event argument type mismatch: argument "
                    f"{idx + 1} is {type(arg)}, {err}",
                ) from err

            # Again: if we now have a type match, we're done.
            if isinstance(maybe_arg, self.ARG_TYPES[idx]):
                self.args.append(maybe_arg)
                continue

            raise TypeError(
                f"event argument type mismatch: argument "
                f"{idx + 1} is {type(arg)}, should be {self.ARG_TYPES[idx]}",
            )

    def __getattr__(self, name: str) -> DataType:
        """Allow attribute-like access to event arguments."""
        try:
            idx = self.ARG_NAMES.index(name)
            return self.args[idx]
        except ValueError as err:
            raise AttributeError(
                f'event type {self.NAME} has no "{name}" argument',
            ) from err

    def __str__(self) -> str:
        # A list of pairs (argument name, typename)
        zeek_style_args = zip(
            self.ARG_NAMES, [str(type(arg)) for arg in self.args], strict=False
        )
        # That list, with each item now a string "<name>: <typename"
        zeek_style_arg_strings = [": ".join(arg) for arg in zeek_style_args]
        # A Zeek-looking event signature
        return self.NAME + "(" + ", ".join(zeek_style_arg_strings) + ")"

    def to_brokertype(self) -> ZeekEvent:
        return ZeekEvent(self.NAME, *self.args)

    @classmethod
    def from_brokertype(cls, data: Any) -> Any:
        # Verify that data is an event
        return Registry.make_event(data.name, data.args)


class Registry:
    """Functionality for event types and to instantiate typed events from data."""

    # Map from Zeek-level event names to Event classes. The make_event()
    # function uses this map to instantiate the right event class from
    # received Broker data.
    EVENT_TYPES: dict[str, type[Event]] = {}

    @staticmethod
    def make_event_class(
        name: str, arg_names: list[str], arg_types: list[type[Any]]
    ) -> type[Event]:
        """Factory function to generate a Zeek event class.

        Given an event name, event arguments, and corresponding argument types,
        the function generates a new Event class, registers it, and returns it.
        """
        res = type(name, (Event,), {})

        if len(arg_names) != len(arg_types):
            raise TypeError(
                f"error creating event type {name}: number of event "
                f"argument names and types must match ({len(arg_names)}/{len(arg_types)})",
            )

        for idx, typ in enumerate(arg_types):
            if not issubclass(typ, Type):
                raise TypeError(
                    f"event type creation error: argument {idx + 1}, "
                    f'"{arg_names[idx]}", is not a brokertype class',
                )
        res.NAME = name  # type: ignore
        res.ARG_NAMES = arg_names  # type: ignore
        res.ARG_TYPES = arg_types  # type: ignore

        # Register the new event type
        Registry.EVENT_TYPES[name] = res

        return res

    @staticmethod
    def make_event(name: str, *args: Any) -> Event | None:
        """This method allows constructing an Event instance from its name."""
        if name not in Registry.EVENT_TYPES:
            LOG.warning('received unexpected event "%s", skipping', name)
            return None

        LOG.debug('received event "%s"', name)
        return Registry.EVENT_TYPES[name](*args)


# Any Zeek object/record that's an event argument gets represented as a
# tuple below, reflecting Broker's representation thereof.

DeployRequest = Registry.make_event_class(
    "Management::Controller::API::deploy_request",
    ["reqid"],
    [String],
)

DeployResponse = Registry.make_event_class(
    "Management::Controller::API::deploy_response",
    ["reqid", "results"],
    [String, Vector],
)

GetConfigurationRequest = Registry.make_event_class(
    "Management::Controller::API::get_configuration_request",
    ["reqid", "deployed"],
    [String, Boolean],
)

GetConfigurationResponse = Registry.make_event_class(
    "Management::Controller::API::get_configuration_response",
    ["reqid", "result"],
    [String, Vector],
)

GetIdValueRequest = Registry.make_event_class(
    "Management::Controller::API::get_id_value_request",
    ["reqid", "id", "nodes"],
    [String, String, Set],
)

GetIdValueResponse = Registry.make_event_class(
    "Management::Controller::API::get_id_value_response",
    ["reqid", "results"],
    [String, Vector],
)

GetInstancesRequest = Registry.make_event_class(
    "Management::Controller::API::get_instances_request",
    ["reqid"],
    [String],
)

GetInstancesResponse = Registry.make_event_class(
    "Management::Controller::API::get_instances_response",
    ["reqid", "result"],
    [String, Vector],
)

GetNodesRequest = Registry.make_event_class(
    "Management::Controller::API::get_nodes_request",
    ["reqid"],
    [String],
)

GetNodesResponse = Registry.make_event_class(
    "Management::Controller::API::get_nodes_response",
    ["reqid", "results"],
    [String, Vector],
)

RestartRequest = Registry.make_event_class(
    "Management::Controller::API::restart_request",
    ["reqid", "nodes"],
    [String, Set],
)

RestartResponse = Registry.make_event_class(
    "Management::Controller::API::restart_response",
    ["reqid", "results"],
    [String, Vector],
)

StageConfigurationRequest = Registry.make_event_class(
    "Management::Controller::API::stage_configuration_request",
    ["reqid", "config"],
    [String, Vector],
)

StageConfigurationResponse = Registry.make_event_class(
    "Management::Controller::API::stage_configuration_response",
    ["reqid", "results"],
    [String, Vector],
)

TestNoopRequest = Registry.make_event_class(
    "Management::Controller::API::test_noop_request",
    ["reqid"],
    [String],
)

TestTimeoutRequest = Registry.make_event_class(
    "Management::Controller::API::test_timeout_request",
    ["reqid", "with_state"],
    [String, Boolean],
)

TestTimeoutResponse = Registry.make_event_class(
    "Management::Controller::API::test_timeout_response",
    ["reqid", "result"],
    [String, Vector],
)
