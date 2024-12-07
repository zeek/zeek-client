"""This module provides Broker-based communication with a Zeek cluster controller."""

import ssl
import time

import websocket

from .brokertypes import (
    DataMessage,
    HandshakeAckMessage,
    HandshakeMessage,
    ZeekEvent,
)
from .config import CONFIG
from .consts import CONTROLLER_TOPIC
from .events import Registry
from .logs import LOG
from .ssl import get_websocket_sslopt
from .utils import make_uuid


class Error(Exception):
    """Catch-all for exceptions arising from use of Controller objects."""


class ConfigError(Error):
    """A problem occurred while configuring the WebSocket object."""


class UsageError(Error):
    """Invalid sequence of operations on a Controller object."""


class Controller:
    """A class managing a connection to the Zeek cluster controller."""

    def __init__(
        self,
        controller_host=None,
        controller_port=None,
        controller_topic=CONTROLLER_TOPIC,
    ):
        """Controller connection constructor.

        This may raise ConfigError in case of trouble with the
        connection settings.
        """
        self.controller_host = controller_host or CONFIG.get("controller", "host")
        self.controller_port = controller_port or CONFIG.getint("controller", "port")
        self.controller_topic = controller_topic
        self.controller_broker_id = None  # Defined in Handshake ACK message

        try:
            if self.controller_port < 1 or self.controller_port > 65535:
                raise ValueError(
                    f"controller port number {self.controller_port} outside valid range",
                )

            disable_ssl = CONFIG.getboolean("ssl", "disable")

            proto = "ws" if disable_ssl else "wss"
            remote = f"{self.controller_host}:{self.controller_port}"
            self.wsock_url = f"{proto}://{remote}/v1/messages/json"

            sslopt = None if disable_ssl else get_websocket_sslopt()
            self.wsock = websocket.WebSocket(sslopt=sslopt)
        except (ValueError, OSError, ssl.SSLError) as err:
            raise ConfigError(
                f"cannot configure connection to "
                f"{self.controller_host}:{self.controller_port}: {err}",
            ) from err

    def connect(self):
        """Connect to the configured controller.

        This takes the controller coordonates from the zeek-client configuration
        (or the arguments passed to the constructor, if any) and establishes a
        fully peered connection. "Fully peered" here means that the object first
        establishes the websocket connection, potentially wrapped in TLS as per
        the TLS-specific configuration settings, and then conducts the
        Broker-level handshake. The latter establishes the Controller's Broker
        ID and our topic subscriptions.

        Returns True if peering completes successfully, False otherwise, with
        according messages written to the log.
        """
        LOG.info(
            "connecting to controller %s:%s",
            self.controller_host,
            self.controller_port,
        )

        attempts = CONFIG.getint("client", "peering_attempts")
        retry_delay = CONFIG.getfloat("client", "peering_retry_delay_secs")

        handshake = HandshakeMessage([self.controller_topic])

        # We accommodate problems during connect() and the Broker handshake,
        # attempting these a total of client.peering_attempts times.  That is,
        # if we use 10 attempts and connect() takes 3 attempts, 7 attempts
        # remain for the handshake. Since the kinds of problems that may arise
        # in either stage in the (web)socket operations overlap substantially,
        # we use a single function that checks them all:
        def wsock_operation(op, stage):
            nonlocal attempts

            while attempts > 0:
                try:
                    attempts -= 1
                    return op()
                except websocket.WebSocketTimeoutException:
                    time.sleep(retry_delay)
                    continue
                except websocket.WebSocketException as err:
                    LOG.error(
                        "websocket error in %s with controller %s:%s: %s",
                        stage,
                        self.controller_host,
                        self.controller_port,
                        err,
                    )
                    return False
                except ConnectionRefusedError:
                    # We don't consider these fatal since they can happen
                    # naturally during tests and other automated setups where
                    # it's beneficial to keep trying.  Also, this is a subclass
                    # of OSError, so needs to come before it:
                    LOG.debug(
                        "connection refused for controller %s:%s",
                        self.controller_host,
                        self.controller_port,
                    )
                    time.sleep(retry_delay)
                    continue
                except ssl.SSLError as err:
                    # Same here, likewise a subclass of OSError:
                    LOG.error(
                        "socket TLS error in %s with controller %s:%s: %s",
                        stage,
                        self.controller_host,
                        self.controller_port,
                        err,
                    )
                    return False
                except OSError as err:
                    # From socket.py docs: "Errors related to socket or address
                    # semantics raise OSError or one of its subclasses".
                    LOG.error(
                        "socket error in %s with controller %s:%s: %s",
                        stage,
                        self.controller_host,
                        self.controller_port,
                        err,
                    )
                    return False
                except Exception as err:
                    LOG.exception(
                        "unexpected error in %s with controller %s:%s: %s",
                        stage,
                        self.controller_host,
                        self.controller_port,
                        err,
                    )
                    return False

            if attempts == 0:
                LOG.error(
                    "websocket connection to %s:%s timed out in %s",
                    self.controller_host,
                    self.controller_port,
                    stage,
                )
            return False

        def connect_op():
            self.wsock.connect(self.wsock_url, timeout=retry_delay)
            self.wsock.send(handshake.serialize())
            return True

        def handshake_op():
            rawdata = self.wsock.recv()
            try:
                msg = HandshakeAckMessage.unserialize(rawdata)
            except TypeError as err:
                LOG.error(
                    "protocol data error with controller %s:%s: %s, raw data: %s",
                    self.controller_host,
                    self.controller_port,
                    err,
                    rawdata,
                )
                return False

            self.controller_broker_id = msg.endpoint
            LOG.info(
                "peered with controller %s:%s",
                self.controller_host,
                self.controller_port,
            )
            return True

        if not wsock_operation(connect_op, "connect()"):
            return False
        if not wsock_operation(handshake_op, "handshake"):
            return False

        return True

    def publish(self, event):
        """Publishes the given event to the controller topic.

        Raises UsageError when invoked without an earlier connect().

        Args:
            event (zeekclient.event.Event): the event to publish.
        """
        if self.controller_broker_id is None:
            raise UsageError("cannot publish without established peering")

        msg = DataMessage(self.controller_topic, event.to_brokertype())
        self.wsock.send(msg.serialize())

    def receive(self, timeout_secs=None, filter_pred=None):
        """Receive an event from the controller's event subscriber.

        Raises UsageError when invoked without an earlier connect().

        Args:
            timeout_secs (int): number of seconds before we time out.
                Has sematics of the poll.poll() timeout argument, i.e.
                None and negative values mean no timeout. The default
                is client.request_timeout_secs.

            filter_pred: a predicate function for filtering out unacceptable
                events. The function takes a received event as only input,
                returning True if the event is acceptable for returning to the
                `receive()` caller, and False otherwise. When not provided,
                any received event is acceptable. When the predicate returns
                false, the wait for a suitable event continues, subject to the
                same overall timeout.

        Returns:
            A tuple of (1) an instance of one of the Event classes defined for
            the client, or None if timeout_secs passed before anything arrived,
            and (2) a string indicating any occurring errors. The string is
            empty when no error occurs.
        """
        if self.controller_broker_id is None:
            raise UsageError("cannot receive without established peering")

        timeout = timeout_secs or CONFIG.getint("client", "request_timeout_secs")
        old_timeout = self.wsock.gettimeout()

        try:
            self.wsock.settimeout(timeout)

            remote = f"{self.controller_host}:{self.controller_port}"

            while True:
                # Reading the event proceeds in three steps:
                # (1) read data from the websocket
                # (2) ensure it's a data message
                # (3) try to extract data message payload as event
                try:
                    msg = DataMessage.unserialize(self.wsock.recv())
                except TypeError as err:
                    return (
                        None,
                        f"protocol data error with controller {remote}: {err}",
                    )
                except websocket.WebSocketTimeoutException:
                    return (
                        None,
                        f"websocket connection to {remote} timed out",
                    )
                except Exception as err:
                    LOG.exception("unexpected error")
                    return (
                        None,
                        f"unexpected error with controller {remote}: {err}",
                    )
                try:
                    # Events are a specially laid-out vector of vectors:
                    # https://docs.zeek.org/projects/broker/en/current/web-socket.html#encoding-of-zeek-events
                    evt = ZeekEvent.from_vector(msg.data)

                    # Turn Broker-level event data into a zeekclient.event.Event:
                    res = Registry.make_event(evt.name, *evt.args)
                    if res is not None and (filter_pred is None or filter_pred(res)):
                        return res, ""
                except TypeError:
                    return None, (
                        f"protocol data error with controller {remote}: "
                        f"invalid event data, {repr(msg.data)}"
                    )

                # This wasn't the event type we wanted, try again.
        finally:
            self.wsock.settimeout(old_timeout)

    def transact(self, request_type, response_type, *request_args, reqid=None):
        """Pairs publishing a request event with receiving its response event.

        This is a wrapper around :meth:`.Controller.publish()` with subsequent
        :meth:`.Controller.receive()`, with automatic provision of a request ID
        in the request event, and validation of a matching request ID in the
        response. Mismatching response events are ignored, and lack of a
        suitable event in the timeout period leads to an empty result with
        according error message, just like :meth:`.Controller.receive()`.

        The function works only with request and response event types that take
        a "reqid" string as first argument. The function verifies this lightly,
        just by looking at the name of the first argument. See
        `zeekclient.events` for suitable event types.

        Raises UsageError when invoked without an earlier connect().

        Args:
            request_type (zeekclient.event.Event class): the request event type.

            response_type (zeekclient.event.Event class): the response event type.

            request_args: any event arguments in addition to the initial "reqid" string.

            reqid (str): the request ID to use in the request event, and expect
                in the response event. When omitted, the function produces its
                own ID.

        Returns:
            The same as Controller.receive(): tuple of an event instance
            and a string indicating any error.
        """
        # Verify that the first arguments of the event types are actually a
        # request ID -- we just look at the name:
        if request_type.ARG_NAMES[0] != "reqid":
            return (
                None,
                f"type error: event type {request_type.__name__} does not have request ID",
            )
        if response_type.ARG_NAMES[0] != "reqid":
            return (
                None,
                f"type error: event type {response_type.__name__} does not have request ID",
            )

        if reqid is None:
            reqid = make_uuid()

        evt = request_type(reqid, *request_args)
        self.publish(evt)

        def is_response(evt):
            try:
                return isinstance(evt, response_type) and evt.reqid.to_py() == reqid
            except AttributeError:
                return False

        return self.receive(filter_pred=is_response)
