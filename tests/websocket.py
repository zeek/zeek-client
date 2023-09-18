"""A light shim for zeekclient's use of the websocket-client package.

For details, see https://github.com/websocket-client/websocket-client.
"""

import zeekclient


class WebSocketException(Exception):
    pass


class WebSocketTimeoutException(WebSocketException):
    pass


class UnknownException(Exception):
    pass


class WebSocket:
    def __init__(self, *_args, **_kwargs):
        self.timeout = None

        # The URL provided to connect(). Doesn't look like there's a quick way
        # to retrieve that from real instances.
        self.mock_url = None

        # Exception instances in case we want to trigger problems during I/O.
        # These correspond to the exceptions handled in Controller.connect()'s
        # wsock_operation() inner function.
        self.mock_connect_exc = None
        self.mock_recv_exc = None

        self.mock_broker_id = "broker-id-aaa"

        # During normal operation the server responds with a
        # HandshakeAckMessage, so put that in the queue:
        self.mock_recv_queue = [
            zeekclient.brokertypes.HandshakeAckMessage(
                self.mock_broker_id, 1.0
            ).serialize()
        ]

        # Messages sent via the socket
        self.mock_send_queue = []

    def connect(self, url, **_options):
        if self.mock_connect_exc is not None:
            raise self.mock_connect_exc

        self.mock_url = url

    def send(self, payload):
        self.mock_send_queue.append(payload)

    def recv(self):
        if self.mock_recv_exc is not None:
            raise self.mock_recv_exc

        assert self.mock_recv_queue, "socket mock ran out of data"
        return self.mock_recv_queue.pop(0)

    def gettimeout(self):
        return self.timeout

    def settimeout(self, timeout):
        self.timeout = timeout
