"""A light shim for zeekclient's use of the websocket-client package.

For details, see https://github.com/websocket-client/websocket-client.
"""

import ssl
import zeekclient

class WebSocketException(Exception):
    pass

class WebSocketTimeoutException(WebSocketException):
    pass

class UnknownException(Exception):
    pass


class WebSocket():
    def __init__(self, *args, **kwargs):
        self.timeout = None

        # The URL provided to connect(). Doesn't look like there's a quick way
        # to retrieve that from real instances.
        self.mock_url = None

        self.mock_connect_timeout = False
        self.mock_connect_websocket_exception = False
        self.mock_connect_sslerror = False
        self.mock_connect_oserror = False
        self.mock_connect_unknown_exception = False

        self.mock_recv_timeout = False
        self.mock_recv_websocket_exception = False
        self.mock_recv_oserror = False
        self.mock_recv_unknown_exception = False

        self.mock_broker_id = 'broker-id-aaa'

        # During normal operation the server responds with a
        # HandshakeAckMessage, so put that in the queue:
        self.mock_recv_queue = [zeekclient.HandshakeAckMessage(
            self.mock_broker_id, 1.0).serialize()]

        # Messages sent via the socket
        self.mock_send_queue = []

    def connect(self, url, **options):
        if self.mock_connect_timeout:
            raise WebSocketTimeoutException('connection timed out')
        if self.mock_connect_websocket_exception:
            raise WebSocketException('uh-oh')
        if self.mock_connect_sslerror:
            raise ssl.SSLError('dummy library version', 'uh-oh')
        if self.mock_connect_oserror:
            raise OSError('uh-oh')
        if self.mock_connect_unknown_exception:
            raise UnknownException('surprise')

        self.mock_url = url

    def send(self, payload):
        self.mock_send_queue.append(payload)

    def recv(self):
        if self.mock_recv_timeout:
            raise WebSocketTimeoutException('connection timed out')
        if self.mock_recv_websocket_exception:
            raise WebSocketException('uh-oh')
        if self.mock_recv_oserror:
            raise OSError('uh-oh')
        if self.mock_recv_unknown_exception:
            raise UnknownException('surprise')

        assert self.mock_recv_queue, 'socket mock ran out of data'
        return self.mock_recv_queue.pop(0)

    def gettimeout(self):
        return self.timeout

    def settimeout(self, timeout):
        self.timeout = timeout
