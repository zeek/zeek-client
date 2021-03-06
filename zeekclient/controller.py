"""This module provides Broker-based communication with a Zeek cluster controller."""
import select
import time

import broker

from .config import CONFIG
from .consts import CONTROLLER_TOPIC
from .events import Registry
from .logs import LOG


class Controller:
    """A class representing our Broker connection to the Zeek cluster controller."""
    def __init__(self, controller_host, controller_port,
                 controller_topic=CONTROLLER_TOPIC):
        self.controller_host = controller_host
        self.controller_port = controller_port
        self.controller_topic = controller_topic
        self.ept = broker.Endpoint()
        self.sub = self.ept.make_safe_subscriber(controller_topic)
        self.ssub = self.ept.make_status_subscriber(True)

        self.poll = select.poll()
        self.poll.register(self.sub.fd())
        self.poll.register(self.ssub.fd())

    def connect(self):
        if self.controller_port < 1 or self.controller_port > 65535:
            LOG.error('controller port number {} outside valid range'.format(
                self.controller_port))
            return False

        LOG.info('connecting to controller %s:%s', self.controller_host,
                 self.controller_port)

        self.ept.peer_nosync(self.controller_host, self.controller_port,
                             CONFIG.getfloat('client', 'peer_retry_secs'))

        # Wait for successful peering in the status subscriber, to ensure we can
        # communicate events reliably. We need to time this out since this
        # status may never arrive -- the plain get() in the Broker example is
        # dangerous. The version of get() with a timeout currently throws a
        # Python bindings error, so we resort to our own timeout mechanism. Note
        # that we see other status updates in a successful connection setup: the
        # first status update will usually be endpoint_discovered, followed by
        # peer_added.
        attempts = CONFIG.getint('client', 'peering_status_attempts')

        for i in range(attempts):
            if not self.ssub.available():
                time.sleep(CONFIG.getfloat('client', 'peering_status_retry_delay_secs'))
                continue

            status = self.ssub.get()
            LOG.debug('status update, attempt %s/%s to connect to %s:%s: %s',
                      i, attempts, self.controller_host, self.controller_port,
                      status)

            # The return can be an error or a status, so we need to typecheck
            if isinstance(status, broker.Status) and status.code() == broker.SC.PeerAdded:
                LOG.info('peered with controller %s:%s', self.controller_host,
                         self.controller_port)
                return True

            time.sleep(CONFIG.getfloat('client', 'peering_status_retry_delay_secs'))

        LOG.error('could not peer with controller %s:%s',
                  self.controller_host, self.controller_port)
        return False

    def publish(self, event):
        """Publishes the given event to the controller topic.

        Args:
            event (Event): the event to publish.
        """
        self.ept.publish(self.controller_topic, event)

    def receive(self, timeout_secs=None):
        """Receive an event from the controller's event subscriber.

        Args:
            timeout_secs (int): number of seconds before we time out.
                Has sematics of the poll.poll() timeout argument, i.e.
                None and negative values mean no timeout. The default
                is a 10-second timeout.

        Returns:
            A tuple of (1) an instance of one of the Event classes defined for
            the client, or None if timeout_secs passed before anything arrived,
            and (2) a string indicating any occurring errors. The string is
            empty when no error occurs.
        """
        timeout_msecs = timeout_secs or CONFIG.getint('client', 'request_timeout_secs')
        if timeout_msecs is not None:
            timeout_msecs *= 1000

        # This is quite basic: no event dispatch mechanism, event loop, etc. For
        # now we just poll on the fds of the subscriber and status subscriber so
        # we get notified when something arrives or an error occurs. Might have
        # to handle POLLERR and POLLHUP here too to be more robust.
        while True:
            try:
                resps = self.poll.poll(timeout_msecs)
            except OSError as err:
                return None, 'polling error: {}'.format(err)

            if not resps:
                return None, 'connection timed out'

            for fdesc, event in resps:
                if fdesc == self.sub.fd() and event & select.POLLIN:
                    _, data = self.sub.get()

                    res = Registry.make_event(data)
                    if res is not None:
                        return res, ''

                if fdesc == self.ssub.fd() and event & select.POLLIN:
                    status = self.ssub.get()
                    # Fail on errors, but swallow regular status updates:
                    if not isinstance(status, broker.Status):
                        return None, 'broker error: {}'.format(status)
                    LOG.debug('broker status change: {}'.format(status))
