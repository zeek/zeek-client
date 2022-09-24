"""This module provides specializes the Python ConfigParser class, pre-defining
a set of config settings for zeek-client and includes ways to override these
from the environment and the command line.
"""
import configparser
import os
import shlex

from .consts import CONFIG_FILE
from .logs import LOG


class Config(configparser.ConfigParser):
    """zeek-client configuration settings.

    A specialized ConfigParser that hardwires defaults for select values.
    Three levels of overrides apply, if provided:

    (1) first, the config file, if available

    (2) the ZEEK_CLIENT_CONFIG_SETTINGS environment variable may contain a
        series of <section.key>=<val> assignments

    (3) Any --set <section.key>=<val> arguments apply final overrides
    """
    def __init__(self):
        super().__init__()
        self.reset()

    def reset(self):
        self.read_dict({
            'client': {
                # The default timeout for request state is 15 seconds on the
                # Zeek side, so by making it larger here we ensure that timeout
                # events can fire & propagate in Zeek before we give up here.
                'request_timeout_secs': 20,

                # Successful peering requires a successful WebSocket connection
                # to the controller and the successful exchange of peering
                # handshake and response. We retry both, counting connection as
                # well as handshake attempts toward this total:
                'peering_attempts': 10,

                # How long the client's Broker's endpoint should wait internally
                # until it retries a peering upon connection or when the
                # connection goes away. Its default is 10 seconds; we dial that
                # down to be more interactive.
                'peering_retry_delay_secs': 1.0,

                # The way zeek-client reports informational messages on stderr
                'rich_logging_format': False,

                # Whether we pretty-print JSON output by default.
                'pretty_json': True,

                # Default output verbosity level:
                #   0   permits errors
                #   1   also warnings
                #   2   also informational messages
                #   3   also debug messages
                #   4+  no additional effect
                'verbosity': 0,
            },
            'controller': {
                # Default host name/address where we contact the controller.
                'host': '127.0.0.1',

                # Default WebSocket port of the controller.
                'port': 2149,
            },
            'ssl': {
                # These settings control the security settings of the connection
                # to the controller. They mirror Broker's approach and naming:
                # by default, SSL is active, but unvalidated. Providing
                # certificate, private key, and possibly CA & passphrase secure
                # the connection properly.  Compare to Zeek's Broker framework.

                # Whether to use SSL at all. Disabling this yields plaintext
                # communication. This mirrors Broker::disable_ssl on the Zeek
                # side.
                'disable': False,

                # Path to a file containing a X.509 certificate in PEM format.
                'certificate': '',

                # Path to a file containing the private key for the certificate,
                # in PEM format.
                'keyfile': '',

                # Path to a file containing concatenated, trusted certificates,
                # in PEM format.
                'cafile': '',

                # Path to an OpenSSL-style directory of trusted certificates.
                'capath': '',

                # A passphrase to decrypt the private key, if required.
                'passphrase': '',
            }
        })

    def update_from_file(self, config_file=CONFIG_FILE):
        self.read(config_file)

    def update_from_env(self):
        for item in shlex.split(os.getenv('ZEEK_CLIENT_CONFIG_SETTINGS') or ''):
            try:
                self.apply(item)
            except ValueError:
                LOG.error('config item "%s" in ZEEK_CLIENT_CONFIG_SETTINGS '
                          'invalid. Please use <section.key>=<val>.', item)

    def update_from_args(self, args):
        for item in args.set:
            try:
                self.apply(item)
            except ValueError:
                LOG.error('config item "%s" invalid. Please use '
                          '<section.key>=<val>.', item)

        # The `--controller` argument is a shortcut for two `--set` arguments that
        # set controller host and port, so update these manually:
        if args.controller:
            host_port = args.controller.split(':', 1)
            if len(host_port) != 2 or not host_port[1]:
                # It's just a hostname
                self.set('controller', 'host', host_port[0])
            elif not host_port[0]:
                # It's just a port (as ":<port>")
                self.set('controller', 'port', host_port[1])
            else:
                self.set('controller', 'host', host_port[0])
                self.set('controller', 'port', host_port[1])

        # --verbose/-v/-vvv etc set a numeric verbosity level:
        if args.verbose:
            self.set('client', 'verbosity', str(args.verbose))

    def apply(self, item):
        """This is equivalent to set(), but works via a single <section.key>=<val> string."""
        try:
            identifier, val = item.split('=', 1)
            section, key = identifier.split('.', 1)
            if not self.has_section(section):
                self.add_section(section)
            self.set(section, key, val)
        except ValueError as err:
            raise ValueError('config item "{}" invalid'.format(item)) from err

    def completer(self, **_kwargs):
        """A completer suitable for argcomplete."""
        ret = []

        for section in self.sections():
            for key, val in self.items(section):
                ret.append(section + '.' + key + '=' + val)

        return sorted(ret)


CONFIG = Config()
