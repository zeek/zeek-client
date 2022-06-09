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
        self.read_dict({
            'client': {
                # The default timeout for request state is 15 seconds on the
                # Zeek side, so by making it larger here we ensure that timeout
                # events can fire & propagate in Zeek before we give up here.
                'request_timeout_secs': 20,

                # How long Broker's endpoint.peer() should wait until it retries
                # a peering. Its default is 10 seconds; we dial that down
                # because we retry anyway, per the next setting. 0 disables.
                'connect_peer_retry_secs': 1,

                # How often to attempt peerings within Controller.connect():
                'connect_attempts': 4,

                # Delay between our connection attempts.
                'connect_retry_delay_secs': 0.25,

                # The way zeek-client reports informational messages on stderr
                'rich_logging_format': False,

                # Whether we pretty-print JSON output by default.
                'pretty_json': True,
            },
            'controller': {
                # Default host name/address where we contact the controller.
                'host': '127.0.0.1',

                # Default port of the controller.
                'port': 2150,
            },
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
