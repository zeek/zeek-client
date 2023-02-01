"""This package defines a Python interface for interacting with a Zeek cluster
controller. It provides a Controller class for sending and retrieving events, a
Zeek event abstraction on top of Broker, and various types that mirror those
defined in Zeek's policy/management/frameworks/management/types.zeek, needed
for request/response events.
"""
import sys

from . import brokertypes
from . import cli
from . import config
from . import consts
from . import controller
from . import events
from . import logs
from . import ssl
from . import types
from . import utils

from .config import CONFIG

from .consts import (
    CONTROLLER_TOPIC,
    CONFIG_FILE,
)

from .logs import LOG

__version__ = "1.2.0"
__all__ = ['brokertypes', 'cli', 'config', 'consts', 'controller', 'events',
           'logs', 'ssl', 'types', 'utils']
