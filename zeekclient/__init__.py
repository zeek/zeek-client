import sys

try:
    import broker
except ImportError:
    print('error: zeek-client requires the Python Broker bindings.\n'
          'Make sure your Zeek build includes them. To add installed\n'
          'Broker bindings to Python search path manually, add the\n'
          'output of "zeek-config --python_dir" to PYTHONPATH.')
    sys.exit(1)

from .config import *
from .cli import *
from .consts import *
from .controller import *
from .events import *
from .logs import *
from .types import *
from .utils import *

__version__ = "0.3.0-1"
__all__ = ['cli', 'config', 'consts', 'controller', 'events', 'logging', 'types', 'utils']
