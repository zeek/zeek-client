import os

# Default address for connecting to the Zeek cluster controller
CONTROLLER_HOST = '127.0.0.1'

# The controller's default port
CONTROLLER_PORT = '2150'

# Controller host and port, combined
CONTROLLER = CONTROLLER_HOST + ':' + CONTROLLER_PORT

# The Broker topic prefix for communicating with the controller
CONTROLLER_TOPIC = 'zeek/management/controller'

# The default location zeek-client considers for a config file
CONFIG_FILE = os.getenv('ZEEK_CLIENT_CONFIG_FILE') or '@ZEEK_CLIENT_CONFIG_FILE@'
