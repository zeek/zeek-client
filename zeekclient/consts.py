import os

# The Broker topic prefix for communicating with the controller
CONTROLLER_TOPIC = 'zeek/management/controller'

# The default location zeek-client considers for a config file
CONFIG_FILE = os.getenv('ZEEK_CLIENT_CONFIG_FILE') or '@ZEEK_CLIENT_CONFIG_FILE@'
