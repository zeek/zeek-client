"""Types corresponding to the members of policy/framework/management/types.zeek."""
import configparser
import enum
import ipaddress
import shlex

import broker

from .utils import make_uuid
from .logs import LOG


class ConfigParserMixin():
    """A mixin that adds a method to create and represent the object via
    ConfigParser instances.
    """
    @classmethod
    def from_config_parser(cls, cfp, section=None): # pylint: disable=unused-argument
        """Instantiates an object of this class based on the given
        ConfigParser, and optional section name in it, as applicable.

        Raises ValueError if the provided configuration is invalid for the class
        to instantiate.
        """
        return None

    def to_config_parser(self, cfp=None): # pylint: disable=unused-argument
        """Returns this object in a ConfigParser instance. When the optional cfp
        argument is not None, the caller requests the implementation to add to
        the given parser, not create a new one.
        """
        return None

    @staticmethod
    def _get(cfp, typ, section, *keys):
        """Typed config key/val retrieval, with support for key name aliases."""
        for key in keys:
            val = cfp.get(section, key, fallback=None)
            if val is not None:
                try:
                    return typ(val)
                except ValueError as err:
                    raise ValueError('cannot convert "{}.{}" value "{}" to {}'
                                     .format(section, key, val, typ.__name__)) from err
        return None


class BrokerType:
    """Base class for types we can instantiate from or render to the
    Python-level Broker data model.

    See the Python type table and general Broker data model below for details:
    https://docs.zeek.org/projects/broker/en/current/python.html#data-model
    https://docs.zeek.org/projects/broker/en/current/data.html
    """
    def to_broker(self):
        """Returns a Broker-compatible rendition of this instance."""
        return None

    def to_json_data(self):
        """Returns JSON-suitable datastructure representing the object."""
        return self.__dict__

    @classmethod
    def from_broker(cls, broker_data): # pylint: disable=unused-argument
        """Returns an instance of the type given Broker data. Raises TypeError when the
        given data doesn't match the type's expectations."""
        return None


class BrokerEnumType(BrokerType, enum.Enum):
    """A specialization of Broker-based enums to bridge Broker/Python.

    This distinguishes the "flat" Python enums ("FOO") from the fully qualified
    way they're rendered via Zeek ("Some::Module::FOO"). To enable a Python enum
    to present the full qualification when sending into Broker, derivations
    reimplement the module_scope() class method.
    """
    def to_broker(self):
        scope = self.module_scope()
        scope = scope + '::' if scope else ''
        return broker.Enum(scope + self.name)

    def to_json_data(self):
        # A similar concern as above applies here, but the exact enum type will
        # often be clear from context and so the un-scoped name alone may
        # suffice.
        return self.name

    def qualified_name(self):
        scope = self.module_scope()
        scope = scope + '::' if scope else ''
        return scope + self.name

    @classmethod
    def lookup(cls, name):
        """Robust name-based lookup of an enum value.

        This removes any Zeek-land or Python-land qualifications, and
        automatically upper-cases the looked-up name.

        Raises KeyError if the requested enum value isn't defined.
        """
        name = name.split('::')[-1]
        name = name.split('.')[-1]
        return cls[name.upper()]

    @classmethod
    def module_scope(cls):
        # Reimplement this in derived classes to convey the Zeek-level enum
        # scope. For example, for a Foo.BAR (or Foo::BAR, in Zeek) enum value,
        # this should return the string "Foo".
        return ''

    @classmethod
    def from_broker(cls, broker_data):
        # The argument is a broker.Enum with a name property like Foo::VALUE.
        try:
            return cls.lookup(broker_data.name)
        except KeyError as err:
            raise TypeError('unexpected enum value for {}: {}'.format(
                cls.__name__, broker_data)) from err


class ClusterRole(BrokerEnumType):
    """Equivalent of Supervisor::ClusterRole enum in Zeek"""
    NONE = 0
    LOGGER = 1
    MANAGER = 2
    PROXY = 3
    WORKER = 4

    @classmethod
    def module_scope(cls):
        return 'Supervisor'


class ManagementRole(BrokerEnumType):
    """Equivalent of Management::Role enum in Zeek"""
    NONE = 0
    AGENT = 1
    CONTROLLER = 2
    NODE = 3

    @classmethod
    def module_scope(cls):
        return 'Management'


class State(BrokerEnumType):
    """Equivalent of Management::State enum in Zeek"""
    PENDING = 0
    RUNNING = 1
    STOPPED = 2
    FAILED = 3
    CRASHED = 4
    UNKNOWN = 5

    @classmethod
    def module_scope(cls):
        return 'Management'


class Option(BrokerType):
    """Equivalent of Management::Option."""
    def __init__(self, name, value):
        self.name = name
        self.value = value

    def to_broker(self):
        return (self.name, self.value)

    @classmethod
    def from_broker(cls, broker_data):
        try:
            return Option(*broker_data)
        except ValueError as err:
            raise TypeError('unexpected Broker data for Option object ({})'.format(
                broker_data)) from err


class Instance(BrokerType):
    """Equivalent of Management::Instance."""
    def __init__(self, name, addr=None, port=None):
        self.name = name
        # This is a workaround until we've resolved addresses in instances
        self.host = addr or '0.0.0.0' # string or ipaddress type ... TBD
        self.port = port # None or integer value; we always mean TCP

    def __lt__(self, other):
        return self.name < other.name

    @classmethod
    def from_broker(cls, broker_data):
        try:
            name, addr, port = broker_data
            return Instance(name, addr, None if port is None else port.number())
        except ValueError as err:
            raise TypeError('unexpected Broker data for Instance object ({})'.format(
                broker_data)) from err

    def to_broker(self):
        port = None
        if self.port:
            port = broker.Port(int(self.port), broker.Port.TCP)
        return (self.name, ipaddress.ip_address(self.host), port)

    def to_json_data(self):
        if self.port is not None:
            return self.__dict__

        # Here too, work around 0.0.0.0 until resolved
        if str(self.host) != '0.0.0.0':
            return { 'name': self.name, 'host': self.host }

        return { 'name': self.name }


class Node(BrokerType, ConfigParserMixin):
    """Equivalent of Management::Node."""

    class HashableDict(dict):
        """Ad-hoc dict adaptation to work around the fact that we cannot readily put a
        dictionary into a set. We make a promise not to modify such dictionaries
        after hashing is needed."""
        def __hash__(self):
            return hash(frozenset(self))

    def __init__(self, name, instance, role, state=State.RUNNING, port=None,
                 scripts=None, options=None, interface=None, cpu_affinity=None,
                 env=None):
        self.name = name
        self.instance = instance
        self.role = role
        self.state = state
        self.port = port
        self.scripts = scripts
        self.options = options
        self.interface = interface
        self.cpu_affinity = cpu_affinity
        self.env = env or {}

    def __lt__(self, other):
        return self.name < other.name

    def to_broker(self):
        # Brokerization of the self.env dict poses a problem: Broker uses Python
        # sets to represent Broker sets, but Python sets cannot hash members
        # that have/are dicts. We work around this with a hashable dictionary
        # that we create only here, so won't modify after hashing.
        hdenv = Node.HashableDict(self.env.items())

        port = None
        if self.port is not None:
            port = broker.Port(self.port, broker.Port.TCP)

        return (self.name, self.instance,
                self.role.to_broker(),
                self.state.to_broker(),
                port,
                self.scripts,
                self.options,
                self.interface,
                self.cpu_affinity,
                hdenv)

    def to_json_data(self):
        return {
            'name': self.name,
            'instance': self.instance,
            'role': self.role.to_json_data(),

            # We currently omit the state field since it has no effect on
            # cluster node operation.
            # 'state': self.state.to_json_data(),

            'port': self.port,
            'scripts': self.scripts,
            'options': self.options,
            'interface': self.interface,
            'cpu_affinity': self.cpu_affinity,
            'env': self.env,
        }

    @classmethod
    def from_broker(cls, broker_data):
        try:
            options = None
            if broker_data[6] is not None:
                options = [Option.from_broker(opt_data) for opt_data in broker_data[6]]

            port = None
            if broker_data[4] is not None:
                port = broker_data[4].number()

            return Node(
                broker_data[0], # name
                broker_data[1], # instance
                ClusterRole.from_broker(broker_data[2]),
                State.from_broker(broker_data[3]),
                port,
                broker_data[5], # scripts
                options,
                broker_data[7], # interface
                broker_data[8], # cpu_affinity
                broker_data[9], # env
            )
        except ValueError as err:
            raise TypeError('unexpected Broker data for Node object ({})'.format(
                broker_data)) from err

    @classmethod
    def from_config_parser(cls, cfp, section=None):
        def get(typ, *keys):
            return cls._get(cfp, typ, section, *keys)

        name = section
        instance = get(str, 'instance')
        role = get(str, 'role', 'type')

        # We currently ignore the node state, if provided. The Node class
        # defaults to 'RUNNING'.
        state = State.RUNNING
        if get(str, 'state'):
            LOG.warning('ignoring node "%s" state "%s" in configuration',
                        name, get(str, 'state'))

        port = get(int, 'port')
        scripts = None

        # The Node record type on the Zeek side features a set[Options] that we
        # don't use (yet).

        interface = get(str, 'interface')
        cpu_affinity = get(int, 'cpu_affinity')
        env = None

        # Validate the specified values
        if not instance:
            raise ValueError('node "{}" requires an instance'.format(name))

        if not role:
            raise ValueError('node "{}" requires a role'.format(name))

        try:
            role = ClusterRole.lookup(role)
        except (AttributeError, KeyError) as err:
            raise ValueError('node "{}" role "{}" is invalid'.format(name, role)) from err

        # Optional values follow:

        # All cluster node types except workers need a port
        if port is None and role not in [ClusterRole.NONE, ClusterRole.WORKER]:
            raise ValueError('node "{}" requires a port'.format(name))

        if port is not None and (port < 1 or port > 65535):
            raise ValueError('node "{}" port {} outside valid range'.format(name, port))

        try:
            # We support multiple scripts as a simple space-separated sequence
            # of filenames, with possible quotation marks for strings with
            # spaces. The shlex module provides a convenient way to parse these.
            val = get(str, 'scripts')
            if val:
                scripts = sorted(shlex.split(val))
        except (AttributeError, KeyError) as err:
            raise ValueError('node "{}" scripts value "{}" is invalid'.format(
                name, val)) from err

        try:
            # An environment variable dictionary is represented as a single
            # config value: a space-separated sequence of <var>=<val> strings,
            # possibly with quotation marks around the val. shlex helps here
            # too: shlex.split('foo=bar=baz blum="foo bar baz"') yields
            # ['foo=bar=baz', 'blum=foo bar baz']
            val = get(str, 'env')
            if val:
                env = {}
                for item in shlex.split(val):
                    key, kval = item.split('=', 1)
                    env[key] = kval
        except (AttributeError, KeyError, ValueError) as err:
            raise ValueError('node "{}" env value "{}" is invalid'.format(
                name, val)) from err

        return Node(name=name, instance=instance, role=role, state=state,
                    port=port, scripts=scripts, interface=interface,
                    cpu_affinity=cpu_affinity, env=env)

    def to_config_parser(self, cfp=None):
        if cfp is None:
            cfp = configparser.ConfigParser(allow_no_value=True)

        if self.name in cfp.sections():
            cfp.remove_section(self.name)

        cfp.add_section(self.name)

        cfp.set(self.name, 'instance', self.instance)
        cfp.set(self.name, 'role', self.role.name)

        # Skip state for the moment, it has no operational effect
        # if self.state is not None:
        #    cfp.set(self.name, 'state', self.state.name)

        if self.port is not None:
            cfp.set(self.name, 'port', str(self.port))

        if self.scripts:
            # See if any of the script paths contain spaces, and use quotation
            # marks if so. This does not escape quotation marks or deal with
            # other "difficult" characters.
            scripts = []

            for script in sorted(self.scripts):
                if len(script.split()) > 1:
                    script = '"' + script + '"'
                scripts.append(script)

            cfp.set(self.name, 'scripts', ' '.join(scripts))

        if self.interface is not None:
            cfp.set(self.name, 'interface', self.interface)

        if self.cpu_affinity is not None:
            cfp.set(self.name, 'cpu_affinity', str(self.cpu_affinity))

        if self.env:
            # If the value has whitespace, use key="val". As with scripts above,
            # this does not deal with more complicated escaping/characters.
            env = []

            for key in sorted(self.env.keys()):
                val = self.env[key]
                if len(val).split() > 1:
                    val = '"' + val + '"'

                env.append('{}={}'.format(key, val))

            cfp.set(self.name, 'env', ' '.join(env))

        return cfp


class Configuration(BrokerType, ConfigParserMixin):
    """Equivalent of Management::Configuration."""
    def __init__(self):
        self.id = make_uuid()
        self.instances = []
        self.nodes = []

    @classmethod
    def from_broker(cls, broker_data):
        res = Configuration()
        res.id = broker_data[0]
        for inst_data in broker_data[1]:
            res.instances.append(Instance.from_broker(inst_data))
        for node_data in broker_data[2]:
            res.nodes.append(Node.from_broker(node_data))
        return res

    def to_broker(self):
        """Marshal the configuration to a Broker-compatible layout.

        Broker's data format uses tuples for records, so we go through the
        defined instances and nodes to convert, when they're not None.
        """
        instances = {inst.to_broker() for inst in self.instances}
        nodes = {node.to_broker() for node in self.nodes}

        return (self.id, instances, nodes)

    def to_json_data(self):
        return {
            "id": self.id,
            "instances": [inst.to_json_data() for inst in sorted(self.instances)],
            "nodes": [node.to_json_data() for node in sorted(self.nodes)],
        }

    @classmethod
    def from_config_parser(cls, cfp, _section=None):
        config = Configuration()

        for section in cfp.sections():
            if section == 'instances':
                # The [instances] section is special: each key in it is the name of
                # an instance, each val is the host:port pair where its agent is
                # listening. The val may be absent when it's an instance that
                # connects to the controller.
                for key, val in cfp.items('instances'):
                    if not val:
                        config.instances.append(Instance(key))
                    else:
                        hostport = val
                        parts = hostport.split(':', 1)
                        if len(parts) != 2:
                            LOG.warning('invalid instance "%s" spec "%s", skipping', key, val)
                            continue
                        config.instances.append(Instance(key, parts[0].strip(), parts[1].strip()))
                continue

            # All keys for sections other than "instances" need to have a value.
            for key, val in cfp.items(section):
                if val is None:
                    LOG.error('config item %s/%s needs a value', section, key)
                    return None

            # The other sections are cluster nodes. Each section name corresponds to
            # a node name, with the keys being one of "type", "instance", etc.
            if section in [node.name for node in config.nodes]:
                LOG.warning('node "%s" defined more than once, skipping repeats"', section)
                continue

            try:
                config.nodes.append(Node.from_config_parser(cfp, section))
            except ValueError as err:
                LOG.error('invalid node "%s" configuration: %s', section, err)
                return None

        return config

    def to_config_parser(self, cfp=None):
        if cfp is None:
            cfp = configparser.ConfigParser(allow_no_value=True)

        if 'instances' in cfp.sections():
            cfp.remove_section('instances')

        if self.instances:
            cfp.add_section('instances')
            for inst in sorted(self.instances):
                if inst.port is not None:
                    # An instance the controller connects to
                    cfp.set('instances', inst.name, '{}:{}'.format(inst.host, inst.port))
                else:
                    # An instance connecting to the controller
                    cfp.set('instances', inst.name)

        for node in sorted(self.nodes):
            node.to_config_parser(cfp)

        return cfp


class NodeStatus(BrokerType):
    """Equivalent of Management::NodeState."""
    def __init__(self, node, state, mgmt_role, cluster_role, pid=None, port=None):
        self.node = node # A string containing the name of the node
        self.state = state # A State enum value
        self.mgmt_role = mgmt_role # A ManagementRole enum value
        self.cluster_role = cluster_role # A ClusterRole enum value
        self.pid = pid # A numeric process ID
        self.port = port # A numeric (TCP) port

    def __lt__(self, other):
        return self.node < other.node

    @classmethod
    def from_broker(cls, broker_data):
        # When a listening port is available, convert Broker's native port type
        # to a plain integer. We're always dealing with TCP ports here.
        port = broker_data[5].number() if broker_data[5] is not None else None

        return NodeStatus(
            broker_data[0],
            State.from_broker(broker_data[1]),
            ManagementRole.from_broker(broker_data[2]),
            ClusterRole.from_broker(broker_data[3]),
            broker_data[4],
            port)


class Result(BrokerType):
    """Equivalent of Management::Result."""
    def __init__(self, reqid, instance, success=True, data=None, error=None, node=None):
        self.reqid = reqid
        self.instance = instance
        self.success = success
        self.data = data
        self.error = error
        self.node = node

    def __lt__(self, other):
        """Support sorting. Sort first by instance name the result comes from, second by
        the node name if present.
        """
        if self.instance < other.instance:
            return True
        if self.instance > other.instance:
            return False

        # Be more specific if we have a node name -- we can use it to sort when
        # two results come from the same instance.
        if self.node is not None and other.node is not None:
            return self.node < other.node

        return False

    @classmethod
    def from_broker(cls, broker_data):
        return Result(*broker_data)


class NodeOutputs(BrokerType):
    """Equivalent of Management::NodeOutputs."""
    def __init__(self, stdout, stderr):
        self.stdout = stdout
        self.stderr = stderr

    @classmethod
    def from_broker(cls, broker_data):
        return NodeOutputs(*broker_data)
