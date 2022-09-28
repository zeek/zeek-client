"""Python-level representations of the records in policy/framework/management/types.zeek."""
import configparser
import enum
import shlex
import socket

from . import brokertypes as bt
from .utils import make_uuid
from .logs import LOG


class ConfigParserMixin():
    """Methods to create and render the object via ConfigParser instances."""
    @classmethod
    def from_config_parser(cls, cfp, section=None): # pylint: disable=unused-argument
        """Instantiates an object of this class based on the given
        ConfigParser, and optional section name in it, as applicable.

        Raises ValueError if the provided configuration is invalid for the class
        to instantiate.
        """
        return None  # pragma: no cover

    def to_config_parser(self, cfp=None): # pylint: disable=unused-argument,no-self-use
        """Returns this object in a ConfigParser instance. When the optional cfp
        argument is not None, the caller requests the implementation to add to
        the given parser, not create a new one.
        """
        return None  # pragma: no cover

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


class SerializableZeekType:
    """An interface that supports serializing to and from Broker's data model.

    Objects of any class implementing this interface can be rendered to the
    Python-level Broker data model in the brokertypes module, and instantiated
    from it.
    """
    # We are not using abc.abstractmethod and friends here because the metaclass
    # magic they introduces clashes with multiple inheritance from other types,
    # affecting e.g. Enums below.
    def to_brokertype(self):  # pylint: disable=no-self-use
        """Returns a brokertype instance representing this object."""
        return None  # pragma: no cover

    @classmethod
    def from_brokertype(cls, data): # pylint: disable=unused-argument
        """Returns an instance of this class for the given brokertype data.

        data: a brokertype instance

        Raises TypeError when the given data doesn't match the expected type.
        """
        return None  # pragma: no cover


class JsonableZeekType:
    """An interface for objects that can render themselves to JSON.

    This is not to be confused with the Broker-internal JSON representation for
    WebSockets. Instead, it refers to the JSON-formatted outputs zeek-client
    reports to the user.
    """
    def to_json_data(self):
        """Returns JSON-suitable datastructure representing the object."""
        return self.__dict__  # pragma: no cover


class ZeekType(SerializableZeekType, JsonableZeekType):
    """A does-it-all Zeek type."""


class Enum(ZeekType, enum.Enum):
    """A base class for Zeek's enums, with Python's enum features.

    This distinguishes the "flat" Python enums ("FOO") from the fully qualified
    way they're rendered via Zeek ("Some::Module::FOO"). To enable a Python enum
    to present the full qualification when sending into Broker, derivations
    reimplement the module_scope() class method to prefix with a scope string.
    """
    def __lt__(self, other):
        if type(self) != type(other):
            return NotImplemented
        return self.qualified_name() < other.qualified_name()

    def __eq__(self, other):
        return (type(self) == type(other) and
                self.qualified_name() == other.qualified_name())

    def __hash__(self):
        return hash((self.qualified_name(), self.value))

    def to_brokertype(self):
        scope = self.module_scope()
        scope = scope + '::' if scope else ''
        return bt.Enum(scope + self.name)

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
    def module_scope(cls):  # pragma: no cover
        # Reimplement this in derived classes to convey the Zeek-level enum
        # scope. For example, for a Foo.BAR (or Foo::BAR, in Zeek) enum value,
        # this should return the string "Foo".
        assert False, 'reimplement module_scope() in your Enum derivative'
        return ''

    @classmethod
    def from_brokertype(cls, data):
        # The argument should be a brokertype.Enum a scoped value such as
        # "Foo::VALUE".
        try:
            module, name = data.to_py().split('::', 1)
            if module != cls.module_scope():
                raise ValueError('module scope mismatch for {}: {} != {}.'
                                 .format(cls.__name__, module, cls.module_scope()))
            return cls.lookup(data.to_py())
        except (ValueError, KeyError) as err:
            raise TypeError('unexpected enum value for {}: {}'.format(
                cls.__name__, repr(data))) from err


class ClusterRole(Enum):
    """Equivalent of Supervisor::ClusterRole enum in Zeek"""
    NONE = 0
    LOGGER = 1
    MANAGER = 2
    PROXY = 3
    WORKER = 4

    @classmethod
    def module_scope(cls):
        return 'Supervisor'


class ManagementRole(Enum):
    """Equivalent of Management::Role enum in Zeek"""
    NONE = 0
    AGENT = 1
    CONTROLLER = 2
    NODE = 3

    @classmethod
    def module_scope(cls):
        return 'Management'


class State(Enum):
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


class Option(ZeekType):
    """Equivalent of Management::Option."""
    def __init__(self, name, value):
        self.name = name
        self.value = value

    def __eq__(self, other):
        return (type(self) == type(other) and
                self.name == other.name and
                self.value == other.value)

    def __hash__(self):
        return hash((self.name, self.value))

    def to_brokertype(self):
        return bt.Vector([
            bt.String(self.name),
            bt.String(self.value)
        ])

    @classmethod
    def from_brokertype(cls, data):
        return Option(*data.to_py())


class Instance(ZeekType):
    """Equivalent of Management::Instance."""
    def __init__(self, name, addr=None, port=None):
        self.name = name
        # This is a workaround until we've resolved addresses in instances
        self.host = '0.0.0.0' # XXX needs proper optionality
        if addr is not None:
            self.host = str(addr)
        self.port = port # None or integer value; we always mean TCP

    def __lt__(self, other):
        return self.name < other.name

    def __eq__(self, other):
        return (type(self) == type(other) and
                self.name == other.name and
                self.host == other.host and
                self.port == other.port)

    def __hash__(self):
        return hash((self.name, self.host, self.port))

    def to_brokertype(self):
        return bt.Vector([
            bt.String(self.name),
            bt.Address(self.host),
            bt.from_py(self.port, typ=bt.Port),
        ])

    def to_json_data(self):
        if self.port is not None:
            return self.__dict__

        # Here too, work around 0.0.0.0 until resolved
        if str(self.host) != '0.0.0.0':
            return { 'name': self.name, 'host': self.host }

        return { 'name': self.name }

    @classmethod
    def from_brokertype(cls, data):
        try:
            name, addr, port = data.to_py()
            return Instance(name, addr, None if port is None else port.number)
        except ValueError as err:
            raise TypeError('unexpected Broker data for Instance object ({})'
                            .format(data)) from err


class Node(ZeekType, ConfigParserMixin):
    """Equivalent of Management::Node."""
    def __init__(self, name, instance, role, state=State.RUNNING, port=None,
                 scripts=None, options=None, interface=None, cpu_affinity=None,
                 env=None):
        self.name = name
        self.instance = instance
        self.role = role
        self.state = state
        self.port = port
        self.scripts = scripts
        self.options = options # We use a list, Zeek record uses set
        self.interface = interface
        self.cpu_affinity = cpu_affinity
        self.env = env or {}

    def __lt__(self, other):
        return self.name < other.name

    def __eq__(self, other):
        return (type(self) == type(other) and
                self.name == other.name and
                self.instance == other.instance and
                self.role == other.role and
                self.state == other.state and
                self.port == other.port and
                self.scripts == other.scripts and
                self.options == other.options and
                self.interface == other.interface and
                self.cpu_affinity == other.cpu_affinity and
                self.env == other.env)

    def __hash__(self):
        scripts = tuple(self.scripts) if self.scripts else None
        options = tuple(self.options) if self.options else None
        env = None

        if self.env:
            env=((key, self.env[key]) for key in sorted(self.env))

        return hash((self.name, self.instance, self.role, self.state, self.port,
                     scripts, options, self.interface, self.cpu_affinity, env))

    def to_brokertype(self):
        options = bt.NoneType()
        if self.options:
            options = bt.Set({opt.to_brokertype() for opt in self.options})

        return bt.Vector([
            bt.String(self.name),
            bt.String(self.instance),
            self.role.to_brokertype(),
            self.state.to_brokertype(),
            bt.from_py(self.port, typ=bt.Port),
            bt.from_py(self.scripts),
            options,
            bt.from_py(self.interface),
            bt.from_py(self.cpu_affinity, typ=bt.Count),
            bt.from_py(self.env),
        ])

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
    def from_brokertype(cls, data):
        try:
            options = None
            if isinstance(data[6], bt.Set):
                options = [Option.from_brokertype(opt_data) for opt_data in data[6]]

            port = None
            if isinstance(data[4], bt.Port):
                port = data[4].number

            return Node(
                data[0].to_py(), # name
                data[1].to_py(), # instance
                ClusterRole.from_brokertype(data[2]),
                State.from_brokertype(data[3]),
                port,
                data[5].to_py(), # scripts
                options,
                data[7].to_py(), # interface
                data[8].to_py(), # cpu_affinity
                data[9].to_py(), # env
            )
        except (IndexError, TypeError, ValueError) as err:
            raise TypeError('unexpected Broker data for Node object ({})'.format(
                data)) from err

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
            # When a node features no instance name, default to
            # "agent-<hostname>", assuming the config targets host-local
            # deployment.
            hostname = socket.gethostname() or 'localhost'
            instance = 'agent-' + hostname

        if not role:
            raise ValueError('node requires a role')

        try:
            role = ClusterRole.lookup(role)
        except (AttributeError, KeyError) as err:
            raise ValueError('role "{}" is invalid'.format(role)) from err

        # Optional values follow:

        # Ports are optional and filled in by the controller, assuming
        # Management::Controller::auto_assign_ports is enabled. But when
        # present, we validate:
        if port is not None and (port < 1 or port > 65535):
            raise ValueError('port {} outside valid range'.format(port))

        try:
            # We support multiple scripts as a simple space-separated sequence
            # of filenames, with possible quotation marks for strings with
            # spaces. The shlex module provides a convenient way to parse these.
            val = get(str, 'scripts')
            if val:
                scripts = sorted(shlex.split(val))
        except (AttributeError, KeyError) as err:
            raise ValueError('scripts value "{}" is invalid'.format(val)) from err

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
            raise ValueError('env value "{}" is invalid'.format(val)) from err

        # Warn about unexpected keys:
        cfp_subset = cfp[section] if section else cfp
        keys = set(cfp_subset.keys())
        keys -= set(['instance', 'role', 'scripts', 'port', 'scripts',
                     'interface', 'cpu_affinity', 'env'])

        if len(keys) > 0:
            LOG.warning('ignoring unexpected keys: %s', ', '.join(sorted(keys)))

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
                if len(str(val).split()) > 1:
                    val = '"' + val + '"'

                env.append('{}={}'.format(key, val))

            cfp.set(self.name, 'env', ' '.join(env))

        return cfp


class Configuration(ZeekType, ConfigParserMixin):
    """Equivalent of Management::Configuration."""
    def __init__(self):
        self.id = make_uuid()
        # The following are sets in the Zeek record equivalents. We could
        # reflect this, but handling lists is easier. They do get serialized
        # to/from sets.
        self.instances = []
        self.nodes = []

    def __eq__(self, other):
        return (type(self) == type(other) and
                self.id == other.id and
                self.instances == other.instances and
                self.nodes == other.nodes)

    def __hash__(self):
        return hash((self.id, tuple(self.instances), tuple(self.nodes)))

    def to_brokertype(self):
        return bt.Vector([
            bt.String(self.id),
            bt.Set({inst.to_brokertype() for inst in self.instances}),
            bt.Set({node.to_brokertype() for node in self.nodes}),
        ])

    def to_json_data(self):
        return {
            "id": self.id,
            "instances": [inst.to_json_data() for inst in sorted(self.instances)],
            "nodes": [node.to_json_data() for node in sorted(self.nodes)],
        }

    @classmethod
    def from_brokertype(cls, data):
        res = Configuration()
        res.id = data[0].to_py()
        for inst_data in data[1]:
            res.instances.append(Instance.from_brokertype(inst_data))
        for node_data in data[2]:
            res.nodes.append(Node.from_brokertype(node_data))
        res.instances.sort()
        res.nodes.sort()
        return res

    @classmethod
    def from_config_parser(cls, cfp, _section=None):
        config = Configuration()

        # The nodes in this configuration that do not specify an instance.
        # This is a convenience this client offers, so let's be consistent:
        # if we use this feature, the entire config must be instance-free.
        instance_free_nodes = set()

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
                        if len(parts) != 2 or not parts[0] or not parts[1]:
                            LOG.error('invalid spec for instance "%s": "%s" should be <host>:<port>', key, val)
                            return None
                        config.instances.append(Instance(key, parts[0].strip(), parts[1].strip()))
                continue

            # All keys for sections other than "instances" need to have a value.
            for key, val in cfp.items(section):
                if val is None:
                    LOG.error('config item %s.%s needs a value', section, key)
                    return None

            # The other sections are cluster nodes. Each section name corresponds to
            # a node name, with the keys being one of "type", "instance", etc.
            if section in [node.name for node in config.nodes]:
                LOG.warning('node "%s" defined more than once, skipping repeats"', section)
                continue

            try:
                if 'instance' not in cfp[section]:
                    instance_free_nodes.add(section)
                config.nodes.append(Node.from_config_parser(cfp, section))
            except ValueError as err:
                LOG.error('invalid node "%s" configuration: %s', section, err)
                return None

        # Reject if this config mixes instance-free and instance-claiming nodes,
        # or if it uses an instances section while omitting instances in nodes.
        if len(instance_free_nodes) > 0:
            if len(instance_free_nodes) != len(config.nodes):
                LOG.error('either all or no nodes must state instances')
                return None
            if 'instances' in cfp.sections():
                LOG.error('omit instances section when skipping instances in node definitions')
                return None

        # When the configuration has no "instances" section, then any instance
        # names given in node sections imply corresponding instances whose
        # agents connect to the controller. That is, the instances section is
        # just a redundant listing of the instance names and we can synthesize
        # it:
        if 'instances' not in cfp.sections():
            names = set()
            for node in config.nodes:
                names.add(node.instance)
            config.instances = sorted([Instance(name) for name in names])

        # We don't cross-check the set of instances claimed by the nodes vs the
        # set of instances declared in the config, because the controller
        # already does this.

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


class NodeStatus(SerializableZeekType):
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

    def __eq__(self, other):
        return (type(self) == type(other) and
                self.node == other.node and
                self.state == other.state and
                self.mgmt_role == other.mgmt_role and
                self.cluster_role == other.cluster_role and
                self.pid == other.pid and
                self.port == other.port)

    def __hash__(self):
        return hash((self.node, self.state, self.mgmt_role, self.cluster_role,
                     self.pid, self.port))

    def to_brokertype(self):
        # In normal operation we only ever receive NodeStates, but for testing
        # it helps to be able to serialize.
        pid = bt.NoneType() if self.pid is None else bt.Integer(self.pid)
        port = bt.NoneType() if self.port is None else bt.Port(self.port)

        return bt.Vector([
            bt.String(self.node),
            self.state.to_brokertype(),
            self.mgmt_role.to_brokertype(),
            self.cluster_role.to_brokertype(),
            pid,
            port,
        ])

    @classmethod
    def from_brokertype(cls, data):
        port = data[5].to_py()
        if port is not None:
            port = port.number

        return NodeStatus(
            data[0].to_py(),
            State.from_brokertype(data[1]),
            ManagementRole.from_brokertype(data[2]),
            ClusterRole.from_brokertype(data[3]),
            data[4].to_py(),
            port)


class Result(SerializableZeekType):
    """Equivalent of Management::Result."""
    def __init__(self, reqid, success=True, instance=None, data=None, error=None, node=None):
        self.reqid = reqid
        self.success = success
        self.instance = instance
        self.data = data
        self.error = error
        self.node = node

    def __lt__(self, other):
        """Support sorting. Sort first by instance name the result comes from,
        second by the node name if present.
        """
        if self.instance is None and other.instance is not None:
            return False
        if self.instance is not None and other.instance is None:
            return True
        if self.instance is not None and other.instance is not None:
            if self.instance < other.instance:
                return True
            if self.instance > other.instance:
                return False

        # Be more specific if we have a node name -- we can use it to sort when
        # two results come from the same instance.
        if self.node is not None and other.node is not None:
            return self.node < other.node

        return False

    def __eq__(self, other):
        return (type(self) == type(other) and
                self.reqid == other.reqid and
                self.success == other.success and
                self.instance == other.instance and
                self.data == other.data and
                self.error == other.error and
                self.node == other.node)

    def hash(self):
        return hash((self.reqid, self.success, self.instance, self.data,
                     self.error, self.node))

    def to_brokertype(self):
        # In normal operation we only ever receive Results, but for testing it
        # helps to be able to serialize.
        instance = bt.NoneType() if self.instance is None else bt.String(self.instance)

        data = bt.NoneType()
        if self.data is not None:
            # This is any-typed in Zeek and so a bit special: it is up to the
            # caller what exactly this is, an it is assumed to already be in
            # Brokertype format. We just pass it through.
            data = self.data

        error = bt.NoneType() if self.error is None else bt.String(self.error)
        node = bt.NoneType() if self.node is None else bt.String(self.node)

        return bt.Vector([
            bt.String(self.reqid),
            bt.Boolean(self.success),
            instance,
            data,
            error,
            node,
        ])

    @classmethod
    def from_brokertype(cls, data):
        # The data field gets special treatment since it can be of any
        # type. When it's a brokertype.NoneType (i.e., not present), we turn it
        # into None, since that simplifies its handling. Otherwise we leave it
        # untouched: the correct type to deserialize into will become clear
        # later from surrounding context.
        res_data = data[3]

        if isinstance(res_data, bt.NoneType):
            res_data = None

        return Result(reqid=data[0].to_py(), success=data[1].to_py(),
                      instance=data[2].to_py(), data=res_data,
                      error=data[4].to_py(), node=data[5].to_py())


class NodeOutputs(SerializableZeekType):
    """Equivalent of Management::NodeOutputs."""
    def __init__(self, stdout, stderr):
        self.stdout = stdout
        self.stderr = stderr

    def __eq__(self, other):
        return (type(self) == type(other) and
                self.stdout == other.stdout and
                self.stderr == other.stderr)

    def hash(self):
        return hash((self.stdout, self.stderr))

    def to_brokertype(self):
        # In normal operation we only ever receive NodeOutputs, but for testing
        # it helps to be able to serialize.
        return bt.Vector([
            bt.String(self.stdout),
            bt.String(self.stderr),
        ])

    @classmethod
    def from_brokertype(cls, data):
        return NodeOutputs(*(data.to_py()))
