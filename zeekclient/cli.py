"""This module provides command line parsers and corresponding commands."""
import argparse
import configparser
import ipaddress
import json
import os
import sys
import traceback

from . import brokertypes as bt
from . import controller

from .config import CONFIG

from .consts import CONFIG_FILE

from .events import (
    DeployRequest,
    DeployResponse,
    GetConfigurationRequest,
    GetConfigurationResponse,
    GetIdValueRequest,
    GetIdValueResponse,
    GetInstancesRequest,
    GetInstancesResponse,
    GetNodesRequest,
    GetNodesResponse,
    RestartRequest,
    RestartResponse,
    StageConfigurationRequest,
    StageConfigurationResponse,
    TestTimeoutRequest,
    TestTimeoutResponse
)

from .logs import LOG

from .types import (
    Enum,
    ClusterRole,
    Configuration,
    Instance,
    ManagementRole,
    NodeStatus,
    NodeOutputs,
    Result
)

# For unit-testing, a central place to adjust where reads from stdin come from
# and writes to stdout go to. Fiddling with sys.stdin/sys.stdout directly in the
# tests can be tricky.
STDIN = sys.stdin
STDOUT = sys.stdout

# Broker's basic types aren't JSON-serializable, so patch that up
# in this json.dumps() wrapper for JSON serialization of any object.
# Could go into utils.py, but it easier here to keep free of cyclic
# dependencies.
def json_dumps(obj):
    def default(obj):
        # Check specific Python types:
        if isinstance(obj, ipaddress.IPv4Address):
            return str(obj)
        if isinstance(obj, ipaddress.IPv6Address):
            return str(obj)

        # Specific zeek-client types (types.py):
        if isinstance(obj, Enum):
            return obj.to_json_data()

        # Specific brokertypes:
        if isinstance(obj, bt.Port):
            return str(obj.number)
        if isinstance(obj, bt.Timespan):
            return '{}{}'.format(obj.value, obj.unit.value)
        # Fallback: assume the type's own Python representation is right.
        # json.dumps() will complain when that does not work.
        if isinstance(obj, bt.Type):
            return obj.to_py()

        raise TypeError('cannot serialize {} ({})'.format(type(obj), str(obj)))

    indent = 2 if CONFIG.getboolean('client', 'pretty_json') else None
    return json.dumps(obj, default=default, sort_keys=True, indent=indent)


def create_controller():
    try:
        ctl = controller.Controller()
    except controller.Error as err:
        LOG.error(str(err))
        return None

    if not ctl.connect():
        return None

    return ctl


def create_parser():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='A Zeek management client',
        epilog='environment variables:\n\n'
        '    ZEEK_CLIENT_CONFIG_FILE:      '
        'Same as `--configfile` argument, but lower precedence.\n'
        '    ZEEK_CLIENT_CONFIG_SETTINGS:  '
        'Same as a space-separated series of `--set` arguments, but lower precedence.\n')

    controller = '{}:{}'.format(CONFIG.get('controller', 'host'),
                                CONFIG.get('controller', 'port'))

    parser.add_argument('-c', '--configfile', metavar='FILE', default=CONFIG_FILE,
                        help='Path to zeek-client config file. (Default: {})'.format(CONFIG_FILE))
    parser.add_argument('--controller', metavar='HOST:PORT',
                        help='Address and port of the controller, either of '
                        'which may be omitted (default: {})'.format(controller))
    arg = parser.add_argument('--set', metavar='SECTION.KEY=VAL', action='append', default=[],
                              help='Adjust a configuration setting. Can use repeatedly. '
                              'See show-settings.')

    # This is for argcomplete users and has no effect otherwise.
    arg.completer = CONFIG.completer

    verbosity_group = parser.add_mutually_exclusive_group()
    verbosity_group.add_argument('--quiet', '-q', action='store_true',
                                 help='Suppress informational output to stderr.')
    verbosity_group.add_argument('--verbose', '-v', action='count',
                                 help='Increase informational output to stderr. '
                                 'Repeat for more output (e.g. -vvv).')

    parser.add_argument('--version', action='store_true',
                        help='Show version number and exit.')

    command_parser = parser.add_subparsers(
        title='commands', dest='command',
        help='See `%(prog)s <command> -h` for per-command usage info.')

    sub_parser = command_parser.add_parser(
        'deploy', help='Deploy a staged cluster configuration.')
    sub_parser.set_defaults(run_cmd=cmd_deploy)

    sub_parser = command_parser.add_parser(
        'deploy-config', help='Upload a cluster configuration and deploy it.')
    sub_parser.set_defaults(run_cmd=cmd_deploy_config)
    sub_parser.add_argument('config', metavar='FILE',
                            help='Cluster configuration file, "-" for stdin')

    sub_parser = command_parser.add_parser(
        'get-config', help='Retrieve staged or deployed cluster configuration.')
    sub_parser.set_defaults(run_cmd=cmd_get_config)
    sub_parser.add_argument('--filename', '-f', metavar='FILE', default='-',
                            help='Output file for the configuration, default stdout')
    sub_parser.add_argument('--as-json', action='store_true',
                            help='Report in JSON instead of INI-style config file')
    get_config_group = sub_parser.add_mutually_exclusive_group()
    get_config_group.add_argument('--deployed', action='store_true',
                                  dest='deployed', default=False,
                                  help='Return deployed configuration')
    get_config_group.add_argument('--staged', action='store_false', dest='deployed',
                                  help='Return staged configuration (default)')

    sub_parser = command_parser.add_parser(
        'get-id-value', help='Show the value of a given identifier in Zeek cluster nodes.')
    sub_parser.set_defaults(run_cmd=cmd_get_id_value)
    sub_parser.add_argument('id', metavar='IDENTIFIER',
                            help='Name of the Zeek script identifier to retrieve.')
    sub_parser.add_argument('nodes', metavar='NODES', nargs='*', default=[],
                            help='Name(s) of Zeek cluster nodes to query. '
                            'When omitted, queries all nodes.')

    sub_parser = command_parser.add_parser(
        'get-instances', help='Show instances connected to the controller.')
    sub_parser.set_defaults(run_cmd=cmd_get_instances)

    sub_parser = command_parser.add_parser(
        'get-nodes', help='Show active Zeek nodes at each instance.')
    sub_parser.set_defaults(run_cmd=cmd_get_nodes)

    sub_parser = command_parser.add_parser(
        'monitor', help='For troubleshooting: do nothing, just report events.')
    sub_parser.set_defaults(run_cmd=cmd_monitor)

    sub_parser = command_parser.add_parser(
        'restart', help='Restart cluster nodes.')
    sub_parser.set_defaults(run_cmd=cmd_restart)
    sub_parser.add_argument('nodes', metavar='NODES', nargs='*', default=[],
                            help='Name(s) of Zeek cluster nodes to restart. '
                            'When omitted, restarts all nodes.')

    sub_parser = command_parser.add_parser(
        'stage-config', help='Upload a cluster configuration for later deployment.')
    sub_parser.set_defaults(run_cmd=cmd_stage_config)
    sub_parser.add_argument('config', metavar='FILE',
                            help='Cluster configuration file, "-" for stdin')

    sub_parser = command_parser.add_parser(
        'show-settings', help="Show zeek-client's own configuration.")
    sub_parser.set_defaults(run_cmd=cmd_show_settings)

    sub_parser = command_parser.add_parser(
        'test-timeout', help='Send timeout test event.')
    sub_parser.set_defaults(run_cmd=cmd_test_timeout)
    sub_parser.add_argument('--with-state', action='store_true',
                            help='Make request stateful in the controller.')

    return parser


def cmd_deploy(args, controller=None):
    # The deploy-config command first stages a configuration and then calls this
    # function to deploy. We re-use its controller, passed to us.
    if controller is None:
        controller = create_controller()
    if controller is None:
        return 1

    resp, msg = controller.transact(DeployRequest, DeployResponse)

    if resp is None:
        LOG.error('no response received: %s', msg)
        return 1

    retval = 0
    json_data = {
        'results': {},
        'errors': [],
    }

    for broker_data in resp.results:
        res = Result.from_brokertype(broker_data)

        if not res.success:
            retval = 1

        if not res.success and res.node is None and res.error:
            # If a failure doesn't mention a node, it's either an agent
            # reporting an internal error, or the controller reporting a
            # config validation error.
            json_data['errors'].append(res.error)
            continue

        if res.success and res.node is None and res.instance is None and res.data:
            # It's success from the controller (since the instance field is
            # empty): the data field contains the ID of the deployed config.
            json_data['results']['id'] = res.data
            continue

        # At this point we only expect responses from the agents:
        if res.instance is None:
            LOG.warning('skipping unexpected response %s', res)
            continue

        if res.node is None:
            # This happens when an agent handles deployment successfully, and
            # had no nodes to deploy. We skip this silently.
            continue

        # Everything else is node-specific results from agents.

        if 'nodes' not in json_data['results']:
            json_data['results']['nodes'] = {}

        json_data['results']['nodes'][res.node] = {
            'success': res.success,
            'instance': res.instance,
        }

        # If launching this node failed, we should have a NodeOutputs record as
        # data member in the result record. ("should", because on occasion
        # buffering in the node -> stem -> supervisor pipeline delays the
        # output.)
        if res.data:
            node_outputs = NodeOutputs.from_brokertype(res.data)
            json_data['results']['nodes'][res.node]['stdout'] = node_outputs.stdout
            json_data['results']['nodes'][res.node]['stderr'] = node_outputs.stderr

    print(json_dumps(json_data), file=STDOUT)
    return retval


def cmd_get_config(args):
    controller = create_controller()
    if controller is None:
        return 1

    resp, msg = controller.transact(GetConfigurationRequest,
                                    GetConfigurationResponse,
                                    args.deployed)

    if resp is None:
        LOG.error('no response received: %s', msg)
        return 1

    res = Result.from_brokertype(resp.result)

    if not res.success:
        msg = res.error if res.error else 'no reason given'
        LOG.error(msg)
        return 1

    if not res.data:
        LOG.error('received result did not contain configuration data: %s', resp)
        return 1

    config = Configuration.from_brokertype(res.data)

    with open(args.filename, 'w') if args.filename and args.filename != '-' else STDOUT as hdl:
        if args.as_json:
            hdl.write(json_dumps(config.to_json_data()) + '\n')
        else:
            cfp = config.to_config_parser()
            cfp.write(hdl)

    return 0


def cmd_get_id_value(args):
    controller = create_controller()
    if controller is None:
        return 1

    resp, msg = controller.transact(GetIdValueRequest,
                                    GetIdValueResponse,
                                    args.id, set(args.nodes))

    if resp is None:
        LOG.error('no response received: %s', msg)
        return 1

    json_data = {
        'results': {},
        'errors': [],
    }

    # The Result records have both instance and node filled in, so use both for
    # ordering. While for the JSON serialization we can outsource the ordering
    # task to Python, for our error reporting it's up to us, and we want be
    # reproducible.

    results = [Result.from_brokertype(broker_data) for broker_data in resp.results]

    for res in sorted(results):
        if not res.success:
            json_data['errors'].append({
                'source': res.node,
                'error': res.error,
            })
            continue

        # Upon success, we should always have res.node filled in. But guard anyway.
        if res.node:
            # res.data should be a string containing JSON rendered by Zeek's
            # to_json() BiF. Parse it into a data structure to render
            # seamlessly.
            if not isinstance(res.data, bt.String):
                json_data['errors'].append({
                    'source': res.node,
                    'error': 'invalid result data type {}'.format(repr(res.data))
                })
                continue

            try:
                json_data['results'][res.node] = json.loads(res.data.to_py())
            except json.JSONDecodeError as err:
                json_data['errors'].append({
                    'source': res.node,
                    'error': 'JSON decode error: {}'.format(err),
                })
            continue

        json_data['errors'].append({
            'error': 'result lacking node: {}'.format(res.data),
        })

    print(json_dumps(json_data), file=STDOUT)
    return 0 if len(json_data['errors']) == 0 else 1


def cmd_get_instances(_args):
    controller = create_controller()
    if controller is None:
        return 1

    resp, msg = controller.transact(GetInstancesRequest, GetInstancesResponse)

    if resp is None:
        LOG.error('no response received: %s', msg)
        return 1

    res = Result.from_brokertype(resp.result)

    if not res.success:
        msg = res.error if res.error else 'no reason given'
        LOG.error(msg)
        return 1

    if res.data is None:
        LOG.error('received result did not contain instance data: %s', resp)
        return 1

    json_data = {}

    # res.data is a (possibly empty) vector of Instances. Make the list of
    # instances easier to comprehend than raw Broker data: turn it into Instance
    # objects, then render these JSON-friendly.
    try:
        for inst in sorted([Instance.from_brokertype(inst) for inst in res.data]):
            json_data[inst.name] = inst.to_json_data()
            json_data[inst.name].pop('name')
    except TypeError as err:
        LOG.error('instance data invalid: %s', err)

    print(json_dumps(json_data), file=STDOUT)
    return 0


def cmd_get_nodes(_args):
    controller = create_controller()
    if controller is None:
        return 1

    resp, msg = controller.transact(GetNodesRequest, GetNodesResponse)

    if resp is None:
        LOG.error('no response received: %s', msg)
        return 1

    json_data = {
        'results': {},
        'errors': [],
    }

    results = [Result.from_brokertype(broker_data) for broker_data in resp.results]

    for res in sorted(results):
        if not res.success:
            json_data['errors'].append({
                'source': res.instance,
                'error': res.error,
            })
            continue

        if res.data is None:
            json_data['errors'].append({
                'source': res.instance,
                'error': 'result does not contain node status data',
            })
            continue

        json_data['results'][res.instance] = {}

        # res.data is a NodeStatusVec
        try:
            nstats = [NodeStatus.from_brokertype(nstat_data) for nstat_data in res.data]
            for nstat in sorted(nstats):
                # If either of the two role enums are "NONE", we make them
                # None. That way they stay in the reporting, but are more easily
                # distinguished from "actual" values.
                mgmt_role = nstat.mgmt_role if nstat.mgmt_role != ManagementRole.NONE else None
                cluster_role = nstat.cluster_role if nstat.cluster_role != ClusterRole.NONE else None

                json_data['results'][res.instance][nstat.node] = {
                    'state': nstat.state,
                    'mgmt_role': mgmt_role,
                    'cluster_role': cluster_role,
                }

                if nstat.pid is not None:
                    json_data['results'][res.instance][nstat.node]['pid'] = nstat.pid
                if nstat.port is not None:
                    json_data['results'][res.instance][nstat.node]['port'] = nstat.port
        except TypeError as err:
            LOG.error('NodeStatus data invalid: %s', err)
            LOG.debug(traceback.format_exc())

    print(json_dumps(json_data), file=STDOUT)
    return 0 if len(json_data['errors']) == 0 else 1


def cmd_monitor(_args):
    controller = create_controller()
    if controller is None:
        return 1

    while True:
        resp, msg = controller.receive(timeout_secs=None)

        if resp is None:
            print('no response received: {}'.format(msg))
        else:
            print('received "{}"'.format(resp))

    return 0


def cmd_restart(args):
    controller = create_controller()
    if controller is None:
        return 1

    resp, msg = controller.transact(RestartRequest, RestartResponse,
                                    set(args.nodes))

    if resp is None:
        LOG.error('no response received: %s', msg)
        return 1

    json_data = {
        'results': {},
        'errors': [],
    }

    # The Result records have both instance and node filled in, so use both for
    # ordering. While for the JSON serialization we can outsource the ordering
    # task to Python, for our error reporting it's up to us, and we want be
    # reproducible.

    results = [Result.from_brokertype(broker_data) for broker_data in resp.results]

    for res in sorted(results):
        if not res.success and res.instance is None:
            # The controller generated this one, so add to errors section.
            json_data['errors'].append({
                'source': res.node,
                'error': res.error,
            })
            continue

        # Upon success, we should always have a node filled in. But guard anyway.
        if res.node:
            json_data['results'][res.node] = res.success
            continue

        json_data['errors'].append({
            'error': 'result lacking node: {}'.format(res),
        })

    print(json_dumps(json_data), file=STDOUT)
    return 0 if len(json_data['errors']) == 0 else 1


def cmd_stage_config_impl(args):
    """Internals of cmd_stage_config() to enable chaining with other commands.

    Returns a tuple of exit code, any JSON data to show to the user/caller, and
    the created controller object, if any.
    """
    if not args.config or (args.config != '-' and not os.path.isfile(args.config)):
        LOG.error('please provide a cluster configuration file.')
        return 1, None, None

    # We use a config parser to parse the cluster configuration. For instances,
    # we allow names without value to designate agents that connect to the
    # controller, like this:
    #
    # [instances]
    # foobar
    #
    # All other keys must have a value.
    config = Configuration()
    cfp = configparser.ConfigParser(allow_no_value=True)

    if args.config == '-':
        cfp.read_file(STDIN)
    else:
        cfp.read(args.config)

    config = Configuration.from_config_parser(cfp)

    if config is None:
        LOG.error('configuration has errors, not sending')
        return 1, None, None

    controller = create_controller()
    if controller is None:
        return 1, None, None

    resp, msg = controller.transact(StageConfigurationRequest,
                                    StageConfigurationResponse,
                                    config.to_brokertype())

    if resp is None:
        LOG.error('no response received: %s', msg)
        return 1, None, controller

    retval = 0
    json_data = {
        'results': {},
        'errors': [],
    }

    for broker_data in resp.results:
        res = Result.from_brokertype(broker_data)

        if not res.success:
            retval = 1

            # Failures are config validation problems, trouble while
            # auto-assigning ports, or internal controller errors.
            # They should all come with error messages.
            json_data['errors'].append(res.error if res.error else 'no reason given')
            continue

        if res.data:
            json_data['results']['id'] = res.data

    return retval, json_data, controller


def cmd_stage_config(args):
    ret, json_data, _ = cmd_stage_config_impl(args)

    if json_data:
        print(json_dumps(json_data), file=STDOUT)

    return ret


def cmd_deploy_config(args):
    ret, json_data, controller = cmd_stage_config_impl(args)

    if ret != 0:
        if json_data:
            print(json_dumps(json_data), file=STDOUT)
        return ret

    return cmd_deploy(args, controller=controller)


def cmd_show_settings(_args):
    CONFIG.write(STDOUT)
    return 0


def cmd_test_timeout(args):
    controller = create_controller()
    if controller is None:
        return 1

    resp, msg = controller.transact(TestTimeoutRequest, TestTimeoutResponse,
                                    args.with_state)

    if resp is None:
        LOG.error('no response received: %s', msg)
        return 1

    res = Result.from_brokertype(resp.result)
    print(json_dumps({'success': res.success, 'error': res.error}),
          file=STDOUT)
    return 0
