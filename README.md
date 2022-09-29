# The Zeek Cluster Management Client

[![Unit tests](https://github.com/zeek/zeek-client/actions/workflows/test.yml/badge.svg)](https://github.com/zeek/zeek-client/actions/workflows/test.yml)

This is the recommended command-line client for interacting with Zeek's
[Management framework](https://docs.zeek.org/en/master/frameworks/management.html).
Built in Python and using Broker's [WebSocket pub/sub interface](https://docs.zeek.org/projects/broker/en/v2.3.0/web-socket.html), it
connects to a cluster controller to execute management tasks. Here's what it looks like:

```console
$ zeek-client --help
usage: zeek-client [-h] [-c FILE] [--controller HOST:PORT] [--set SECTION.KEY=VAL] [--quiet | --verbose]
                   [--version]
                   {deploy,deploy-config,get-config,get-id-value,get-instances,get-nodes,monitor,restart,stage-config,show-settings,test-timeout}
                   ...

A Zeek management client

options:
  -h, --help            show this help message and exit
  -c FILE, --configfile FILE
                        Path to zeek-client config file. (Default: /home/christian/inst/opt/zeek/etc/zeek-
                        client.cfg)
  --controller HOST:PORT
                        Address and port of the controller, either of which may be omitted (default:
                        127.0.0.1:2150)
  --set SECTION.KEY=VAL
                        Adjust a configuration setting. Can use repeatedly. See show-settings.
  --quiet, -q           Suppress informational output to stderr.
  --verbose, -v         Increase informational output to stderr. Repeat for more output (e.g. -vvv).
  --version             Show version number and exit.

commands:
  {deploy,deploy-config,get-config,get-id-value,get-instances,get-nodes,monitor,restart,stage-config,show-settings,test-timeout}
                        See `zeek-client <command> -h` for per-command usage info.
    deploy              Deploy a staged cluster configuration.
    deploy-config       Upload a cluster configuration and deploy it.
    get-config          Retrieve staged or deployed cluster configuration.
    get-id-value        Show the value of a given identifier in Zeek cluster nodes.
    get-instances       Show instances connected to the controller.
    get-nodes           Show active Zeek nodes at each instance.
    monitor             For troubleshooting: do nothing, just report events.
    restart             Restart cluster nodes.
    stage-config        Upload a cluster configuration for later deployment.
    show-settings       Show zeek-client's own configuration.
    test-timeout        Send timeout test event.

environment variables:

    ZEEK_CLIENT_CONFIG_FILE:      Same as `--configfile` argument, but lower precedence.
    ZEEK_CLIENT_CONFIG_SETTINGS:  Same as a space-separated series of `--set` arguments, but lower precedence.
```

## Installation

The recommended way to run the client is to install it with Zeek, since the
client is part of the distribution. You may also run it directly from the
official Zeek [Docker image](https://hub.docker.com/r/zeekurity/zeek).

The WebSocket-powered `zeek-client` currently requires Zeek built from
the master branch, or via our [development Docker image](https://hub.docker.com/r/zeekurity/zeek-dev).
`zeek-client` will officially become available as a standalone package,
installable via `pip`, with Zeek 5.2.

## Quickstart

Run the following (as root) to launch an all-in-one management instance on your
system:

```console
# zeek -C -j policy/frameworks/management/controller policy/frameworks/management/agent
```

The above will stay in the foreground. In a new shell, save the following
content to a file ``cluster.cfg`` and adapt the worker's sniffing interfaces to
your system:

```ini
[manager]
role = manager

[logger]
role = logger

[worker-01]
role = worker
interface = lo

[worker-02]
role = worker
interface = eth0
```

Run the following command (as any user) to deploy the configuration:

```console
$ zeek-client deploy-config cluster.cfg
{
  "errors": [],
  "results": {
    "id": "9befc56c-f7e8-11ec-8626-7c10c94416bb",
    "nodes": {
      "logger": {
        "instance": "agent-testbox",
        "success": true
      },
      "manager": {
        "instance": "agent-testbox",
        "success": true
      },
      "worker-01": {
        "instance": "agent-testbox",
        "success": true
      },
      "worker-02": {
        "instance": "agent-testbox",
        "success": true
      }
    }
  }
}
```

You are now running a Zeek cluster on your system. Try ``zeek-client get-nodes``
to see more details about the cluster's current status. (In the above, "testbox"
is the system's hostname.)

## Documentation

The [Zeek documentation](https://docs.zeek.org/en/master/frameworks/management.html)
covers both the Management framework and the client's commands.
