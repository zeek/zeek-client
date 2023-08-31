"""This verifies zeek-client invocations."""
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from contextlib import contextmanager

TESTS = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.normpath(os.path.join(TESTS, ".."))

# Prepend this folder so we can load our mocks
sys.path.insert(0, TESTS)

# Prepend the tree's root folder to the module searchpath so we find zeekclient
# via it. This allows tests to run without package installation.
sys.path.insert(0, ROOT)

import zeekclient as zc  # pylint: disable=wrong-import-position


# A context guard to switch the current working directory.
# With 3.11 this can go and become contextlib.chdir():
@contextmanager
def setdir(path):
    origin = os.getcwd()
    try:
        os.chdir(path)
        yield
    finally:
        os.chdir(origin)


class TestCliInvocation(unittest.TestCase):
    # This invokes the zeek-client toplevel script.
    def setUp(self):
        # Set up an environment in which subprocesses pick up our package first:
        self.env = os.environ.copy()
        self.env["PYTHONPATH"] = os.pathsep.join(sys.path)

    def test_help(self):
        cproc = subprocess.run(
            [os.path.join(ROOT, "zeek-client"), "--help"],
            check=True,
            env=self.env,
            capture_output=True,
        )
        self.assertEqual(cproc.returncode, 0)

    def test_show_settings(self):
        env = os.environ.copy()
        env["PYTHONPATH"] = os.pathsep.join(sys.path)
        cproc = subprocess.run(
            [os.path.join(ROOT, "zeek-client"), "show-settings"],
            check=True,
            env=self.env,
            capture_output=True,
        )
        self.assertEqual(cproc.returncode, 0)


class TestBundledCliInvocation(unittest.TestCase):
    # Verify that zeek-client finds its package in Zeek-bundled install, where
    # the package will not be in the usual Python search path. As we add more
    # system-level testing, this may become a btest too, but for we stick to
    # Python. Most system-level testing happens in the zeek-testing-cluster
    # external testsuite.
    @unittest.skipUnless(
        shutil.which("cmake") and shutil.which("make"),
        "needs both cmake and make in the system path",
    )
    def test_bundled_install(self):
        with tempfile.TemporaryDirectory() as tmpdir, setdir(tmpdir):
            # Configure the package via cmake with a Python module directory, as
            # Zeek would do. Do this from the temp directory we're now in ...
            cproc = subprocess.run(
                [
                    "cmake",
                    "-D",
                    f'PY_MOD_INSTALL_DIR={os.path.join(tmpdir, "python")}',
                    f"--install-prefix={tmpdir}",
                    ROOT,
                ],
                check=True,
                capture_output=True,
            )

            # ... and install there too, into local bin/ and python/ dirs.
            cproc = subprocess.run(["make", "install"], check=True, capture_output=True)

            # We should now be able to run "./bin/zeek-client --help".
            cproc = subprocess.run(
                [os.path.join(tmpdir, "bin", "zeek-client"), "--help"],
                capture_output=True,
                check=False,
            )
            if cproc.returncode != 0:
                print("==== STDOUT ====")
                print(cproc.stdout.decode("utf-8"))
                print("==== STDERR ====")
                print(cproc.stderr.decode("utf-8"))
                self.fail("zeek-client invocation failed")


class TestCliBasics(unittest.TestCase):
    def test_create_controller(self):
        # We mock create_controller() below, so use this class to test it:
        res = zc.cli.create_controller()
        self.assertIsNotNone(res)
        self.assertIsNotNone(res.controller_broker_id)


class TestCli(unittest.TestCase):
    # This tests the zeekclient.cli module. Most commands in that module create
    # a controller object, so we mock out its generation so we can enqueue the
    # various response events in its websocket.
    def setUp(self):
        # For capturing log writes done by zeekclient code
        self.logbuf = io.StringIO()
        zc.logs.configure(verbosity=2, stream=self.logbuf)

        self.controller = zc.controller.Controller()

        def mock_create_controller():
            self.controller.connect()
            return self.controller

        self.orig_create_controller = zc.cli.create_controller
        zc.cli.create_controller = mock_create_controller

        def mock_make_uuid(_prefix=""):
            return "mocked-reqid-00000"

        self.orig_make_uuid = zc.utils.make_uuid
        zc.controller.make_uuid = mock_make_uuid
        zc.types.make_uuid = mock_make_uuid
        zc.utils.make_uuid = mock_make_uuid

        # Capture regular writes made by the commands,
        # and let us adjust stdin:
        zc.cli.STDOUT = io.StringIO()
        zc.cli.STDIN = io.StringIO()

    def tearDown(self):
        zc.cli.create_controller = self.orig_create_controller

        zc.controller.make_uuid = self.orig_make_uuid
        zc.types.make_uuid = self.orig_make_uuid
        zc.utils.make_uuid = self.orig_make_uuid

    def assertLogLines(self, *patterns):
        buflines = self.logbuf.getvalue().split("\n")
        todo = list(patterns)
        for line in buflines:
            if todo and re.search(todo[0], line) is not None:
                todo.pop(0)
        msg = None
        if todo:
            msg = f"log pattern '{todo[0]}' not found; have:\n{self.logbuf.getvalue().strip()}"
        self.assertEqual(len(todo), 0, msg)

    def enqueue_response_event(self, event):
        msg = zc.brokertypes.DataMessage("dummy/topic", event.to_brokertype())
        self.controller.wsock.mock_recv_queue.append(msg.serialize())

    def mock_no_controller(self, inargs):
        # This fakes the scenario where connecting to the controller fails.
        parser = zc.cli.create_parser()
        args = parser.parse_args(inargs)

        def mock_create_controller():  # pylint: disable=useless-return
            self.controller.wsock.mock_connect_exc = OSError()
            self.controller.connect()
            return None

        zc.cli.create_controller = mock_create_controller

        self.assertEqual(args.run_cmd(args), 1)
        self.assertLogLines("error: socket error in connect()")

    def mock_no_response(self, inargs):
        # This fakes the scenario where an established connection to the
        # controller starts experiencing trouble.
        parser = zc.cli.create_parser()
        args = parser.parse_args(inargs)

        def mock_create_controller():
            self.controller.connect()
            self.controller.wsock.mock_recv_exc = OSError()
            return self.controller

        zc.cli.create_controller = mock_create_controller

        self.assertEqual(args.run_cmd(args), 1)
        self.assertLogLines("error: no response received")

    def test_cmd_deploy_no_controller(self):
        self.mock_no_controller(["deploy"])

    def test_cmd_deploy_no_response(self):
        self.mock_no_response(["deploy"])

    def test_cmd_deploy(self):
        node_outputs = zc.types.NodeOutputs("problems on stdout", "problems on stderr")

        self.enqueue_response_event(
            zc.events.DeployResponse(
                zc.brokertypes.String(zc.utils.make_uuid()),
                zc.brokertypes.Vector(
                    [
                        zc.types.Result(
                            "reqid-0001", data=zc.brokertypes.String("reqid-config-id")
                        ).to_brokertype(),
                        zc.types.Result(
                            "reqid-0002", instance="instance1", node="manager"
                        ).to_brokertype(),
                        zc.types.Result(
                            "reqid-0003", instance="instance1", node="logger"
                        ).to_brokertype(),
                        zc.types.Result(
                            "reqid-0004",
                            success=False,
                            instance="instance1",
                            node="worker1",
                            data=node_outputs.to_brokertype(),
                        ).to_brokertype(),
                        zc.types.Result(
                            "reqid-0005",
                            success=False,
                            instance="instance1",
                            error="uh-oh",
                        ).to_brokertype(),
                        zc.types.Result(
                            "reqid-0006", instance="instance1"
                        ).to_brokertype(),
                        zc.types.Result("reqid-0007").to_brokertype(),
                    ]
                ),
            )
        )

        parser = zc.cli.create_parser()
        args = parser.parse_args(["deploy"])

        self.assertEqual(args.run_cmd, zc.cli.cmd_deploy)
        self.assertEqual(args.run_cmd(args), 1)
        self.assertEqual(
            zc.cli.STDOUT.getvalue(),
            """{
  "errors": [
    "uh-oh"
  ],
  "results": {
    "id": "reqid-config-id",
    "nodes": {
      "logger": {
        "instance": "instance1",
        "success": true
      },
      "manager": {
        "instance": "instance1",
        "success": true
      },
      "worker1": {
        "instance": "instance1",
        "stderr": "problems on stderr",
        "stdout": "problems on stdout",
        "success": false
      }
    }
  }
}
""",
        )

    def test_cmd_get_config_no_controller(self):
        self.mock_no_controller(["get-config"])

    def test_cmd_get_config_no_response(self):
        self.mock_no_response(["get-config"])

    def test_cmd_get_config_as_json(self):
        config = zc.types.Configuration()
        config.instances.append(zc.types.Instance("instance1"))
        config.nodes.append(
            zc.types.Node("worker1", "instance1", zc.types.ClusterRole.WORKER)
        )

        self.enqueue_response_event(
            zc.events.GetConfigurationResponse(
                zc.brokertypes.String(zc.utils.make_uuid()),
                zc.types.Result(
                    "reqid-0001", data=config.to_brokertype()
                ).to_brokertype(),
            )
        )

        parser = zc.cli.create_parser()
        args = parser.parse_args(["get-config", "--as-json"])

        # cmd_get_config closes the output handle as part of its regular
        # processing. After a close, the contents of a StringIO object vanish,
        # so we prevent this:
        zc.cli.STDOUT.close = lambda: None

        self.assertEqual(args.run_cmd, zc.cli.cmd_get_config)
        self.assertEqual(args.run_cmd(args), 0)

        zc.cli.STDOUT.flush()

        self.assertEqual(
            zc.cli.STDOUT.getvalue(),
            """{
  "id": "mocked-reqid-00000",
  "instances": [
    {
      "name": "instance1"
    }
  ],
  "nodes": [
    {
      "cpu_affinity": null,
      "env": {},
      "instance": "instance1",
      "interface": null,
      "name": "worker1",
      "options": null,
      "port": null,
      "role": "WORKER",
      "scripts": null
    }
  ]
}
""",
        )

    def test_cmd_get_config_as_ini(self):
        config = zc.types.Configuration()
        config.instances.append(zc.types.Instance("instance1"))
        config.nodes.append(
            zc.types.Node("worker1", "instance1", zc.types.ClusterRole.WORKER)
        )

        self.enqueue_response_event(
            zc.events.GetConfigurationResponse(
                zc.brokertypes.String(zc.utils.make_uuid()),
                zc.types.Result(
                    "reqid-0001", data=config.to_brokertype()
                ).to_brokertype(),
            )
        )

        parser = zc.cli.create_parser()
        args = parser.parse_args(["get-config"])

        # cmd_get_config closes the output handle as part of its regular
        # processing. After a close, the contents of a StringIO object vanish,
        # so we prevent this:
        zc.cli.STDOUT.close = lambda: None

        self.assertEqual(args.run_cmd, zc.cli.cmd_get_config)
        self.assertEqual(args.run_cmd(args), 0)

        zc.cli.STDOUT.flush()

        self.assertEqual(
            zc.cli.STDOUT.getvalue(),
            """[instances]
instance1

[worker1]
instance = instance1
role = WORKER

""",
        )

    def test_cmd_get_config_failure(self):
        self.enqueue_response_event(
            zc.events.GetConfigurationResponse(
                zc.brokertypes.String(zc.utils.make_uuid()),
                zc.types.Result(
                    "reqid-0001", success=False, error="uh-oh"
                ).to_brokertype(),
            )
        )

        parser = zc.cli.create_parser()
        args = parser.parse_args(["get-config"])

        self.assertEqual(args.run_cmd, zc.cli.cmd_get_config)
        self.assertEqual(args.run_cmd(args), 1)

    def test_cmd_get_config_no_data(self):
        self.enqueue_response_event(
            zc.events.GetConfigurationResponse(
                zc.brokertypes.String(zc.utils.make_uuid()),
                zc.types.Result("reqid-0001").to_brokertype(),
            )
        )

        parser = zc.cli.create_parser()
        args = parser.parse_args(["get-config"])

        self.assertEqual(args.run_cmd, zc.cli.cmd_get_config)
        self.assertEqual(args.run_cmd(args), 1)

    def test_cmd_get_id_value_no_controller(self):
        self.mock_no_controller(["get-id-value", "Foo:id"])

    def test_cmd_get_id_value_no_response(self):
        self.mock_no_response(["get-id-value", "Foo:id"])

    def test_cmd_get_id_value(self):
        self.enqueue_response_event(
            zc.events.GetIdValueResponse(
                zc.brokertypes.String(zc.utils.make_uuid()),
                zc.brokertypes.Vector(
                    [
                        zc.types.Result(
                            "reqid-0001",
                            data=zc.brokertypes.String('"a-value"'),
                            node="worker1",
                        ).to_brokertype(),
                        zc.types.Result(
                            "reqid-0002",
                            data=zc.brokertypes.String('"b-value"'),
                            node="worker2",
                        ).to_brokertype(),
                        zc.types.Result(
                            "reqid-0003",
                            success=False,
                            error="that did not work",
                            node="worker2",
                        ).to_brokertype(),
                        zc.types.Result(
                            "reqid-0004", data=zc.brokertypes.Count(10), node="worker2"
                        ).to_brokertype(),
                    ]
                ),
            )
        )

        parser = zc.cli.create_parser()
        args = parser.parse_args(["get-id-value", "Foo:id"])

        self.assertEqual(args.run_cmd, zc.cli.cmd_get_id_value)
        self.assertEqual(args.run_cmd(args), 1)
        self.assertEqual(
            zc.cli.STDOUT.getvalue(),
            """{
  "errors": [
    {
      "error": "that did not work",
      "source": "worker2"
    },
    {
      "error": "invalid result data type {\\"@data-type\\": \\"count\\", \\"data\\": 10}",
      "source": "worker2"
    }
  ],
  "results": {
    "worker1": "a-value",
    "worker2": "b-value"
  }
}
""",
        )

    def test_cmd_get_instances_no_controller(self):
        self.mock_no_controller(["get-instances"])

    def test_cmd_get_instances_no_response(self):
        self.mock_no_response(["get-instances"])

    def test_cmd_get_instances(self):
        self.enqueue_response_event(
            zc.events.GetInstancesResponse(
                zc.brokertypes.String(zc.utils.make_uuid()),
                zc.types.Result(
                    "reqid-0001",
                    data=zc.brokertypes.Vector(
                        [
                            zc.types.Instance(
                                "instance1", "10.0.0.1", 123
                            ).to_brokertype(),
                            zc.types.Instance(
                                "instance2", "10.0.0.2", 234
                            ).to_brokertype(),
                        ]
                    ),
                ).to_brokertype(),
            )
        )

        parser = zc.cli.create_parser()
        args = parser.parse_args(["get-instances"])

        self.assertEqual(args.run_cmd, zc.cli.cmd_get_instances)
        self.assertEqual(args.run_cmd(args), 0)
        self.assertEqual(
            zc.cli.STDOUT.getvalue(),
            """{
  "instance1": {
    "host": "10.0.0.1",
    "port": 123
  },
  "instance2": {
    "host": "10.0.0.2",
    "port": 234
  }
}
""",
        )

    def test_cmd_get_nodes_no_controller(self):
        self.mock_no_controller(["get-nodes"])

    def test_cmd_get_nodes_no_response(self):
        self.mock_no_response(["get-nodes"])

    def test_cmd_get_nodes(self):
        self.enqueue_response_event(
            zc.events.GetNodesResponse(
                zc.brokertypes.String(zc.utils.make_uuid()),
                zc.brokertypes.Vector(
                    [
                        zc.types.Result(
                            "reqid-0001",
                            instance="instance1",
                            data=zc.brokertypes.Vector(
                                [
                                    zc.types.NodeStatus(
                                        "manager",
                                        zc.types.State.RUNNING,
                                        zc.types.ManagementRole.NONE,
                                        zc.types.ClusterRole.MANAGER,
                                        12345,
                                        2200,
                                    ).to_brokertype(),
                                    zc.types.NodeStatus(
                                        "logger",
                                        zc.types.State.RUNNING,
                                        zc.types.ManagementRole.NONE,
                                        zc.types.ClusterRole.LOGGER,
                                        12346,
                                        2201,
                                    ).to_brokertype(),
                                ]
                            ),
                        ).to_brokertype(),
                        zc.types.Result(
                            "reqid-0002",
                            instance="instance2",
                            data=zc.brokertypes.Vector(
                                [
                                    zc.types.NodeStatus(
                                        "worker1",
                                        zc.types.State.RUNNING,
                                        zc.types.ManagementRole.NONE,
                                        zc.types.ClusterRole.WORKER,
                                        23456,
                                    ).to_brokertype(),
                                    zc.types.NodeStatus(
                                        "worker2",
                                        zc.types.State.RUNNING,
                                        zc.types.ManagementRole.NONE,
                                        zc.types.ClusterRole.WORKER,
                                        23457,
                                    ).to_brokertype(),
                                ]
                            ),
                        ).to_brokertype(),
                        # These cover various error conditions
                        zc.types.Result(
                            "reqid-0003",
                            success=False,
                            instance="instance3",
                            error="uh-oh",
                        ).to_brokertype(),
                        zc.types.Result(
                            "reqid-0003", instance="instance4"
                        ).to_brokertype(),
                    ]
                ),
            )
        )

        parser = zc.cli.create_parser()
        args = parser.parse_args(["get-nodes"])

        self.assertEqual(args.run_cmd, zc.cli.cmd_get_nodes)
        self.assertEqual(args.run_cmd(args), 1)
        self.assertEqual(
            zc.cli.STDOUT.getvalue(),
            """{
  "errors": [
    {
      "error": "uh-oh",
      "source": "instance3"
    },
    {
      "error": "result does not contain node status data",
      "source": "instance4"
    }
  ],
  "results": {
    "instance1": {
      "logger": {
        "cluster_role": "LOGGER",
        "mgmt_role": null,
        "pid": 12346,
        "port": 2201,
        "state": "RUNNING"
      },
      "manager": {
        "cluster_role": "MANAGER",
        "mgmt_role": null,
        "pid": 12345,
        "port": 2200,
        "state": "RUNNING"
      }
    },
    "instance2": {
      "worker1": {
        "cluster_role": "WORKER",
        "mgmt_role": null,
        "pid": 23456,
        "state": "RUNNING"
      },
      "worker2": {
        "cluster_role": "WORKER",
        "mgmt_role": null,
        "pid": 23457,
        "state": "RUNNING"
      }
    }
  }
}
""",
        )

    def test_cmd_restart_no_controller(self):
        self.mock_no_controller(["restart"])

    def test_cmd_restart_no_response(self):
        self.mock_no_response(["restart"])

    def test_cmd_restart(self):
        self.enqueue_response_event(
            zc.events.RestartResponse(
                zc.brokertypes.String(zc.utils.make_uuid()),
                zc.brokertypes.Vector(
                    [
                        zc.types.Result(
                            "reqid-0001", instance="instance1", node="manager"
                        ).to_brokertype(),
                        zc.types.Result(
                            "reqid-0002", instance="instance1", node="logger"
                        ).to_brokertype(),
                        zc.types.Result(
                            "reqid-0003", instance="instance2", node="worker1"
                        ).to_brokertype(),
                        zc.types.Result(
                            "reqid-0004", instance="instance2", node="worker2"
                        ).to_brokertype(),
                        zc.types.Result(
                            "reqid-0004",
                            success=False,
                            node="worker3",
                            error="unknown node",
                        ).to_brokertype(),
                    ]
                ),
            )
        )

        parser = zc.cli.create_parser()
        args = parser.parse_args(["restart"])

        self.assertEqual(args.run_cmd, zc.cli.cmd_restart)
        self.assertEqual(args.run_cmd(args), 1)
        self.assertEqual(
            zc.cli.STDOUT.getvalue(),
            """{
  "errors": [
    {
      "error": "unknown node",
      "source": "worker3"
    }
  ],
  "results": {
    "logger": true,
    "manager": true,
    "worker1": true,
    "worker2": true
  }
}
""",
        )

    def test_cmd_stage_config_no_controller(self):
        self.mock_no_controller(["stage-config", "-"])

    def test_cmd_stage_config_no_response(self):
        self.mock_no_response(["stage-config", "-"])

    def test_cmd_stage_config(self):
        self.enqueue_response_event(
            zc.events.StageConfigurationResponse(
                zc.brokertypes.String(zc.utils.make_uuid()),
                zc.brokertypes.Vector(
                    [
                        zc.types.Result(
                            "reqid-0001", data=zc.brokertypes.String("reqid-config-id")
                        ).to_brokertype(),
                        zc.types.Result(
                            "reqid-0002", success=False, error="uh-oh"
                        ).to_brokertype(),
                    ]
                ),
            )
        )

        parser = zc.cli.create_parser()
        args = parser.parse_args(["stage-config", "-"])

        self.assertEqual(args.run_cmd, zc.cli.cmd_stage_config)
        self.assertEqual(args.run_cmd(args), 1)
        self.assertEqual(
            zc.cli.STDOUT.getvalue(),
            """{
  "errors": [
    "uh-oh"
  ],
  "results": {
    "id": "reqid-config-id"
  }
}
""",
        )

    def test_cmd_deploy_config(self):
        self.enqueue_response_event(
            zc.events.StageConfigurationResponse(
                zc.brokertypes.String(zc.utils.make_uuid()),
                zc.brokertypes.Vector(
                    [
                        zc.types.Result(
                            "reqid-0001", data=zc.brokertypes.String("reqid-config-id")
                        ).to_brokertype(),
                    ]
                ),
            )
        )

        self.enqueue_response_event(
            zc.events.DeployResponse(
                zc.brokertypes.String(zc.utils.make_uuid()),
                zc.brokertypes.Vector(
                    [
                        zc.types.Result(
                            "reqid-0001", data=zc.brokertypes.String("reqid-config-id")
                        ).to_brokertype(),
                        zc.types.Result(
                            "reqid-0002", instance="instance1", node="manager"
                        ).to_brokertype(),
                        zc.types.Result(
                            "reqid-0003", instance="instance1", node="logger"
                        ).to_brokertype(),
                    ]
                ),
            )
        )

        parser = zc.cli.create_parser()
        args = parser.parse_args(["deploy-config", "-"])

        self.assertEqual(args.run_cmd, zc.cli.cmd_deploy_config)
        self.assertEqual(args.run_cmd(args), 0)
        self.assertEqual(
            zc.cli.STDOUT.getvalue(),
            """{
  "errors": [],
  "results": {
    "id": "reqid-config-id",
    "nodes": {
      "logger": {
        "instance": "instance1",
        "success": true
      },
      "manager": {
        "instance": "instance1",
        "success": true
      }
    }
  }
}
""",
        )

    def test_show_settings(self):
        parser = zc.cli.create_parser()
        args = parser.parse_args(["show-settings"])

        self.assertEqual(args.run_cmd, zc.cli.cmd_show_settings)
        self.assertEqual(args.run_cmd(args), 0)

        # The output should be an ini file that we can load back into our
        # configuration:
        zc.CONFIG.read_string(zc.cli.STDOUT.getvalue())
