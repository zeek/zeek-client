#! /usr/bin/env python
"""This verifies zeek-client invocations."""
import os
import subprocess
import sys
import unittest

TESTS = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.normpath(os.path.join(TESTS, '..'))

# Prepend the tree's root folder to the module searchpath so we find zeek-client
# via it. This allows tests to run without package installation.
sys.path.insert(0, ROOT)


class TestCli(unittest.TestCase):
    def setUp(self):
        # Set up an environment in which subprocesses pick up our stub Broker fist:
        self.env = os.environ.copy()
        self.env['PYTHONPATH'] = os.pathsep.join(sys.path)

    def test_help(self):
        cproc = subprocess.run([os.path.join(ROOT, 'zeek-client'), '--help'],
                               env=self.env, capture_output=True)
        self.assertEqual(cproc.returncode, 0)

    def test_show_settings(self):
        env = os.environ.copy()
        env['PYTHONPATH'] = os.pathsep.join(sys.path)
        cproc = subprocess.run([os.path.join(ROOT, 'zeek-client'), 'show-settings'],
                               env=self.env, capture_output=True)
        self.assertEqual(cproc.returncode, 0)


def test():
    """Entry point for testing this module.

    Returns True if successful, False otherwise.
    """
    res = unittest.main(sys.modules[__name__], verbosity=0, exit=False)
    # This is how unittest.main() implements the exit code itself:
    return res.result.wasSuccessful()

if __name__ == '__main__':
    sys.exit(not test())
