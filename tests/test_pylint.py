#! /usr/bin/env python
"""This runs pylint on zeek-client and the zeekclient package. It
exits non-zero if pylint identifies any hard errors, and zero otherwise
(including when pylint isn't available). These aren't unit tests, but we
use the unittest infrastructure for convenient test-skipping functionality.
"""
import os
import sys
import unittest

try:
    import pylint.lint
except ImportError:
    pass

TESTS = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.normpath(os.path.join(TESTS, ".."))
RCFILE = os.path.join(ROOT, ".pylintrc")


class TestPylint(unittest.TestCase):
    def _run(self, args):
        try:
            # The easiest way to get the return code out of a pylint run
            # seems to be allowing it to try to exit and catch its SystemExit.
            pylint.lint.Run(args)
        except SystemExit as err:
            return err.code == 0

    @unittest.skipIf("pylint.lint" not in sys.modules, "Pylint not available")
    def test_zeekclient(self):
        self.assertTrue(
            self._run(["--rcfile=" + RCFILE, "-E", os.path.join(ROOT, "zeekclient")])
        )

    @unittest.skipIf("pylint.lint" not in sys.modules, "Pylint not available")
    def test_zeek_client(self):
        self.assertTrue(
            self._run(["--rcfile=" + RCFILE, "-E", os.path.join(ROOT, "zeek-client")])
        )
