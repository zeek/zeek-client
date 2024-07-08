#!/usr/bin/env python3
#
# A helper script to derive a zeek-client manpage from its argparse state.
#
import os
import sys

try:
    from argparse_manpage.manpage import Manpage
except ImportError:
    print("The manpage builder needs the argparse_manpage package.")
    sys.exit(1)

import zeekclient.cli

LOCALDIR = os.path.dirname(os.path.realpath(__file__))
ROOTDIR = os.path.normpath(os.path.join(LOCALDIR, ".."))

# Prepend the project's toplevel directory to the search path so we import the
# zeekclient package locally.
sys.path.insert(0, ROOTDIR)

import zeekclient.cli  # pylint: disable=wrong-import-position,import-error


def main():
    # Set a fixed number of columns to avoid output discrepancies between
    # invocation at the shell vs via CI tooling. This only affects how the
    # manpage is written to disk, not how it renders at the terminal.
    os.environ["COLUMNS"] = "80"

    # Change the program name so the parsers report zeek-client, not build.py.
    sys.argv[0] = "zeek-client"

    parser = zeekclient.cli.create_parser()

    # Expand the description:
    parser.description = """A command-line client for Zeek's Management Framework.

Use this client to push cluster configurations to a cluster controller, retrieve
running state from the system, restart nodes, and more.

For details about Zeek's Management Framework, please consult the documentation
at https://docs.zeek.org/en/master/frameworks/management.html.
"""
    # Remove the epilog -- it's more suitable for an ENVIRONMENT section.
    environment = parser.epilog
    parser.epilog = None

    # The 'single-commands-section' formatter spells out the details of every
    # subcommand as it lists each of those commands.
    manpage = Manpage(parser, format="single-commands-section")

    # The Manpage class cannot handle ":" in the usage string ("HOST:PORT"),
    # so replace the synopsis. Must yield a list of strings.
    # https://github.com/praiskup/argparse-manpage/pull/102
    manpage.synopsis = parser.format_usage().split(":", 1)[-1].split()

    # The manpage contains a date, which breaks our comparison logic when
    # running this script produces otherwise identical output.
    manpage.date = ""

    # It's just another user command, more meaningful than "Generated Python Manual"
    manpage.manual = "User Commands"

    manpage.add_section(
        "EXIT STATUS",
        ">",
        """The client exits with 0 on
success and 1 if a problem arises, such as lack of a response from the
controller, unexpected response data, or the controller explicitly reporting an
error in its handling of a command.""",
    )

    # Create an environment section from the epilog in the parser.
    # We replace the first line to be more manpage-suitable.
    env = environment.splitlines()
    env = ["zeek-client supports the following environment variables:"] + env[1:]
    manpage.add_section("ENVIRONMENT", ">", "\n".join(env))

    manpage.add_section(
        "SUGGESTIONS AND BUG REPORTS",
        ">",
        """The Management Framework and this client are experimental
software. The Zeek team welcomes your feedback. Please file issues on Github at
https://github.com/zeek/zeek-client/issues, or contact us on Discourse or Slack:
https://zeek.org/community""",
    )

    with open(os.path.join(LOCALDIR, "zeek-client.1"), "w", encoding="ascii") as hdl:
        hdl.write(str(manpage))


if __name__ == "__main__":
    main()
