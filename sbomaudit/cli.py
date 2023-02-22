# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import argparse
import sys
import textwrap
from collections import ChainMap

from lib4sbom.parser import SBOMParser

from sbomaudit.audit import SBOMaudit
from sbomaudit.version import VERSION

# CLI processing


def main(argv=None):

    argv = argv or sys.argv
    app_name = "sbomaudit"
    parser = argparse.ArgumentParser(
        prog=app_name,
        description=textwrap.dedent(
            """
            SBOMAudit reports on the quality of an SBOM.
            """
        ),
    )
    input_group = parser.add_argument_group("Input")
    input_group.add_argument(
        "-i",
        "--input-file",
        action="store",
        default="",
        help="Name of SBOM file",
    )

    input_group.add_argument(
        "--offline",
        action="store_true",
        help="operate in offline mode",
        default=False,
    )

    input_group.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="verbose reporting",
    )

    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="add debug information",
    )

    # # Add format option
    # output_group.add_argument(
    #     "-f",
    #     "--format",
    #     action="store",
    #     help="Output format (default: output to console)",
    #     choices=["console", "markdown", "pdf"],
    #     default="console",
    # )
    #
    # output_group.add_argument(
    #     "-o",
    #     "--output-file",
    #     action="store",
    #     default="",
    #     help="output filename (default: output to stdout)",
    # )

    parser.add_argument("-V", "--version", action="version", version=VERSION)

    defaults = {
        "input_file": "",
        "debug": False,
        "offline": False,
        "verbose": False,
        "format": "console",
    }

    raw_args = parser.parse_args(argv[1:])
    args = {key: value for key, value in vars(raw_args).items() if value}
    args = ChainMap(args, defaults)

    # Validate CLI parameters

    input_file = args["input_file"]

    if input_file == "":
        print("[ERROR] SBOM name must be specified.")
        return -1

    # if args["format"] != "console" and args["output_file"] == "":
    #     print("[ERROR] Output filename must be specified.")
    #     return -1

    if args["debug"]:
        print("Input file", args["input_file"])
        print("Offline mode", args["offline"])
        print("Verbose", args["verbose"])

    sbom_parser = SBOMParser()
    # Load SBOM - will autodetect SBOM type
    try:
        sbom_parser.parse_file(input_file)

        sbom_audit = SBOMaudit(args["verbose"], offline = args["offline"])
        sbom_audit.audit_sbom(sbom_parser)

    except FileNotFoundError:
        print(f"{input_file} not found")

    return 0


if __name__ == "__main__":
    sys.exit(main())
