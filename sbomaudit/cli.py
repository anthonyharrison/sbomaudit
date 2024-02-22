# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import argparse
import sys
import textwrap
from collections import ChainMap

from lib4sbom.output import SBOMOutput
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
            SBOMAudit reports on the quality of the contents of a SBOM.
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
        "--cpecheck",
        action="store_true",
        help="check for CPE specification",
        default=False,
    )

    input_group.add_argument(
        "--purlcheck",
        action="store_true",
        help="check for PURL specification",
        default=False,
    )

    input_group.add_argument(
        "--disable-license-check",
        action="store_true",
        help="disable check for SPDX License identifier",
        default=False,
    )

    input_group.add_argument(
        "--age",
        action="store",
        help="minimum age of package (as integer representing days) to report (default: 0)",
        default=0,
    )

    input_group.add_argument(
        "--maxage",
        action="store",
        help="maximum age of package (as integer representing years) to report (default: 2)",
        default=2,
    )
    input_group.add_argument(
        "--allow",
        action="store",
        default="",
        help="Name of allow list file",
    )

    input_group.add_argument(
        "--deny",
        action="store",
        default="",
        help="Name of deny list file",
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

    output_group.add_argument(
        "-o",
        "--output-file",
        action="store",
        default="",
        help="output filename (default: output to stdout)",
    )

    parser.add_argument("-V", "--version", action="version", version=VERSION)

    defaults = {
        "input_file": "",
        "debug": False,
        "offline": False,
        "cpecheck": False,
        "purlcheck": False,
        "disable_license_check": False,
        "age": 0,
        "maxage": 2,
        "allow": "",
        "deny": "",
        "verbose": False,
        "output_file": "",
    }

    raw_args = parser.parse_args(argv[1:])
    args = {key: value for key, value in vars(raw_args).items() if value}
    args = ChainMap(args, defaults)

    # Validate CLI parameters

    input_file = args["input_file"]

    if input_file == "":
        print("[ERROR] SBOM name must be specified.")
        return -1

    if args["debug"]:
        print("Input file", args["input_file"])
        print("Offline mode", args["offline"])
        print("Verbose", args["verbose"])
        print("CPE Check", args["cpecheck"])
        print("PURL Check", args["purlcheck"])
        print("SPDX License Check", not args["disable_license_check"])
        print("Minimum package age", args["age"])
        print("Maximum package age", args["maxage"])
        print("Allow list file", args["allow"])
        print("Deny list file", args["deny"])
        print("Output file", args["output_file"])

    audit_options = {
        "verbose": args["verbose"],
        "offline": args["offline"],
        "cpecheck": args["cpecheck"],
        "purlcheck": args["purlcheck"],
        "license_check": not args["disable_license_check"],
        "age": args["age"],
        "maxage": args["maxage"],
        "debug": args["debug"],
    }

    sbom_parser = SBOMParser()
    ntia_compliance = False
    # Load SBOM - will autodetect SBOM type
    try:
        sbom_parser.parse_file(input_file)

        sbom_audit = SBOMaudit(options=audit_options, output=args["output_file"])
        if args["allow"]:
            sbom_audit.process_file(args["allow"], allow=True)
        if args["deny"]:
            sbom_audit.process_file(args["deny"], allow=False)
        ntia_compliance = sbom_audit.audit_sbom(sbom_parser)

        if args["output_file"] != "":
            audit_out = SBOMOutput(args["output_file"], "json")
            audit_out.generate_output(sbom_audit.get_audit())

    except FileNotFoundError:
        print(f"{input_file} not found")

    # Return 0 for False, 1 for True
    return int(ntia_compliance)


if __name__ == "__main__":
    sys.exit(main())
