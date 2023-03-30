# SBOMAUIDT

SBOMAUDIT reports on the quality of the contents of an SBOM (Software Bill of Materials) by performing a number of checks. SBOMs are supported in a number of formats including
[SPDX](https://www.spdx.org) and [CycloneDX](https://www.cyclonedx.org).

## Installation

To install use the following command:

`pip install sbomaudit`

Alternatively, just clone the repo and install dependencies using the following command:

`pip install -U -r requirements.txt`

The tool requires Python 3 (3.7+). It is recommended to use a virtual python environment especially
if you are using different versions of python. `virtualenv` is a tool for setting up virtual python environments which
allows you to have all the dependencies for the tool set up in a single environment, or have different environments set
up for testing using different versions of Python.

## Usage

```
usage: sbomaudit [-h] [-i INPUT_FILE] [--offline] [--cpecheck] [--purlcheck] [--verbose] [--debug] [-V]

SBOMAudit reports on the quality of the contents of a SBOM.

options:
  -h, --help            show this help message and exit
  -V, --version         show program's version number and exit

Input:
  -i INPUT_FILE, --input-file INPUT_FILE
                        Name of SBOM file
  --offline             operate in offline mode
  --cpecheck            check for CPE specification
  --purlcheck           check for PURL specification
  --disable-license-check
                        disable check for SPDX License identifier
  --allow ALLOW         Name of allow list file
  --deny DENY           Name of deny list file
  --verbose             verbose reporting

Output:
  --debug               add debug information

```
					
## Operation

The `--input-file` option is used to specify the SBOM to be processed. The format of the SBOM is determined according to
the following filename conventions.

| SBOM      | Format    | Filename extension |
| --------- | --------- |--------------------|
| SPDX      | TagValue  | .spdx              |
| SPDX      | JSON      | .spdx.json         |
| SPDX      | YAML      | .spdx.yaml         |
| SPDX      | YAML      | .spdx.yml          |
| CycloneDX | JSON      | .json              |

The `--offline` option is used when the tool is used in an environment where access to external systems is not available. This means
that some audit checks are not performed.

The `--cpecheck` and `--purlcheck` options are used to enable additional checks related to a SBOM component.
The `--disable-license-check` option is used to disable the check that the licenses have valid [SPDX License identifiers](https://spdx.org/licenses/).

The `--allow` and `--deny` options are used to specify additional checks related to licenses and packages which are to be allowed or denied within a SBOM component.
An **_allow_** file contains the set of licenses and packages which to be contained within the SBOM; this may be useful to ensure that the SBOM does not contain any
unapproved licenses or packages not identified in a software design. A **_deny_** file is used to specify the licenses and packages which must not be contained within the SBOM.

### Allow and Deny list file formats

The files are text files consisting of two sections

- List of SPDX license identifiers
- Lst of Package names

Each section is optional.

In this sample allow file, this would only allow cemponents with the MIT, Apache-2.0 or BSD-3-Clause licenses.
It is also only expecting a single package 'click'.

```bash
# This is an example ALLOW list file for SBOMAUDIT
# Allowed licenses
[license]
MIT
Apache-2.0
BSD-3-Clause
# Allowed packages 
[package] 
click                                                           
```

## Checks Performed

The following section identifies the checks which are performed.

### SBOM Format

The following checks are performed:

- Check that the version of the SBOM is either version 2.2 or 2.3 (SPDX) or version 1.3 or 1.4 (CycloneDX).

- Check that a creator is defined.

- Check that the time that the SBOM is created is defined.

### Files

The following checks are performed for each file item:

- Check that a file name is specified.

- Check that the file type is specified.

- Check that a license is specified and that the license identified is a valid [SPDX License identifier](https://spdx.org/licenses/). Note that NOASSERTION is not considered a valid license.

- Check that the license is an [OSI Approved](https://opensource.org/licenses/) license.

- Optionally check that the license is allowed as specified in the ALLOW list

- Optionally check that the license is not included in the licenses specified in the DENY list

- Check that a copyright statement is specified. Note that NOASSERTION is not considered a valid copyright statement.

### Packages

The following checks are performed on each package item:

- Check that a package name is specified.

- Optionally check that the package name is allowed as specified in the ALLOW list

- Optionally check that the package name is not included in the packages specified in the DENY list

- Check that a supplier is specified.

- Check that a version is specified.

- Check that the package version is the latest released version of the package. The latest version checks are only performed if the `--offline` option is not specified and is only performed for Python modules available on the [Python Package Index (PyPi)](https://pypi.org/).

- Check that a license is specified and that the license identified is a valid [SPDX License identifier](https://spdx.org/licenses/). Note that NOASSERTION is not considered a valid license.

- Check that the license is an [OSI Approved](https://opensource.org/licenses/) license.

- Optionally check that the license is allowed as specified in the ALLOW list

- Optionally check that the license is not included in the licenses specified in the DENY list

- Check that a [PURL specification](https://github.com/package-url/purl-spec) is provided for the package.

- Check that a [CPE specification](https://nvd.nist.gov/products/cpe) is provided for the package.

### Relationships

The following checks are performed:

- Check that relationships are defined.

### NTIA Conformance

The following checks are performed:

- Check that the contents of the SBOM meet the minimum requirements for an SBOM as defined by the [NTIA](https://www.ntia.doc.gov/files/ntia/publications/sbom_minimum_elements_report.pdf).

## Example

Given the following SBOM (click.json)

```
{
  "$schema": "http://cyclonedx.org/schema/bom-1.4.schema.json",
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "serialNumber": "urn:uuided03b5fe-42a8-41ee-b68f-114aa6fcead9",
  "version": 1,
  "metadata": {
    "timestamp": "2023-02-21T16:09:46Z",
    "tools": [
      {
        "name": "sbom4python",
        "version": "0.8.0"
      }
    ],
    "component": {
      "type": "application",
      "bom-ref": "CDXRef-DOCUMENT",
      "name": "Python-click"
    }
  },
  "components": [
    {
      "type": "library",
      "bom-ref": "1-click",
      "name": "click",
      "version": "8.1.3",
      "supplier": {
        "name": "Armin Ronacher",
        "contact": [
          {
            "email": "armin.ronacher@active-4.com"
          }
        ]
      },
      "cpe": "cpe:2.3:a:armin_ronacher:click:8.1.3:*:*:*:*:*:*:*",
      "description": "Composable command line interface toolkit",
      "licenses": [
        {
          "license": {
            "id": "BSD-3-Clause",
            "url": "https://opensource.org/licenses/BSD-3-Clause"
          }
        }
      ],
      "externalReferences": [
        {
          "url": "https://palletsprojects.com/p/click/",
          "type": "other",
          "comment": "Home page for project"
        }
      ],
      "purl": "pkg:pypi/click@8.1.3"
    }
  ],
  "dependencies": [
    {
      "ref": "CDXRef-DOCUMENT",
      "dependsOn": [
        "1-click"
      ]
    }
  ]
}
```

The following command will audit the contents of the SBOM.

```bash
sbomaudit --input-file click.json
╭─────────────────────╮
│ SBOM Format Summary │
╰─────────────────────╯
[x] SBOM Format
╭─────────────────╮
│ Package Summary │
╰─────────────────╯
[x] Package Summary
╭───────────────────────╮
│ Relationships Summary │
╰───────────────────────╯
[x] Relationship Summary
╭──────────────╮
│ NTIA Summary │
╰──────────────╯
[x] NTIA Summary
╭────────────────────╮
│ SBOM Audit Summary │
╰────────────────────╯
[x] Checks passed 11
[x] Checks failed 0                                                              
```

A verbose report and summary of the contents of the SBOM to the console.

```bash
sbomaudit --input-file click.json --verbose --cpecheck --purlcheck
╭─────────────────────╮
│ SBOM Format Summary │
╰─────────────────────╯
[x] Up to date CycloneDX Version
[x] SBOM Creator identified
[x] SBOM Creation time defined
╭─────────────────╮
│ Package Summary │
╰─────────────────╯
[x] Supplier included for package click
[x] Version included for package click
[x] License included for package click
[x] SPDX Compatible License id included for package click
[x] Using latest version of package click
[x] CPE name included for package click
[x] PURL included for package click
[x] PURL name compatible with package click
[x] NTIA compliant
╭───────────────────────╮
│ Relationships Summary │
╰───────────────────────╯
[x] Dependency relationships provided for NTIA compliancw
╭──────────────╮
│ NTIA Summary │
╰──────────────╯
[x] NTIA conformant
╭────────────────────╮
│ SBOM Audit Summary │
╰────────────────────╯
[x] Checks passed 14
[x] Checks failed 0                                                        
```

The following is an example of the output which is generated
when some checks on the contents of the SBOM fail.

```bash
╭─────────────────────╮
│ SBOM Format Summary │
╰─────────────────────╯
[x] SBOM Format
╭─────────────────╮
│ Package Summary │
╰─────────────────╯
[ ] Using latest version of package black: Version is 22.12.0; latest is 23.1.0
[ ] Using latest version of package mypy-extensions: Version is 0.4.3; latest is 1.0.0
[ ] SPDX Compatible License id included for package pathspec: MPL 2.0
[ ] Using latest version of package pathspec: Version is 0.10.3; latest is 0.11.0
[ ] License included for package platformdirs: MISSING
[ ] SPDX Compatible License id included for package platformdirs: NOASSERTION
[ ] Using latest version of package platformdirs: Version is 2.6.2; latest is 3.0.0
[ ] CPE name included for package platformdirs: MISSING
[ ] License included for package tomli: MISSING
[ ] SPDX Compatible License id included for package tomli: NOASSERTION
[ ] NTIA compliant : FAILED
╭───────────────────────╮
│ Relationships Summary │
╰───────────────────────╯
[x] Relationship Summary
╭──────────────╮
│ NTIA Summary │
╰──────────────╯
[ ] NTIA conformant : FAILED
╭────────────────────╮
│ SBOM Audit Summary │
╰────────────────────╯
[x] Checks passed 42
[x] Checks failed 12                                                   
```

## License

Licensed under the Apache 2.0 License.

## Limitations

The tool has the following limitations:

- The latest version checks are only performed on Python modules available on the [Python Package Index (PyPi)](https://pypi.org/).

- Invalid SBOMs will result in unpredictable results.

## Feedback and Contributions

Bugs and feature requests can be made via GitHub Issues.