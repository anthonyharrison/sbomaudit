# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path

import requests
from lib4sbom.data.document import SBOMDocument
from lib4sbom.license import LicenseScanner
from packageurl import PackageURL
from rich import print
from rich.panel import Panel
from rich.text import Text


class SBOMaudit:
    def __init__(self, options={}):
        self.verbose = options.get("verbose", False)
        self.offline = options.get("offline", False)
        self.cpe_check = options.get("cpecheck", False)
        self.purl_check = options.get("purlcheck", False)
        self.license_check = options.get("license_check", True)
        self.license_scanner = LicenseScanner()
        self.check_count = {"Fail": 0, "Pass": 0}
        self.allow_list = {}
        self.deny_list = {}

    def _show_text(self, text):
        print(Text.styled(f"[x] {text}", "green"))

    def _show_result(self, text, state, value=None, failure_text="MISSING"):
        if state:
            # Green
            if self.verbose:
                self._show_text(text)
            self.check_count["Pass"] = self.check_count["Pass"] + 1
        else:
            # Red
            if value is not None:
                print(Text.styled(f"[ ] {text}: {value}", "red"))
            elif len(failure_text) > 0:
                print(Text.styled(f"[ ] {text}: {failure_text}", "red"))
            else:
                print(Text.styled(f"[ ] {text}", "red"))
            self.check_count["Fail"] = self.check_count["Fail"] + 1

    def _heading(self, title):
        print(Panel(title, style="bold", expand=False))

    def _check_value(self, text, values, data_item):
        self._show_result(text, data_item in values, data_item)

    def _check(self, text, value, failure_text="MISSING"):
        self._show_result(text, value, failure_text=failure_text)

    def find_latest_version_maven(self, name):
        """Returns the latest version of the package available at Maven Central."""

        url: str = f"https://search.maven.org/solrsearch/select?q=a:{name}&wt=json"
        maven_version = None
        try:
            package_json = requests.get(url).json()
            maven_version = package_json["response"]["docs"][0]["latestVersion"]
        except Exception as error:
            print(
                f"""
            -------------------------- Can't check Maven Central for the latest version -------
            Exception details: {error}
            Please make sure you have a working internet connection or try again later.
            """
            )
        return maven_version

    def find_latest_version(self, name):
        """Returns the latest version of the package available at PyPI."""

        url: str = f"https://pypi.org/pypi/{name}/json"
        pypi_version = None
        try:
            package_json = requests.get(url).json()
            pypi_version = package_json["info"]["version"]
        except Exception as error:
            print(
                f"""
            -------------------------- Can't check PyPi for the latest version -------
            Exception details: {error}
            Please make sure you have a working internet connection or try again later.
            """
            )
        return pypi_version

    def get_latest_version(self, name, backend="PyPI"):
        url: str = f"https://release-monitoring.org/api/v2/projects/?name={name}"
        latest_version = None
        try:
            package_json = requests.get(url).json()
            if (
                package_json["total_items"] == 1
                and package_json["items"][0]["backend"].lower() == backend.lower()
            ):
                latest_version = package_json["items"][0]["stable_versions"][0]
            else:
                for item in package_json["items"]:
                    if item["backend"].lower() == backend.lower():
                        latest_version = item["stable_versions"][0]
                        break

        except Exception as error:
            print(
                f"""
            -------------------------- Can't check for the latest version -------
            Exception details: {error}
            Please make sure you have a working internet connection or try again later.
            """
            )
        return latest_version

    def process_file(self, filename, allow):
        # Only process if file exists
        if Path(filename).resolve().exists():
            if allow:
                self._setup(filename, self.allow_list)
            else:
                self._setup(filename, self.deny_list)

    def _setup(self, filename, data_list):
        with open(filename, "r") as f:
            lines = f.readlines()
            for line in lines:
                if line.startswith("#"):
                    # Comment so ignore
                    continue
                elif line.startswith("["):
                    type = line.replace("[", "").replace("]", "").strip()
                    data_list[type] = []
                else:
                    data_list[type].append(line.strip())

    def audit_sbom(self, sbom_parser):
        # Get constituent components of the SBOM
        packages = sbom_parser.get_packages()
        files = sbom_parser.get_files()
        relationships = sbom_parser.get_relationships()
        document = SBOMDocument()
        document.copy_document(sbom_parser.get_document())

        self._heading("SBOM Format Summary")
        fail_count = self.check_count["Fail"]

        # Check that document is a valid SBOM
        if document.get_type() is not None:
            # Check recent version of SBOM
            if document.get_type().lower() == "spdx":
                self._check_value(
                    "Up to date SPDX Version",
                    ["SPDX-2.2", "SPDX-2.3"],
                    document.get_version(),
                )
            else:
                self._check_value(
                    "Up to date CycloneDX Version",
                    ["1.3", "1.4", "1.5"],
                    document.get_version(),
                )
            creation_time = document.get_created() is not None
            creator_identified = len(document.get_creator()) > 0
            relationships_valid = len(relationships) > 0
            self._check("SBOM Creator identified", creator_identified)
            self._check("SBOM Creation time defined", creation_time)
        else:
            # Not a valid SBOM file
            self._check("SBOM Format", False, failure_text="INVALID")
            creator_identified = False
            relationships_valid = False
        # Report if all checks passed
        if not self.verbose:
            if self.check_count["Fail"] == fail_count:
                # No tests failed
                self._show_text("SBOM Format")

        files_valid = True
        packages_valid = True

        allow_licenses = self.allow_list.get("license", None)
        deny_licenses = self.deny_list.get("license", None)
        allow_packages = self.allow_list.get("package", None)
        deny_packages = self.deny_list.get("package", None)

        if len(files) > 0:
            self._heading("File Summary")
            fail_count = self.check_count["Fail"]
            for file in files:
                # Minimum elements are ID, Name
                id = file.get("id", None)
                if id is None:
                    self._check("File id missing", id)
                else:
                    name = file.get("name", None)
                    filetype = file.get("filetype", None)
                    if filetype is not None:
                        file_type = ", ".join(t for t in filetype)
                    else:
                        file_type = None
                    license = file.get("licenseconcluded", None)
                    spdx_license = self.license_scanner.find_license(license) not in [
                        "UNKNOWN",
                        "NOASSERTION",
                    ]
                    copyright = file.get("copyrighttext", None)
                    self._check(f"File name specified - {name}", name)
                    if name is not None:
                        self._check(
                            f"File type identified - {name} : {file_type}",
                            filetype is not None,
                        )
                        self._check(
                            f"License specified - {name} : {license}",
                            not (license in [None, "NOASSERTION"]),
                            failure_text="",
                        )
                        if self.license_check:
                            self._check(
                                f"SPDX Compatible License id included for {name}",
                                spdx_license,
                                failure_text=f"{license}",
                            )
                            self._check(
                                f"OSI Approved license for {name}",
                                self.license_scanner.osi_approved(license),
                            )
                            self._check(
                                f"Non-deprecated license for {name}",
                                not self.license_scanner.deprecated(license),
                            )
                        if allow_licenses is not None:
                            self._check(
                                f"Allowed License check for {name}",
                                license in allow_licenses,
                                failure_text=f"{license} not allowed",
                            )
                        if deny_licenses is not None:
                            self._check(
                                f"Denied License check for {name}",
                                not (license in deny_licenses),
                                failure_text=f"{license} not allowed",
                            )
                        self._check(
                            f"Copyright defined - {name} : {copyright}",
                            not (copyright in [None, "NOASSERTION"]),
                            failure_text="",
                        )
                    else:
                        self._check(
                            f"File type identified - {id} : {file_type}",
                            filetype is not None,
                        )
                        self._check(
                            f"License specified - {id} : {license}",
                            not (license in [None, "NOASSERTION"]),
                            failure_text="",
                        )
                        if self.license_check:
                            self._check(
                                f"SPDX Compatible License id included for {id}",
                                spdx_license,
                                failure_text=f"{license}",
                            )
                            self._check(
                                f"OSI Approved license for {id}",
                                self.license_scanner.osi_approved(license),
                            )
                            self._check(
                                f"Non-deprecated license for {name}",
                                not self.license_scanner.deprecated(license),
                            )
                        if allow_licenses is not None:
                            self._check(
                                f"Allowed License check for {id}",
                                license in allow_licenses,
                                failure_text=f"{license} not allowed",
                            )
                        if deny_licenses is not None:
                            self._check(
                                f"Denied License check for {id}",
                                not (license in deny_licenses),
                                failure_text=f"{license} not allowed",
                            )
                        self._check(
                            f"Copyright defined - {id} : {copyright}",
                            not (copyright in [None, "NOASSERTION"]),
                            failure_text="",
                        )

                if id is None or name is None:
                    files_valid = False
            self._check("NTIA compliant", files_valid, failure_text="FAILED")

            # Report if all checks passed
            if not self.verbose:
                if self.check_count["Fail"] == fail_count:
                    # No tests failed
                    self._show_text("File Summary")

        if len(packages) > 0:
            self._heading("Package Summary")
            fail_count = self.check_count["Fail"]
            for package in packages:
                # Minimum elements are ID, Name, Version, Supplier
                id = package.get("id", None)
                if id is None:
                    self._check("Package id missing", id)
                else:
                    # Get package metadata
                    name = package.get("name", None)
                    version = package.get("version", None)
                    supplier = package.get("supplier", None)
                    license = package.get("licenseconcluded", "NOT KNOWN")
                    spdx_license = self.license_scanner.find_license(license) not in [
                        "UNKNOWN",
                        "NOASSERTION",
                    ]
                    # Check if package is the latest version
                    external_refs = package.get("externalreference", None)
                    latest_version = None
                    purl_used = False
                    cpe_used = False
                    if external_refs is not None:
                        for external_ref in external_refs:
                            # Can be two specifications of PACKAGE MANAGER attribute!
                            if external_ref[0] in [
                                "PACKAGE-MANAGER",
                                "PACKAGE_MANAGER",
                            ]:
                                purl_used = True
                                try:
                                    purl = PackageURL.from_string(
                                        external_ref[2]
                                    ).to_dict()
                                    if not self.offline:
                                        if purl["type"] == "pypi":
                                            # Python package detected
                                            latest_version = self.find_latest_version(
                                                name
                                            )
                                        elif purl["type"] == "maven":
                                            # Maven package detected
                                            latest_version = (
                                                self.find_latest_version_maven(name)
                                            )
                                        else:
                                            latest_version = self.get_latest_version(
                                                name, backend=purl["type"]
                                            )
                                    purl_name = purl["name"]
                                except ValueError:
                                    purl_used = False
                            elif external_ref[1] in ["cpe22Type", "cpe23Type"]:
                                cpe_used = True

                    # Now summarise
                    if name is not None:
                        if allow_packages is not None:
                            self._check(
                                f"Allowed Package check for package {name}",
                                name in allow_packages,
                                failure_text=f"{package} not allowed",
                            )
                        if deny_packages is not None:
                            self._check(
                                f"Denied Package check for package {name}",
                                not (name in deny_packages),
                                failure_text=f"{name} not allowed",
                            )
                        self._check(f"Supplier included for package {name}", supplier)
                        self._check(f"Version included for package {name}", version)
                        self._check(
                            f"License included for package {name}",
                            not (license in ["NOT KNOWN", "NOASSERTION"]),
                        )
                        if self.license_check and license not in [
                            "NOT KNOWN",
                            "NOASSERTION",
                        ]:
                            self._check(
                                f"SPDX Compatible License id included for package {name}",
                                spdx_license,
                                failure_text=f"{license}",
                            )
                            self._check(
                                f"OSI Approved license for {name}",
                                self.license_scanner.osi_approved(license),
                            )
                            self._check(
                                f"Non-deprecated license for {name}",
                                not self.license_scanner.deprecated(license),
                            )
                        if allow_licenses is not None:
                            self._check(
                                f"Allowed License check for package {name}",
                                license in allow_licenses,
                                failure_text=f"{license} not allowed",
                            )
                        if deny_licenses is not None:
                            self._check(
                                f"Denied License check for package {name}",
                                not (license in deny_licenses),
                                failure_text=f"{license} not allowed",
                            )
                        if latest_version is not None:
                            report = f"Version is {version}; latest is {latest_version}"
                            self._check(
                                f"Using latest version of package {name}",
                                latest_version == version,
                                failure_text=report,
                            )
                        if self.cpe_check:
                            self._check(
                                f"CPE name included for package {name}", cpe_used
                            )
                        if self.purl_check:
                            self._check(
                                f"PURL included for package {name}",
                                purl_used,
                                failure_text="MISSING or INVALID",
                            )
                            if purl_used:
                                # Check name is consistent with package name
                                self._check(
                                    f"PURL name compatible with package {name}",
                                    purl_name == name,
                                )
                    else:
                        self._check(f"Package name missing for {id}", False)

                if (
                    id is None
                    or name is None
                    or version is None
                    or supplier is None
                    or supplier == "NOASSERTION"
                ):
                    packages_valid = False
            self._check("NTIA compliant", packages_valid, failure_text="FAILED")

            # Report if all checks passed
            if not self.verbose:
                if self.check_count["Fail"] == fail_count:
                    # No tests failed
                    self._show_text("Package Summary")

        self._heading("Relationships Summary")
        fail_count = self.check_count["Fail"]

        self._check(
            "Dependency relationships provided for NTIA compliance", relationships_valid
        )

        # Check all files/packages included in at least one relationship
        if len(files) > 0:
            for file in files:
                name = file.get("name", None)
                dep_check = False
                if name is not None:
                    for r in relationships:
                        if name in [r.get("source"), r.get("target")]:
                            dep_check = True
                            break
                self._check(f"Dependency relationship found for {name}", dep_check)
        if len(packages) > 0:
            for package in packages:
                name = package.get("name", None)
                dep_check = False
                if name is not None:
                    for r in relationships:
                        if name in [r.get("source"), r.get("target")]:
                            dep_check = True
                            break
                self._check(f"Dependency relationship found for {name}", dep_check)

        # Report if all checks passed
        if not self.verbose:
            if self.check_count["Fail"] == fail_count:
                # No tests failed
                self._show_text("Relationships Summary")

        self._heading("NTIA Summary")
        fail_count = self.check_count["Fail"]

        valid_sbom = (
            files_valid
            and packages_valid
            and creator_identified
            and creation_time
            and relationships_valid
        )
        self._check("NTIA conformant", valid_sbom, failure_text="FAILED")

        # Report if all checks passed
        if not self.verbose:
            if self.check_count["Fail"] == fail_count:
                # No tests failed
                self._show_text("NTIA Summary")

        self._heading("SBOM Audit Summary")
        # Overide verbose setting to ensure always shown
        self.verbose = True
        self._show_text(f"Checks passed {self.check_count['Pass']}")
        self._show_text(f"Checks failed {self.check_count['Fail']}")
