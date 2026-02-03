"""
GrapeQL Injection Tester
Author: Aleksa Zatezalo
Version: 3.0
Date: February 2025
Description: Tests GraphQL endpoints for SQL and command injection vulnerabilities.
             Payloads and detection indicators are loaded from YAML test cases.
"""

import time
import json
from typing import Dict, List, Optional, Tuple, Any
from .tester import VulnerabilityTester
from .utils import Finding
from .logger import GrapeLogger
from .loader import TestCaseLoader
from .baseline import BaselineTracker


class InjectionTester(VulnerabilityTester):
    """
    Tests GraphQL endpoints for SQL and command injection vulnerabilities.
    Payloads come from ``test_cases/injection/*.yaml``.
    """

    MODULE_NAME = "injection"

    def __init__(
        self,
        logger: Optional[GrapeLogger] = None,
        loader: Optional[TestCaseLoader] = None,
        baseline: Optional[BaselineTracker] = None,
    ):
        super().__init__(logger=logger, loader=loader, baseline=baseline)
        self.test_name = "GraphQL Injection Testing"
        self.username = "admin"
        self.password = "changeme"

        # Separate loaded test cases by file convention (name prefix)
        self._sqli_cases: List[Dict] = []
        self._cmd_cases: List[Dict] = []
        for tc in self.test_cases:
            name = tc.get("name", "")
            # Heuristic: if indicators include SQL-related strings → sqli
            indicators = tc.get("indicators", [])
            indicator_text = " ".join(indicators).lower()
            if "sql" in indicator_text or "pg::" in indicator_text:
                self._sqli_cases.append(tc)
            else:
                self._cmd_cases.append(tc)

    def set_credentials(self, username: str, password: str) -> None:
        self.username = username
        self.password = password
        self.printer.print_msg(
            f"Set credentials: {username}:{password}", status="success"
        )

    # ------------------------------------------------------------------ #
    #  Payload helpers (fallbacks if no YAML loaded)
    # ------------------------------------------------------------------ #

    def _get_sqli_payloads(self) -> List[Dict]:
        """Return sqli test cases from YAML, or generate defaults."""
        if self._sqli_cases:
            return self._sqli_cases
        # Fallback
        default_indicators = [
            "SQL syntax", "SQLite", "MySQL", "PostgreSQL", "ORA-",
            "SQL Server", "SQLSTATE[", "PG::Error:",
        ]
        return [
            {"name": p, "payload": p, "indicators": default_indicators}
            for p in [
                "'", "' OR 1=1 --", "' OR '1'='1", "\" OR \"\"=\"",
                "' UNION SELECT 1,2,3 --", "' AND 1=1 --", "' AND 1=0 --",
            ]
        ]

    def _get_cmd_payloads(self) -> List[Dict]:
        """Return command injection test cases from YAML, or generate defaults."""
        if self._cmd_cases:
            return self._cmd_cases
        default_indicators = [
            "root:", "/bin/bash", "/bin/sh", ":/home/", "/usr/bin",
            "Permission denied", "command not found", "Linux",
        ]
        return [
            {"name": p, "payload": p, "indicators": default_indicators}
            for p in [
                ";id", "|id", "||id", "&& id",
                ";cat /etc/passwd", "$(id)", "`id`",
            ]
        ]

    # ------------------------------------------------------------------ #
    #  Core testing methods
    # ------------------------------------------------------------------ #

    def _build_query(
        self,
        field_name: str,
        arg_name: str,
        payload: str,
        is_mutation: bool,
    ) -> Optional[str]:
        """Build a GraphQL query injecting *payload* into *arg_name*."""
        operation_type = "mutation" if is_mutation else "query"
        field_info = (
            self.client.mutation_fields.get(field_name)
            if is_mutation
            else self.client.query_fields.get(field_name)
        )
        if not field_info:
            return None

        arg_strings = []
        for arg in field_info["args"]:
            if arg["name"] == arg_name:
                arg_strings.append(f'{arg["name"]}: "{payload}"')
            elif arg["name"] == "username":
                arg_strings.append(f'{arg["name"]}: "{self.username}"')
            elif arg["name"] == "password":
                arg_strings.append(f'{arg["name"]}: "{self.password}"')
            elif arg["type"]["name"] == "Int":
                arg_strings.append(f'{arg["name"]}: 1')
            elif arg["type"]["name"] == "Boolean":
                arg_strings.append(f'{arg["name"]}: true')
            else:
                arg_strings.append(f'{arg["name"]}: "test"')

        args_str = ", ".join(arg_strings)

        field_selections = {
            "CreatePaste": "{ id content title success error }",
            "DeletePaste": "{ success error }",
            "UpdatePaste": "{ id content success error }",
            "AuthResponse": "{ token error }",
            "UserResponse": "{ id username error }",
            "SystemResponse": "{ status message error }",
            "Default": "{ id message error success }",
        }

        if field_name in ["systemDiagnostics", "getVersion", "getStatus"]:
            return f"{operation_type} {{ {field_name}({args_str}) }}"

        selection = field_selections.get(
            field_name.replace("create", "Create")
            .replace("delete", "Delete")
            .replace("update", "Update"),
            field_selections["Default"],
        )
        return f"{operation_type} {{ {field_name}({args_str}) {selection} }}"

    async def _test_field(
        self,
        field_name: str,
        arg_name: str,
        test_case: Dict,
        is_mutation: bool,
    ) -> Tuple[bool, Optional[str], float]:
        """
        Send one payload to one field.arg and check indicators.
        """
        payload = test_case["payload"]
        indicators = test_case.get("indicators", [])

        query = self._build_query(field_name, arg_name, payload, is_mutation)
        if not query:
            return False, None, 0.0

        self.client.set_log_context("InjectionTester", test_case.get("name", "?"))

        start_time = time.time()
        response, error = await self.client.graphql_query(
            query,
            _log_parameter=f"{field_name}.{arg_name}",
            _log_payload=payload,
        )
        duration = time.time() - start_time

        # Record for baseline
        self._record_response_time(duration)

        if error:
            return False, None, duration

        response_text = json.dumps(response)

        for indicator in indicators:
            if indicator.lower() in response_text.lower():
                detail = (
                    f"Possible injection in {field_name}.{arg_name} "
                    f"with payload: {payload}"
                )
                return True, detail, duration

        return False, None, duration

    async def _scan_field(
        self,
        field_name: str,
        is_mutation: bool,
        test_cases: List[Dict],
        vuln_type: str,
    ) -> List[Finding]:
        """Scan a field for a specific injection type using given test cases."""
        findings: List[Finding] = []
        field_info = (
            self.client.mutation_fields.get(field_name)
            if is_mutation
            else self.client.query_fields.get(field_name)
        )
        if not field_info:
            return findings

        string_args = [
            arg["name"]
            for arg in field_info["args"]
            if arg["type"]["name"] in ["String", "ID"]
        ]
        if not string_args:
            return findings

        for arg_name in string_args:
            self.printer.print_msg(
                f"Testing {'mutation' if is_mutation else 'query'} "
                f"field for {vuln_type}: {field_name}.{arg_name}",
                status="log",
            )

            for tc in test_cases:
                is_vuln, detail, _ = await self._test_field(
                    field_name, arg_name, tc, is_mutation
                )
                if is_vuln:
                    severity = "CRITICAL"
                    if vuln_type == "SQLi":
                        impact = "Database access, data extraction, authentication bypass"
                        remediation = "Use parameterized queries and ORM sanitization"
                    else:
                        impact = "Arbitrary command execution on the server"
                        remediation = "Never pass user input to shell commands"

                    finding = Finding(
                        title=f"{vuln_type} in {field_name}.{arg_name}",
                        severity=severity,
                        description=detail,
                        endpoint=self.client.endpoint,
                        impact=impact,
                        remediation=remediation,
                    )
                    findings.append(finding)
                    self.add_finding(finding)
                    break  # one finding per arg is enough

        return findings

    # ------------------------------------------------------------------ #
    #  Main entry point
    # ------------------------------------------------------------------ #

    async def run_test(self) -> List[Finding]:
        if not self.client.endpoint or not (
            self.client.query_fields or self.client.mutation_fields
        ):
            self.printer.print_msg(
                "No endpoint set or schema not retrieved. Run setup_endpoint first.",
                status="error",
            )
            return self.findings

        self.printer.print_section("Starting Injection Testing")
        self.printer.print_msg(
            f"Using credentials username='{self.username}' password='{self.password}'",
            status="log",
        )

        sqli_cases = self._get_sqli_payloads()
        cmd_cases = self._get_cmd_payloads()

        # SQLi — queries then mutations
        self.printer.print_msg("Testing for SQL injection...", status="log")
        for field in self.client.query_fields:
            await self._scan_field(field, False, sqli_cases, "SQLi")
        for field in self.client.mutation_fields:
            await self._scan_field(field, True, sqli_cases, "SQLi")

        # Command injection — queries then mutations
        self.printer.print_msg("Testing for command injection...", status="log")
        for field in self.client.query_fields:
            await self._scan_field(field, False, cmd_cases, "Command Injection")
        for field in self.client.mutation_fields:
            await self._scan_field(field, True, cmd_cases, "Command Injection")

        if not self.findings:
            self.printer.print_msg(
                "No injection vulnerabilities found", status="success"
            )

        return self.findings
