"""
Author: [Your Name]
Version: 1.0
Date: February 2025
Description: Module to test authentication vulnerabilities in GraphQL endpoints.
"""

import aiohttp
from typing import Dict, List, Optional, Tuple, Set
import json
import asyncio
from grapePrint import grapePrint

class authJuice:
    """
    A class for testing GraphQL endpoints for authentication vulnerabilities.
    Tests for missing authentication, broken authentication, and authorization bypasses.
    """

    def __init__(self):
        """Initialize the authentication tester with default settings."""
        self.message = grapePrint()
        self.proxy_url: Optional[str] = None
        self.endpoint: Optional[str] = None
        self.headers = {"Content-Type": "application/json"}
        self.schema: Optional[Dict] = None
        self.mutation_fields: Dict[str, Dict] = {}
        self.query_fields: Dict[str, Dict] = {}
        self.auth_tokens: Dict[str, str] = {}
        self.sensitive_fields = {
            'password', 'token', 'secret', 'key', 'credential',
            'ssn', 'credit_card', 'address', 'phone'
        }

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

    def configureProxy(self, proxy_host: str, proxy_port: int):
        """Configure HTTP proxy settings."""
        self.proxy_url = f"http://{proxy_host}:{proxy_port}"

    async def runIntrospection(self, session: aiohttp.ClientSession) -> bool:
        """Run introspection query to validate the GraphQL endpoint and map its schema."""
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
                        type {
                            name
                            fields {
                                name
                                type {
                                    name
                                }
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
                        type {
                            name
                            fields {
                                name
                                type {
                                    name
                                }
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
                        
                        # Store query fields with return type information
                        if schema.get("queryType"):
                            for field in schema["queryType"]["fields"]:
                                self.query_fields[field["name"]] = {
                                    "args": field.get("args", []),
                                    "return_type": field.get("type", {}).get("name", ""),
                                    "return_fields": self._extract_return_fields(field)
                                }

                        # Store mutation fields with return type information
                        if schema.get("mutationType"):
                            for field in schema["mutationType"]["fields"]:
                                self.mutation_fields[field["name"]] = {
                                    "args": field.get("args", []),
                                    "return_type": field.get("type", {}).get("name", ""),
                                    "return_fields": self._extract_return_fields(field)
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

    def _extract_return_fields(self, field: Dict) -> Set[str]:
        """Extract return field names from a GraphQL field type."""
        fields = set()
        if field.get("type", {}).get("fields"):
            for return_field in field["type"]["fields"]:
                fields.add(return_field["name"])
        return fields

    async def register_user(self, session: aiohttp.ClientSession, username: str, password: str) -> Optional[str]:
        """Attempt to register a new user and return any token."""
        mutation = """
        mutation ($username: String!, $password: String!) {
            register(username: $username, password: $password) {
                token
                error
                success
            }
        }
        """
        
        try:
            async with session.post(
                self.endpoint,
                json={
                    "query": mutation,
                    "variables": {"username": username, "password": password}
                },
                headers=self.headers,
            ) as response:
                result = await response.json()
                if result.get("data", {}).get("register", {}).get("token"):
                    return result["data"]["register"]["token"]
        except Exception as e:
            self.message.printMsg(f"Registration error: {str(e)}", status="error")
        return None

    async def login_user(self, session: aiohttp.ClientSession, username: str, password: str) -> Optional[str]:
        """Attempt to login and return any token."""
        mutation = """
        mutation ($username: String!, $password: String!) {
            login(username: $username, password: $password) {
                token
                error
                success
            }
        }
        """
        
        try:
            async with session.post(
                self.endpoint,
                json={
                    "query": mutation,
                    "variables": {"username": username, "password": password}
                },
                headers=self.headers,
            ) as response:
                result = await response.json()
                if result.get("data", {}).get("login", {}).get("token"):
                    return result["data"]["login"]["token"]
        except Exception as e:
            self.message.printMsg(f"Login error: {str(e)}", status="error")
        return None

    async def test_authentication_bypass(self, session: aiohttp.ClientSession, field_name: str, is_mutation: bool = False) -> List[str]:
        """Test for authentication bypass vulnerabilities."""
        vulnerabilities = []
        operation_type = "mutation" if is_mutation else "query"
        field_info = self.mutation_fields.get(field_name) if is_mutation else self.query_fields.get(field_name)
        
        if not field_info:
            return vulnerabilities

        # Prepare test cases
        test_cases = [
            # No authentication
            {},
            # Invalid token
            {"Authorization": "Bearer invalid_token"},
            # Common default tokens
            {"Authorization": "Bearer null"},
            {"Authorization": "Bearer undefined"},
            {"Authorization": "Bearer admin"},
            # SQL injection in token
            {"Authorization": "Bearer ' OR '1'='1"},
            # JWT specific tests
            {"Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."},
            {"Authorization": "Bearer " + "A" * 100},  # Overflow attempt
        ]

        # Build a generic query that attempts to access the field
        args_str = self._build_default_args(field_info["args"])
        selection = self._build_selection(field_info["return_fields"])
        
        query = f"""
        {operation_type} {{
            {field_name}({args_str}) {selection}
        }}
        """

        for test_headers in test_cases:
            test_headers.update(self.headers)
            try:
                async with session.post(
                    self.endpoint,
                    json={"query": query},
                    headers=test_headers,
                    proxy=self.proxy_url,
                    ssl=False,
                ) as response:
                    result = await response.json()
                    
                    # Check if we got actual data without proper authentication
                    if "data" in result and result["data"].get(field_name):
                        if not result.get("errors"):
                            vuln_msg = f"Possible authentication bypass in {field_name} with headers {test_headers}"
                            vulnerabilities.append(vuln_msg)
                            self.message.printMsg(vuln_msg, status="failed")

            except Exception as e:
                self.message.printMsg(f"Error testing {field_name}: {str(e)}", status="error")

        return vulnerabilities

    def _build_default_args(self, args: List[Dict]) -> str:
        """Build default arguments string for a GraphQL query."""
        arg_strings = []
        for arg in args:
            if arg["type"]["name"] == "Int":
                arg_strings.append(f'{arg["name"]}: 1')
            elif arg["type"]["name"] == "Boolean":
                arg_strings.append(f'{arg["name"]}: true')
            else:
                arg_strings.append(f'{arg["name"]}: "test"')
        return ", ".join(arg_strings)

    def _build_selection(self, return_fields: Set[str]) -> str:
        """Build GraphQL selection set based on return fields."""
        if not return_fields:
            return "{ id }"
        return "{ " + " ".join(return_fields) + " }"

    async def test_brute_force_protection(self, session: aiohttp.ClientSession) -> List[str]:
        """Test for brute force protection in authentication endpoints."""
        vulnerabilities = []
        test_credentials = [
            ("admin", "password"),
            ("admin", "admin"),
            ("test", "test"),
            ("root", "root"),
            ("user", "password123")
        ]

        # Try rapid login attempts
        for username, password in test_credentials:
            tasks = []
            for _ in range(10):  # Try 10 rapid attempts
                tasks.append(self.login_user(session, username, password))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            success_count = sum(1 for r in results if r is not None)
            
            if success_count > 5:  # If more than 5 attempts succeed
                vuln_msg = f"No rate limiting detected for login attempts with user {username}"
                vulnerabilities.append(vuln_msg)
                self.message.printMsg(vuln_msg, status="failed")

        return vulnerabilities

    async def scan_for_auth_vulnerabilities(self) -> List[str]:
        """Perform comprehensive authentication vulnerability scanning."""
        if not self.endpoint:
            self.message.printMsg(
                "No endpoint set. Run setEndpoint first.",
                status="error",
            )
            return []

        print()
        self.message.printMsg("Starting authentication vulnerability testing", status="success")
        self.message.printMsg(
            "Testing for authentication bypasses and brute force protection...",
            status="warning",
        )

        all_vulnerabilities = []
        
        async with aiohttp.ClientSession() as session:
            # Test authentication bypass for queries
            for field_name in self.query_fields:
                vulnerabilities = await self.test_authentication_bypass(session, field_name)
                all_vulnerabilities.extend(vulnerabilities)

            # Test authentication bypass for mutations
            for field_name in self.mutation_fields:
                vulnerabilities = await self.test_authentication_bypass(session, field_name, is_mutation=True)
                all_vulnerabilities.extend(vulnerabilities)

            # Test brute force protection
            vulnerabilities = await self.test_brute_force_protection(session)
            all_vulnerabilities.extend(vulnerabilities)

        if not all_vulnerabilities:
            self.message.printMsg("No authentication vulnerabilities detected", status="success")
        else:
            self.message.printMsg(
                f"Found {len(all_vulnerabilities)} potential vulnerabilities",
                status="failed"
            )

        return all_vulnerabilities

    async def test_token_security(self, token: str) -> List[str]:
        """Test security of authentication tokens."""
        vulnerabilities = []
        
        # Check token length
        if len(token) < 32:
            vulnerabilities.append("Token length is less than recommended minimum of 32 characters")
            
        # Check for JWT format and common vulnerabilities
        if token.count('.') == 2:  # Likely JWT
            try:
                header, payload, signature = token.split('.')
                if signature == "":
                    vulnerabilities.append("JWT token has empty signature")
                if "none" in header.lower():
                    vulnerabilities.append("JWT token uses 'none' algorithm")
            except Exception:
                pass

        return vulnerabilities