"""
Author: Aleksa Zatezalo
Version: 1.0
Date: February 2025
Description: Module for session managment and request generation.
"""

import aiohttp
from typing import Dict, List, Optional, Tuple
from .grapePrint import grapePrint
from .headers_manager import HeadersManager
import json
import time

# To Do
# Use crush, juice, ... etc as payload generation
# Set token as potential thing
# Call out true negatives (note down Ismaeels thing)
# Print Nicley on Windows
# Make this into package (Docs, examples, tests)
# Report test I tried it on

class base:
    """
    A class made to manage and launch GraphQL test suite with support for custom headers and cookies.
    """

    def __init__(self):
        """Initialize the injection tester with default settings."""

        self.message = grapePrint()
        self.proxy_url: Optional[str] = None
        self.endpoint: Optional[str] = None
        self.authToken: Optional[str] = None
        self.headers_manager = HeadersManager()
        self.schema: Optional[Dict] = None
        self.mutation_fields: Dict[str, Dict] = {}
        self.query_fields: Dict[str, Dict] = {}

    def configureProxy(self, proxy_host: str, proxy_port: int):
        """Configure HTTP proxy settings."""

        self.proxy_url = f"http://{proxy_host}:{proxy_port}"

    def set_header(self, name: str, value: str):
        """
        Set a custom header.
        
        Args:
            name: Header name
            value: Header value
        """
        self.headers_manager.add_header(name, value)
        self.message.printMsg(f"Set header {name}: {value}", status="success")

    def set_headers(self, headers: Dict[str, str]):
        """
        Set multiple custom headers.
        
        Args:
            headers: Dictionary of header name/value pairs
        """
        self.headers_manager.add_headers(headers)
        # self.message.printMsg(f"Set {len(headers)} custom headers", status="success")

    def set_cookie(self, name: str, value: str):
        """
        Set a cookie.
        
        Args:
            name: Cookie name
            value: Cookie value
        """
        self.headers_manager.add_cookie(name, value)
        self.message.printMsg(f"Set cookie {name}: {value}", status="success")

    def set_cookies(self, cookies: Dict[str, str]):
        """
        Set multiple cookies.
        
        Args:
            cookies: Dictionary of cookie name/value pairs
        """
        self.headers_manager.add_cookies(cookies)
        # self.message.printMsg(f"Set {len(cookies)} cookies", status="success")

    def set_authorization(self, token: str, prefix: str = "Bearer"):
        """
        Set Authorization header.
        
        Args:
            token: Authorization token
            prefix: Token type prefix (default: "Bearer")
        """
        self.headers_manager.set_authorization(token, prefix)
        self.authToken = token
        self.message.printMsg(f"Set authorization token with prefix '{prefix}'", status="success")

    def clear_headers(self):
        """Reset headers to default state."""
        self.headers_manager.clear_headers()
        self.message.printMsg("Cleared all custom headers", status="success")

    def clear_cookies(self):
        """Remove all cookies."""
        self.headers_manager.clear_cookies()
        self.message.printMsg("Cleared all cookies", status="success")

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
                headers=self.headers_manager.get_all_headers(),
                cookies=self.headers_manager.get_all_cookies(),
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

    def genPayloads():
        """
        """
        
        pass

    def formatRequest():
        """
        """

        pass

    def executeTests():
        """
        """

        pass

    def writeToFile():
        """
        ""
        pass
