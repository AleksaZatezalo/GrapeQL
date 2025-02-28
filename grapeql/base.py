"""
Author: Aleksa Zatezalo
Version: 1.0
Date: February 2025
Description: Module for session managment and request generation.
"""

import aiohttp
from typing import Dict, List, Optional, Tuple
from grapePrint import grapePrint
import json
import time

# To Do
# Use crush, juice, ... etc as payload generation
# Set token as potential thing
# Call out true negatives (note down Ismaeels thing)

class base:
    """
    A class made to manage and launch grapgql test suite.
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
        )s

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
        ""

        pass
        
