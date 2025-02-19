"""
Author: Aleksa Zatezalo
Version: 1.0
Date: February 2025
Description: Module to test for command injection, sql injections, and other injection attacks. 
"""

import aiohttp


class juice:

    def __init__():
        pass

    def configureProxy(self, proxy_host: str, proxy_port: int):
        """Configure HTTP proxy settings."""
        self.proxy_url = f"http://{proxy_host}:{proxy_port}"

    async def runIntrospection(self, session: aiohttp.ClientSession) -> bool:
        """
        Run introspection query to validate the GraphQL endpoint.

        Args:
            session: The aiohttp client session to use

        Returns:
            bool: True if introspection succeeded
        """
        query = """
        query {
            __schema {
                queryType {
                    name
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
                        self.message.printMsg("Fingerprinting server", status="success")
                        return True

                self.message.printMsg(
                    "Introspection failed - endpoint might not be GraphQL",
                    status="error",
                )
                return False

        except Exception as e:
            return False

    async def setEndpoint(
        self, endpoint: str, proxy_string: Optional[str] = None
    ) -> bool:
        """
        Set the endpoint and retrieve its schema through introspection.

        Args:
            endpoint: The GraphQL endpoint URL
            proxy_string: Optional proxy in format "host:port"

        Returns:
            bool: True if endpoint was set and schema retrieved successfully
        """

        self.endpoint = endpoint

        # Configure proxy if provided
        if proxy_string:
            try:
                proxy_host, proxy_port = proxy_string.split(":")
                self.configureProxy(proxy_host, int(proxy_port))
            except ValueError:
                self.message.printMsg(
                    "Invalid proxy format. Expected host:port", status="error"
                )
                return False

        # Run introspection
        async with aiohttp.ClientSession() as session:
            return await self.runIntrospection(session)
