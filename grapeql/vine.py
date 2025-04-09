"""
Author: Aleksa Zatezalo
Version: 2.0
Date: March 2025
Description: Enumeration script for GraphQL endpoints with proxy support for HTTP operations.
"""

import asyncio
import aiohttp
import socket
from typing import Dict, List, Optional, Set
from .grapePrint import grapePrint
from .http_client import GraphQLClient
import time


class vine:
    """
    A class for discovering GraphQL endpoints through port scanning and directory enumeration.
    Supports proxying HTTP traffic through a proxy while performing direct port scans.
    """

    def __init__(self):
        """
        Initialize the vine class with default settings and API endpoints list.
        """
        self.message = grapePrint()
        self.client = GraphQLClient()
        self.default_api_paths = [
            "/graphql",
            "/graphql/playground",
            "/graphiql",
            "/api/explorer",
            "/graphql/v1",
            "/graphql/v2",
            "/graphql/v3",
            "/api/graphql/v1",
            "/api/graphql/v2",
            "/api/public/graphql",
            "/api/private/graphql",
            "/admin/graphql",
            "/user/graphql",
        ]
        self.api_paths = self.default_api_paths.copy()

    def set_header(self, name: str, value: str) -> None:
        """Set a custom header."""
        self.client.set_header(name, value)
        self.message.printMsg(f"Set header {name}: {value}", status="success")

    def set_headers(self, headers: Dict[str, str]) -> None:
        """Set multiple custom headers."""
        self.client.set_headers(headers)

    def set_cookie(self, name: str, value: str) -> None:
        """Set a custom cookie."""
        self.client.set_cookie(name, value)
        self.message.printMsg(f"Set cookie {name}: {value}", status="success")

    def set_cookies(self, cookies: Dict[str, str]) -> None:
        """Set multiple custom cookies."""
        self.client.set_cookies(cookies)

    def set_authorization(self, token: str, prefix: str = "Bearer") -> None:
        """Set authorization header."""
        self.client.set_authorization(token, prefix)
        self.message.printMsg(f"Set authorization token with prefix '{prefix}'", status="success")

    def setApiList(self, endpoints: List[str]) -> bool:
        """
        Set a custom list of API endpoints to scan.

        Args:
            endpoints: List of endpoint paths to scan (e.g., ['/graphql', '/api/graphql'])

        Returns:
            bool: True if endpoints were set successfully, False otherwise
        """
        try:
            # Validate input is a list
            if not isinstance(endpoints, list):
                self.message.printMsg(
                    "Error: Endpoints must be provided as a list", status="error"
                )
                return False

            # Validate and clean each endpoint
            cleaned_endpoints = []
            for endpoint in endpoints:
                # Check if endpoint is a string
                if not isinstance(endpoint, str):
                    self.message.printMsg(
                        f"Warning: Skipping invalid endpoint: {endpoint}",
                        status="warning",
                    )
                    continue

                # Clean the endpoint
                cleaned = endpoint.strip()

                # Ensure endpoint starts with /
                if not cleaned.startswith("/"):
                    cleaned = "/" + cleaned

                # Remove any trailing slashes
                cleaned = cleaned.rstrip("/")

                cleaned_endpoints.append(cleaned)

            # Check if we have any valid endpoints
            if not cleaned_endpoints:
                self.message.printMsg(
                    "Error: No valid endpoints provided", status="error"
                )
                return False

            # Set the new API list
            self.api_paths = cleaned_endpoints
            self.message.printMsg(
                f"Successfully set {len(cleaned_endpoints)} endpoints", status="success"
            )
            return True

        except Exception as e:
            self.message.printMsg(f"Error setting API list: {str(e)}", status="error")
            return False

    def configureProxy(self, proxy_host: str, proxy_port: int) -> None:
        """
        Configure the HTTP proxy settings.

        Args:
            proxy_host: The proxy server hostname or IP
            proxy_port: The proxy server port
        """
        self.client.configure_proxy(proxy_host, proxy_port)

    async def testPortNumber(self, host: str, port: int) -> bool:
        """
        Test if a specific port is open on the target host (direct connection, no proxy).

        Args:
            host: The target hostname or IP address
            port: The port number to test

        Returns:
            bool: True if port is open, False otherwise
        """
        try:
            future = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(future, timeout=0.5)
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False

    async def scanPortRange(
        self, host: str, start_port: int, end_port: int
    ) -> List[int]:
        """
        Scan a range of ports concurrently on the target host (direct connection).

        Args:
            host: The target hostname or IP address
            start_port: The starting port number in the range
            end_port: The ending port number in the range

        Returns:
            List[int]: List of open ports found in the specified range
        """
        tasks = []
        for port in range(start_port, end_port + 1):
            tasks.append(self.testPortNumber(host, port))

        results = await asyncio.gather(*tasks)

        open_ports = []
        for port, is_open in zip(range(start_port, end_port + 1), results):
            if is_open:
                self.message.printMsg(f"{host}:{port} [OPEN]")
                open_ports.append(port)

        return open_ports

    async def scanIP(self, host: str = "127.0.0.1") -> List[int]:
        """
        Scan all ports on a target host in chunks (direct connection).

        Args:
            host: The target hostname or IP address (default: "127.0.0.1")

        Returns:
            List[int]: Sorted list of all open ports found on the host
        """
        chunk_size = 1000
        open_ports = []

        for start_port in range(1, 65536, chunk_size):
            end_port = min(start_port + chunk_size - 1, 65535)
            chunk_results = await self.scanPortRange(host, start_port, end_port)
            open_ports.extend(chunk_results)

        return sorted(open_ports)

    async def dirb(self, base_url: str, path: str) -> Optional[str]:
        """
        Test a single endpoint path for existence on the target URL.
        Filters out WebSocket endpoints.

        Args:
            base_url: The base URL to test against
            path: The endpoint path to append to the base URL

        Returns:
            Optional[str]: Full URL if endpoint exists and is not a WebSocket endpoint, None otherwise
        """
        full_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
        
        try:
            # Set the URL for this request only, without changing the client's endpoint
            result = await self.client.request("GET", full_url)
            
            # Inspect the response status
            status = result.get("status")
            if status == 404:
                return None
                
            # Check for WebSocket indication
            response_text = result.get("text", "")
            if "WebSockets request was expected" in response_text:
                return None
                
            return full_url
                
        except Exception as e:
            self.message.printMsg(f"Error testing {full_url}: {str(e)}", status="error")
            return None

    async def scanEndpoints(self, base_url: str) -> List[str]:
        """
        Scan all API endpoints concurrently on a given base URL.

        Args:
            base_url: The base URL to test endpoints against

        Returns:
            List[str]: List of valid endpoint URLs found
        """
        tasks = [self.dirb(base_url, path) for path in self.api_paths]
        results = await asyncio.gather(*tasks)
        return [result for result in results if result]

    async def constructAddress(self, ip: str) -> List[str]:
        """
        Construct full URLs for all open ports on a target IP.

        Args:
            ip: The target IP address

        Returns:
            List[str]: List of URLs constructed from open ports
        """
        self.message.printMsg("Beginning Direct Port Scan", status="success")
        time.sleep(1)
        ports = await self.scanIP(host=ip)
        return [f"http://{ip}:{port}" for port in ports]

    async def dirbList(self, valid_endpoints: List[str]) -> List[str]:
        """
        Perform directory busting on a list of endpoints.

        Args:
            valid_endpoints: List of base URLs to test

        Returns:
            List[str]: List of all valid URLs found
        """
        self.message.printMsg("Started directory busting", status="success")
        time.sleep(1)
        url_list = []
        for endpoint in valid_endpoints:
            found_urls = await self.scanEndpoints(endpoint)
            for url in found_urls:
                self.message.printMsg(f"Found URL at {url}")
                url_list.append(url)
        return url_list

    async def checkEndpoint(self, endpoint: str) -> Optional[str]:
        """
        Test a single endpoint for GraphQL introspection vulnerability.

        Args:
            endpoint: The endpoint URL to test

        Returns:
            Optional[str]: Endpoint URL if vulnerable, None otherwise
        """
        # Set the endpoint temporarily for this test
        self.client.set_endpoint(endpoint)
        
        # Check if introspection is enabled
        if await self.client.has_introspection():
            self.message.printMsg(f"Introspection enabled: {endpoint}", status="warning")
            return endpoint
            
        return None

    async def introspection(self, endpoints: List[str]) -> List[str]:
        """
        Test multiple endpoints for GraphQL introspection vulnerability.

        Args:
            endpoints: List of endpoints to test

        Returns:
            List[str]: List of vulnerable endpoints with introspection enabled
        """
        self.message.printMsg("Testing for introspection query", status="success")
        time.sleep(1)

        tasks = [self.checkEndpoint(endpoint) for endpoint in endpoints]
        results = await asyncio.gather(*tasks)
        return [endpoint for endpoint in results if endpoint]

    def validate_proxy(self, proxy_host: str, proxy_port: int) -> bool:
        """
        Validate that proxy is accessible.

        Args:
            proxy_host: The proxy server hostname or IP
            proxy_port: The proxy server port

        Returns:
            bool: True if proxy is valid and accessible, False otherwise
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((proxy_host, proxy_port))
            sock.close()
            return True
        except Exception as e:
            self.message.printMsg(
                f"Proxy validation failed: {str(e)}", status="error"
            )
            return False

    async def test(self, proxy_string: str = None, target_ip: str = None) -> List[str]:
        """
        Main execution function that coordinates the scanning process.

        Args:
            proxy_string: Optional string containing proxy host and port in format "host:port"
            target_ip: Target IP address to scan

        Returns:
            List[str]: List of vulnerable GraphQL endpoints found
        """
        try:
            # Configure proxy if provided
            if proxy_string:
                try:
                    proxy_host, proxy_port_str = proxy_string.split(":")
                    proxy_port = int(proxy_port_str)

                    # Validate and configure proxy
                    if not self.validate_proxy(proxy_host, proxy_port):
                        self.message.printMsg(
                            "Cannot connect to proxy. Please ensure proxy is running and settings are correct.",
                            status="error",
                        )
                        return []

                    self.configureProxy(proxy_host, proxy_port)
                except ValueError:
                    self.message.printMsg(
                        "Invalid proxy string format. Expected format: host:port",
                        status="error",
                    )
                    return []

            # Perform scan using provided target IP
            valid_endpoints = await self.constructAddress(target_ip)
            url_list = await self.dirbList(valid_endpoints)
            return await self.introspection(url_list)

        except Exception as e:
            self.message.printMsg(f"Error during scan: {str(e)}", status="error")
            return []