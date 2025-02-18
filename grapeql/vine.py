"""
Author: Original by Aleksa Zatezalo, Modified Version
Version: 1.1
Date: February 2025
Description: Enumeration script for GraphQL endpoints with proxy support for HTTP operations. 
Port scanning is performed directly while directory busting and introspection are proxied.
"""

import asyncio
import aiohttp
from typing import List, Tuple, Optional
from grapePrint import grapePrint
import time
import socket

class vine():
    """
    A class for scanning and identifying GraphQL endpoints with introspection enabled.
    Supports proxying HTTP traffic through Burpsuite while performing direct port scans.
    """
    
    def __init__(self):
        """
        Initialize the vine class with default settings and API endpoints list.
        """
        self.message = grapePrint()
        self.apiList = ["/graphql", "/graphql/playground", "/graphiql", "/api/explorer", "/graphql/v1", "/graphql/v2", "/graphql/v3", 
           "/api/graphql/v1", "/api/graphql/v2", "/api/public/graphql", "/api/private/graphql", "/admin/graphql", "/user/graphql"]
        self.proxy_url: Optional[str] = None
        
    def configureProxy(self, proxy_host: str, proxy_port: int):
        """
        Configure the HTTP proxy settings for Burpsuite.

        Args:
            proxy_host: The proxy server hostname or IP
            proxy_port: The proxy server port
        """
        self.proxy_url = f"http://{proxy_host}:{proxy_port}"
    
    def setApiList(self, endpoints: List[str]) -> bool:
        """
        Set a custom list of API endpoints to scan.

        Args:
            endpoints: List of endpoint paths to scan (e.g., ['/graphql', '/api/graphql'])

        Returns:
            bool: True if endpoints were set successfully, False otherwise

        Example:
            scanner = vine()
            scanner.setApiList(['/graphql', '/api/graphql', '/v1/graphql'])
        """
        try:
            # Validate input is a list
            if not isinstance(endpoints, list):
                self.message.printMsg("Error: Endpoints must be provided as a list", status="error")
                return False

            # Validate each endpoint
            cleaned_endpoints = []
            for endpoint in endpoints:
                # Check if endpoint is a string
                if not isinstance(endpoint, str):
                    self.message.printMsg(f"Warning: Skipping invalid endpoint: {endpoint}", status="warning")
                    continue

                # Clean the endpoint
                cleaned = endpoint.strip()
                
                # Ensure endpoint starts with /
                if not cleaned.startswith('/'):
                    cleaned = '/' + cleaned

                # Remove any trailing slashes
                cleaned = cleaned.rstrip('/')

                cleaned_endpoints.append(cleaned)

            # Check if we have any valid endpoints
            if not cleaned_endpoints:
                self.message.printMsg("Error: No valid endpoints provided", status="error")
                return False

            # Set the new API list
            self.apiList = cleaned_endpoints
            self.message.printMsg(f"Successfully set {len(cleaned_endpoints)} endpoints", status="success")
            return True

        except Exception as e:
            self.message.printMsg(f"Error setting API list: {str(e)}", status="error")
            return False

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
            _, writer = await asyncio.wait_for(future, timeout=0.5)
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False

    async def scanPortRange(self, host: str, start_port: int, end_port: int) -> List[int]:
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
                self.message.printMsg(f'{host}:{port} [OPEN]')
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

    async def dirb(self, session: aiohttp.ClientSession, base_url: str, path: str) -> Optional[str]:
        """
        Test a single endpoint path for existence on the target URL through Burp proxy.
        Filters out WebSocket endpoints.

        Args:
            session: The aiohttp client session to use for requests
            base_url: The base URL to test against
            path: The endpoint path to append to the base URL

        Returns:
            Optional[str]: Full URL if endpoint exists and is not a WebSocket endpoint, None otherwise
        """
        full_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
        try:
            async with session.get(
                full_url,
                timeout=aiohttp.ClientTimeout(total=5),
                proxy=self.proxy_url,
                ssl=False  # Required for Burp to intercept HTTPS
            ) as response:
                if response.status != 404:
                    # Check if response contains WebSocket text
                    response_text = await response.text()
                    if "WebSockets request was expected" not in response_text:
                        return full_url
                    
        except Exception as e:
            self.message.printMsg(f"Error testing {full_url}: {str(e)}", status="error")
            
        return None

    async def scanEndpoints(self, base_url: str) -> List[str]:
        """
        Scan all API endpoints concurrently on a given base URL through Burp proxy.

        Args:
            base_url: The base URL to test endpoints against

        Returns:
            List[str]: List of valid endpoint URLs found
        """
        async with aiohttp.ClientSession() as session:
            tasks = [self.dirb(session, base_url, path) for path in self.apiList]
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
        print()
        self.message.printMsg("Beginning Direct Port Scan", status="success")
        time.sleep(3)
        ports = await self.scanIP(host=ip)
        return [f"http://{ip}:{port}" for port in ports]

    async def dirbList(self, valid_endpoints: List[str]) -> List[str]:
        """
        Perform directory busting on a list of endpoints through Burp proxy.

        Args:
            valid_endpoints: List of base URLs to test

        Returns:
            List[str]: List of all valid URLs found
        """
        print()
        self.message.printMsg("Beginning Proxied Directory Busting through Burp", status="success")
        time.sleep(3)
        url_list = []
        for endpoint in valid_endpoints:
            found_urls = await self.scanEndpoints(endpoint)
            for url in found_urls:
                self.message.printMsg(f"Found URL at {url}")
                url_list.append(url)
        return url_list

    async def checkEndpoint(self, endpoint: str, session: aiohttp.ClientSession) -> Optional[str]:
        """
        Test a single endpoint for GraphQL introspection vulnerability through Burp proxy.

        Args:
            endpoint: The endpoint URL to test
            session: The aiohttp client session to use for requests

        Returns:
            Optional[str]: Endpoint URL if vulnerable, None otherwise
        """
        query = """
        query {
            __schema {
                types {
                    name
                }
            }
        }
        """

        try:
            async with session.post(
                endpoint,
                json={'query': query},
                headers={'Content-Type': 'application/json'},
                timeout=aiohttp.ClientTimeout(total=5),
                proxy=self.proxy_url,
                ssl=False  # Required for Burp to intercept HTTPS
            ) as response:
                if response.status == 200:
                    try:
                        result = await response.json()
                        if result and isinstance(result, dict):
                            if result.get('data', {}).get('__schema'):
                                self.message.printMsg(f"Introspection enabled: {endpoint}", status="warning")
                                return endpoint
                    except (aiohttp.ContentTypeError, ValueError):
                        pass
        except Exception as e:
            self.message.printMsg(f"Error testing {endpoint}: {str(e)}", status="error")
        return None

    async def introspection(self, endpoints: List[str]) -> List[str]:
        """
        Test multiple endpoints for GraphQL introspection vulnerability through Burp proxy.

        Args:
            endpoints: List of endpoints to test

        Returns:
            List[str]: List of vulnerable endpoints with introspection enabled
        """
        print()
        self.message.printMsg("Testing for introspection query", status="success")
        time.sleep(3)
        
        async with aiohttp.ClientSession() as session:
            tasks = [self.checkEndpoint(endpoint, session) for endpoint in endpoints]
            results = await asyncio.gather(*tasks)
        return [endpoint for endpoint in results if endpoint]

    def validate_proxy(self, proxy_host: str, proxy_port: int) -> bool:
        """
        Validate that Burpsuite proxy is accessible.

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
            self.message.printMsg(f"Burp proxy validation failed: {str(e)}", status="error")
            return False
        
    async def test(self, proxy_string: str = None, target_ip: str = None):
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
                    proxy_host, proxy_port_str = proxy_string.split(':')
                    proxy_port = int(proxy_port_str)
                    
                    # Validate and configure proxy
                    if not self.validate_proxy(proxy_host, proxy_port):
                        self.message.printMsg("Cannot connect to proxy. Please ensure proxy is running and settings are correct.", status="error")
                        return []
                        
                    self.configureProxy(proxy_host, proxy_port)
                except ValueError:
                    self.message.printMsg("Invalid proxy string format. Expected format: host:port", status="error")
                    return []
            
            # Perform scan using provided target IP
            valid_endpoints = await self.constructAddress(target_ip)
            url_list = await self.dirbList(valid_endpoints)
            return await self.introspection(url_list)
            
        except Exception as e:
            self.message.printMsg(f"Error during scan: {str(e)}", status="error")
            return []