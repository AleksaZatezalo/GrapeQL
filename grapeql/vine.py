"""
Author: Aleksa Zatezalo
Version: 1.0
Date: February 2025
Description: Enumeration script for GraphQL endpoints. Takes an IP and returns a list of endpoints with introspection enabled.
"""

import asyncio
import aiohttp
from typing import List
from grapePrint import grapePrint
import time
class vine():
    """
    A class for scanning and identifying GraphQL endpoints with introspection enabled.
    
    This class provides functionality for port scanning, directory enumeration,
    and testing GraphQL endpoints for introspection vulnerabilities.
    """
    
    def __init__(self):
        """
        Initialize the vine class with default settings and API endpoints list.
        """
        
        self.message = grapePrint()
        self.apiList = ["/graphql", "/graphql/playground", "/graphiql", "/api/explorer", "/graphql/v1", "/graphql/v2", "/graphql/v3", 
           "/api/graphql/v1", "/api/graphql/v2", "/api/public/graphql", "/api/private/graphql", "/admin/graphql", "/user/graphql"]
        
    def setApiList(self, list):
        """
        Set a custom list of API endpoints to scan.

        Args:
            list: A list of strings representing API endpoint paths to scan
        """

        self.apiList = list

    async def testPortNumber(self, host: str, port: int) -> bool:
        """
        Test if a specific port is open on the target host.

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
        Scan a range of ports concurrently on the target host.

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
        
        # Run port checks concurrently
        results = await asyncio.gather(*tasks)
        
        # Collect open ports
        open_ports = []
        for port, is_open in zip(range(start_port, end_port + 1), results):
            if is_open:
                self.message.printMsg(f'{host}:{port} [OPEN]')
                open_ports.append(port)
        
        return open_ports

    async def scanIP(self, host: str = "127.0.0.1") -> List[int]:
        """
        Scan all ports on a target host in chunks.

        Args:
            host: The target hostname or IP address (default: "127.0.0.1")

        Returns:
            List[int]: Sorted list of all open ports found on the host
        """

        chunk_size = 1000
        open_ports = []
        
        # Scan ports in chunks to avoid overwhelming the system
        for start_port in range(1, 65536, chunk_size):
            end_port = min(start_port + chunk_size - 1, 65535)
            chunk_results = await self.scanPortRange(host, start_port, end_port)
            open_ports.extend(chunk_results)
        
        return sorted(open_ports)

    # Rest of your code remains the same...

    async def dirb(self, session: aiohttp.ClientSession, base_url: str, path: str) -> str | None:
        """
        Test a single endpoint path for existence on the target URL.

        Args:
            session: The aiohttp client session to use for requests
            base_url: The base URL to test against
            path: The endpoint path to append to the base URL

        Returns:
            str | None: Full URL if endpoint exists, None otherwise
        """

        full_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
        try:
            async with session.get(full_url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                if response.status != 404:
                    return full_url
        except Exception:
            return None

    async def scanEndpoints(self, base_url: str) -> List[str]:
        """
        Scan all API endpoints concurrently on a given base URL.

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
        self.message.printMsg("Beginning Portscan", status="success")
        time.sleep(3)
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
        
        print()
        self.message.printMsg("Beginning Directory Busting", status="success")
        time.sleep(3)
        url_list = []
        for endpoint in valid_endpoints:
            found_urls = await self.scanEndpoints(endpoint)
            for url in found_urls:
                self.message.printMsg(f"Found URL at {url}")
                url_list.append(url)
        return url_list

    async def checkEndpoint(self, endpoint: str, session: aiohttp.ClientSession) -> str | None:
        """
        Test a single endpoint for GraphQL introspection vulnerability.

        Args:
            endpoint: The endpoint URL to test
            session: The aiohttp client session to use for requests

        Returns:
            str | None: Endpoint URL if vulnerable, None otherwise
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
                timeout=aiohttp.ClientTimeout(total=5)
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
        except Exception:
            pass
        return None

    async def introspection(self, endpoints: List[str]) -> List[str]:
        """
        Test multiple endpoints for GraphQL introspection vulnerability.

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
        
    async def test(self):
        """
        Main execution function that coordinates the scanning process.

        Returns:
            List[str]: List of vulnerable GraphQL endpoints found
        """

        self.message.intro()
        ip = input("Enter the IP address to scan ports (e.g., 127.0.0.1): ").strip()
        valid_endpoints = await self.constructAddress(ip)
        url_list = await self.dirbList(valid_endpoints)
        return await self.introspection(url_list)