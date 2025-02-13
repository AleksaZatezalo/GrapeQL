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

class vine():
    
    def __init__(self):
        self.message = grapePrint()
        self.apiList = ["/graphql", "/graphql/playground", "/graphiql", "/api/explorer", "/graphql/v1", "/graphql/v2", "/graphql/v3", 
           "/api/graphql/v1", "/api/graphql/v2", "/api/public/graphql", "/api/private/graphql", "/admin/graphql", "/user/graphql"]
        
    def setApiList(self, list):
        self.apiList = list

    async def testPortNumber(self, host: str, port: int) -> bool:
        """Test single port with short timeout"""
        try:
            future = asyncio.open_connection(host, port)
            _, writer = await asyncio.wait_for(future, timeout=0.5)
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False

    async def scanPortRange(self, host: str, start_port: int, end_port: int) -> List[int]:
        """Scan a range of ports concurrently"""
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
        """Scan all ports in chunks"""
        chunk_size = 1000
        open_ports = []
        
        # Scan ports in chunks to avoid overwhelming the system
        for start_port in range(1, 65536, chunk_size):
            end_port = min(start_port + chunk_size - 1, 65535)
            chunk_results = await self.scan_port_range(host, start_port, end_port)
            open_ports.extend(chunk_results)
        
        return sorted(open_ports)

    # Rest of your code remains the same...

    async def dirb(self, session: aiohttp.ClientSession, base_url: str, path: str) -> str | None:
        full_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
        try:
            async with session.get(full_url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                if response.status != 404:
                    return full_url
        except Exception:
            return None

    async def scanEndpoints(self, base_url: str) -> List[str]:
        async with aiohttp.ClientSession() as session:
            tasks = [self.dirb(session, base_url, path) for path in self.apiList]
            results = await asyncio.gather(*tasks)
        return [result for result in results if result]

    async def constructAddress(self, ip: str) -> List[str]:
        print()
        self.message.printMsg("Beginning Portscan", status="success")
        ports = await self.scanIP(host=ip)
        return [f"http://{ip}:{port}" for port in ports]

    async def dirbList(self, valid_endpoints: List[str]) -> List[str]:
        print()
        self.message.printMsg("Beginning Directory Busting", status="success")
        url_list = []
        for endpoint in valid_endpoints:
            found_urls = await self.scanEndpoints(endpoint)
            for url in found_urls:
                self.message.printMsg(f"Found URL at {url}")
                url_list.append(url)
        return url_list

    async def checkEndpoint(self, endpoint: str, session: aiohttp.ClientSession) -> str | None:
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
        print()
        self.message.printMsg("Testing for introspection query", status="success")
        async with aiohttp.ClientSession() as session:
            tasks = [self.check_endpoint(endpoint, session) for endpoint in endpoints]
            results = await asyncio.gather(*tasks)
        return [endpoint for endpoint in results if endpoint]
        
    async def test(self):
        self.message.intro()
        ip = input("Enter the IP address to scan ports (e.g., 127.0.0.1): ").strip()
        valid_endpoints = await self.constructAddress(ip)
        url_list = await self.dirbList(valid_endpoints)
        return await self.test_introspection(url_list)

if __name__ == "__main__":
    test = vine()
    asyncio.run(test.test())