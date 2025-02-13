"""
Author: Aleksa Zatezalo
Version: 1.0
Date: February 2025
Description: Enumeration script for GraphQL endpoints. Takes an IP and returns a list of endpoints with introspection enabled.
"""

import asyncio
import asyncio
import aiohttp
from grapePrint import grapePrint

class vine():
    
    def __init__(self):
        self.message = grapePrint()
        self.apiList = ["/graphql", "/graphql/playground", "/graphiql", "/api/explorer", "/graphql/v1", "/graphql/v2", "/graphql/v3", 
           "/api/graphql/v1", "/api/graphql/v2", "/api/public/graphql", "/api/private/graphql", "/admin/graphql", "/user/graphql"]


        # Port Scanning Functions

    async def testPortNumber(self, host, port, timeout=1):

        try:
            # Attempt to open a connection with a timeout
            _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
            # Close the connection
            writer.close()
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError):
            return False

    
    async def scanPorts(self, host, task_queue, open_ports):

        # read tasks forever
        while True:
            # Get a port to scan from the queue
            port = await task_queue.get()
            if port is None:
                # Add the termination signal back for other workers
                await task_queue.put(None)
                task_queue.task_done()
                break
            if await self.testPortNumber(self, host, port):
                self.message.printMsg(f'{host}:{port} [OPEN]')
                open_ports.append(port)
            task_queue.task_done()


    async def scanIP(self, limit=100, host="127.0.0.1"):
        task_queue = asyncio.Queue()
        open_ports = []

        portsToScan=range(1,65535)

        # Start the port scanning coroutines
        workers = [
            asyncio.create_task(self.scanPorts(host, task_queue, open_ports))
            for _ in range(limit)
        ]

        # Add ports to the task queue
        for port in portsToScan:
            await task_queue.put(port)

        # Wait for all tasks to be processed
        await task_queue.join()

        # Signal termination to workers
        await task_queue.put(None)
        await asyncio.gather(*workers)

        return open_ports

    # Directory Busting Functions

    async def dirb(self, session, base_url, path):
        """
        Constructs a full URL and scans it for a valid response.
        Returns the path if the URL is accessible (status 200), otherwise None.
        """

        full_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
        try:
            async with session.get(full_url) as response:
                if response.status != 404:
                    return full_url
        except Exception as e:
            # Handle exceptions, e.g., connection errors, invalid URLs
            return None

    async def scanEndpoints(self, base_url):
        """
        Scans all endpoints in api_list asynchronously using dirb.
        Returns a list of valid paths.
        """
        async with aiohttp.ClientSession() as session:
            tasks = [self.dirb(session, base_url, path) for path in self.apiList]
            results = await asyncio.gather(*tasks)
        return [result for result in results if result]


    def parseUrl(self):
        """
        Prompts the user to enter a URL in the form "http://IP:PORT".
        Splits the URL into its components (protocol, IP, and port) and prints the IP and port.
        
        Returns:
            tuple: A tuple containing the protocol (str), IP (str), and port (str).
        """
        url = input("Enter a URL in the format 'http://IP:PORT': ").strip()
        try:
            # Ensure the URL starts with "http://" or "https://"
            if not url.startswith(("http://", "https://")):
                raise ValueError("URL must start with 'http://' or 'https://'")

            # Split the URL into protocol and the remaining part
            protocol, rest = url.split("://")
            
            # Split the remaining part into IP and port
            ip, _ = rest.split(":")
            
            # Print the results
    
            return [url, ip]
        
        except ValueError as e:
            print(f"Invalid input: {e}")
            return None

    async def constructAddress(self, ip):
        
        print()
        self.message.printMsg("Beggining Portscan", status="success")
        ports = await self.scanIP(host=ip)
        valid_endpoits = [] # Constructs a list of ip:port constructions
        for port in ports:
            endpoint = "http://" + ip + ":" + str(port)
            valid_endpoits.append(endpoint)
        return valid_endpoits

    async def dirbList(self, valid_endpoints):
        print()
        self.message.printMsg("Beggining Directory Busting", status="success")
        url_list = []
        for endpoint in valid_endpoints:
            list = await self.scanEndpoints(endpoint)
            for item in list:
                msg = "Found URL at " + item
                self.message.printMsg(msg)
                url_list.append(item)
        return url_list

    async def check_endpoint(self, endpoint, session):
        """
        Check a single GraphQL endpoint for enabled introspection.
        
        Args:
            endpoint: GraphQL endpoint URL to test
            session: Shared aiohttp client session
            
        Returns:
            endpoint URL if introspection is enabled, None otherwise
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
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                if response.status == 200:
                    try:
                        result = await response.json()
                        if result and isinstance(result, dict):
                            if result.get('data', {}).get('__schema'):
                                self.message.printMsg(f"Introspection enabled: {endpoint}", status="warning")
                                return endpoint
                    except (aiohttp.ContentTypeError, ValueError) as e:
                        print(f"[-] JSON parsing error for {endpoint}: {str(e)}")
                        
        except Exception as e:
            pass
        
        return None

    async def test_introspection(self, endpoints):
        """
        Test multiple GraphQL endpoints for enabled introspection and return vulnerable ones.
        
        Args:
            endpoints: List of GraphQL endpoint URLs to test
            
        Returns:
            List of endpoints where introspection is enabled
        """

        print()
        self.message.printMsg("Testing for introspection query", status="success")
        async with aiohttp.ClientSession() as session:
            tasks = [self.check_endpoint(endpoint, session) for endpoint in endpoints]
            results = await asyncio.gather(*tasks)
            
            return [endpoint for endpoint in results if endpoint]
        
    async def test(self):
        """
        Main function to handle user input and perform both port scanning and endpoint scanning.
        """

        # Get IP and URL from the user
        self.message.intro()
        ip = input("Enter the IP address to scan ports (e.g., 127.0.0.1): ").strip()
        valid_endpoints = await self.constructAddress(ip)
        url_list = await self.dirbList(valid_endpoints)
        introspection = await self.test_introspection(url_list)
        return introspection

# Example usage
if __name__ == "__main__":
    test = vine()
    asyncio.run(test.test())
