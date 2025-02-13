#!/usr/bin/env python

"""
Author: Aleksa Zatezalo
Version: 1.0
Date: October 2024
Description: ASCII Art and 'graphics' for GrapeQL. 
"""

import time
import asyncio
import asyncio
import aiohttp

class grapePrint():

    def __init__(self):

        self.PURPLE = '\033[95m'
        self.CYAN = '\033[96m'
        self.DARKCYAN = '\033[36m'
        self.BLUE = '\033[94m'
        self.GREEN = '\033[92m'
        self.YELLOW = '\033[93m'
        self.RED = '\033[91m'
        self.BOLD = '\033[1m'
        self.UNDERLINE = '\033[4m'
        self.END = '\033[0m'

    def printGrapes(self):
        """
        Prints ASCII Grapes in purple color to standard output. 
        """
        
        print(self.PURPLE + self.BOLD +  """
                __
            __ {_/  
        \\_}\\ _
            _\\(_)_  
            (_)_)(_)_
            (_)(_)_)(_)
            (_)(_))_)
            (_(_(_)
            (_)_)
                (_)
        """)

    def printTitle(self):
        """
        Prints title sentance in purple color to standard output. 
        """
        
        print(self.PURPLE + self.BOLD + "GrapeQL Version By Aleksa Zatezalo\n\n" + self.END)

    def printWelcome(self):
        """
        Prints a welcome message in purple color to standard output. 
        """
        
        msg = "Welcome to GrapeQL, the GraphQL vuln scanner.\n"
        print(self.PURPLE +  msg + self.END)

    def printPrompt(self):
        """
        Prints a prompt in purple to standard output.
        """

        print(self.PURPLE +  "\n[GrapeQL] >" + self.END)

    def printMsg(self, message, status="log"):
        """
        Prints various types of logs to standard output.
        """
        
        plus = "[+] "
        exclaim ="[!] "
        fail = "[-] "

        match status:
            case "success":
                print(self.GREEN + plus + message + self.END)
            case "warning":
                print(self.YELLOW + exclaim + message + self.END)
            case "failed":
                print(self.RED + fail + message + self.END)
            case "log":
                print(self.CYAN + exclaim + message + self.END)

    def printNotify(self):
        """
        Prints messages about notifications and logs. 
        """

        time.sleep(0.25)
        print(self.BOLD + "EXAMPLE NOTIFICATIONS: " + self.END)
        time.sleep(0.5)
        self.printMsg("Warnings are printed like this.", status="warning")
        time.sleep(0.5)
        self.printMsg("Errors are printed like this.", status="failed")
        time.sleep(0.5)
        self.printMsg("Good news is printed like this.", status="success")
        time.sleep(0.5)
        self.printMsg("Logs are printed like this.\n", status="log")
        time.sleep(0.5)

    def intro(self):
        """
        Prints the introductory banner and prompt to standard output.
        """
        self.printGrapes()
        self.printTitle()
        self.printWelcome()
        self.printNotify()

#################
#Global Variables#
#################

apiList = ["/graphql", "/graphql/playground", "/graphiql", "/api/explorer", "/graphql/v1", "/graphql/v2", "/graphql/v3", 
           "/api/graphql/v1", "/api/graphql/v2", "/api/public/graphql", "/api/private/graphql", "/admin/graphql", "/user/graphql"]

# Port Scanning Functions

async def testPortNumber(host, port, timeout=1):

    try:
        # Attempt to open a connection with a timeout
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        # Close the connection
        writer.close()
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError):
        return False

    
async def scanPorts(host, task_queue, open_ports):

    message = grapePrint()

    # read tasks forever
    while True:
        # Get a port to scan from the queue
        port = await task_queue.get()
        if port is None:
            # Add the termination signal back for other workers
            await task_queue.put(None)
            task_queue.task_done()
            break
        if await testPortNumber(host, port):
            message.printMsg(f'{host}:{port} [OPEN]')
            open_ports.append(port)
        task_queue.task_done()


async def scanIP(limit=100, host="127.0.0.1"):
    task_queue = asyncio.Queue()
    open_ports = []

    portsToScan=range(1,65535)

    # Start the port scanning coroutines
    workers = [
        asyncio.create_task(scanPorts(host, task_queue, open_ports))
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

async def dirb(session, base_url, path):
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

async def scanEndpoints(base_url):
    """
    Scans all endpoints in api_list asynchronously using dirb.
    Returns a list of valid paths.
    """
    async with aiohttp.ClientSession() as session:
        tasks = [dirb(session, base_url, path) for path in apiList]
        results = await asyncio.gather(*tasks)
    return [result for result in results if result]


def parseUrl():
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

async def constructAddress(ip):
    message = grapePrint()

    print()
    message.printMsg("Beggining Portscan", status="success")
    ports = await scanIP(host=ip)
    valid_endpoits = [] # Constructs a list of ip:port constructions
    for port in ports:
        endpoint = "http://" + ip + ":" + str(port)
        valid_endpoits.append(endpoint)
    return valid_endpoits

async def dirbList(valid_endpoints):
    message = grapePrint()
    print()
    message.printMsg("Beggining Directory Busting", status="success")
    url_list = []
    for endpoint in valid_endpoints:
        list = await scanEndpoints(endpoint)
        for item in list:
            msg = "Found URL at " + item
            message.printMsg(msg)
            url_list.append(item)
    return url_list

async def check_endpoint(endpoint, session):
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
    
    message = grapePrint()

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
                            message.printMsg(f"Introspection enabled: {endpoint}")
                            return endpoint
                except (aiohttp.ContentTypeError, ValueError) as e:
                    print(f"[-] JSON parsing error for {endpoint}: {str(e)}")
                    
    except Exception as e:
        pass
    
    return None

async def test_introspection(endpoints):
    """
    Test multiple GraphQL endpoints for enabled introspection and return vulnerable ones.
    
    Args:
        endpoints: List of GraphQL endpoint URLs to test
        
    Returns:
        List of endpoints where introspection is enabled
    """

    message = grapePrint()
    print()
    message.printMsg("Testing for introspection query", status="success")
    async with aiohttp.ClientSession() as session:
        tasks = [check_endpoint(endpoint, session) for endpoint in endpoints]
        results = await asyncio.gather(*tasks)
        
        return [endpoint for endpoint in results if endpoint]
    
async def main():
    """
    Main function to handle user input and perform both port scanning and endpoint scanning.
    """

    # Get IP and URL from the user
    ip = input("Enter the IP address to scan ports (e.g., 127.0.0.1): ").strip()
    valid_endpoints = await constructAddress(ip)
    url_list = await dirbList(valid_endpoints)
    introspection = await test_introspection(url_list)

# Example usage
if __name__ == "__main__":
    message = grapePrint()
    message.intro()
    asyncio.run(main())
