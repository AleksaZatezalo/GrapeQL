#!/usr/bin/env python

"""
Author: Aleksa Zatezalo
Version: 1.0
Date: October 2024
Description: ASCII Art and 'graphics' for GrapeQL. 
"""

import time
import asyncio
import requests
import asyncio
from aiohttp import ClientSession
import aiohttp

class color:
   PURPLE = '\033[95m'
   CYAN = '\033[96m'
   DARKCYAN = '\033[36m'
   BLUE = '\033[94m'
   GREEN = '\033[92m'
   YELLOW = '\033[93m'
   RED = '\033[91m'
   BOLD = '\033[1m'
   UNDERLINE = '\033[4m'
   END = '\033[0m'

def printGrapes():
    """
    Prints ASCII Grapes in purple color to standard output. 
    """
    
    print(color.PURPLE + color.BOLD +  """
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

def printTitle():
    """
    Prints title sentance in purple color to standard output. 
    """
    
    print(color.PURPLE + color.BOLD + "GrapeQL Version By Aleksa Zatezalo\n\n" + color.END)

def printWelcome():
    """
    Prints a welcome message in purple color to standard output. 
    """
    
    msg = "Welcome to GrapeQL, the GraphQL vuln scanner.\n"
    print(color.PURPLE +  msg + color.END)

def printPrompt():
    """
    Prints a prompt in purple to standard output.
    """
    print(color.PURPLE +  "\n[GrapeQL] >" + color.END)

def printMsg(message, status="log"):
    """
    Prints various types of logs to standard output.
    """
    
    plus = "[+] "
    exclaim ="[!] "
    fail = "[-] "

    match status:
        case "success":
            print(color.GREEN + plus + message + color.END)
        case "warning":
            print(color.YELLOW + exclaim + message + color.END)
        case "failed":
            print(color.RED + fail + message + color.END)
        case "log":
            print(color.CYAN + exclaim + message + color.END)

def printNotify():
    """
    Prints messages about notifications and logs. 
    """

    time.sleep(0.25)
    print(color.BOLD + "EXAMPLE NOTIFICATIONS: " + color.END)
    time.sleep(0.5)
    printMsg("Warnings are printed like this.", status="warning")
    time.sleep(0.5)
    printMsg("Errors are printed like this.", status="failed")
    time.sleep(0.5)
    printMsg("Good news is printed like this.", status="success")
    time.sleep(0.5)
    printMsg("Logs are printed like this.\n", status="log")
    time.sleep(0.5)

def intro():
    """
    Prints the introductory banner and prompt to standard output.
    """
    printGrapes()
    printTitle()
    printWelcome()
    printNotify()

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
            printMsg(f'{host}:{port} [OPEN]')
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
    async with ClientSession() as session:
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
    print()
    printMsg("Beggining Portscan", status="success")
    ports = await scanIP(host=ip)
    valid_endpoits = [] # Constructs a list of ip:port constructions
    for port in ports:
        endpoint = "http://" + ip + ":" + str(port)
        valid_endpoits.append(endpoint)
    return valid_endpoits

async def dirbList(valid_endpoints):
    print()
    printMsg("Beggining Directory Busting", status="success")
    url_list = []
    for endpoint in valid_endpoints:
        list = await scanEndpoints(endpoint)
        for item in list:
            msg = "Found URL at " + item
            printMsg(msg)
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
                            printMsg(f"Introspection enabled: {endpoint}")
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

    print()
    printMsg("Testing for introspection query", status="success")
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
    intro()
    asyncio.run(main())
