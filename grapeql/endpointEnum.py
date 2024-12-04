#!/usr/bin/env python

"""
Author: Aleksa Zatezalo
Version: 1.0
Date: October 2024
Description: A simple implementation of dirbuster.
"""

import requests
import asyncio
from aiohttp import ClientSession

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
            print(f'{host}:{port} [OPEN]')
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