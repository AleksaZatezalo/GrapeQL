#!/usr/bin/env python

"""
Author: Aleksa Zatezalo
Version: 1.0
Date: October 2024
Description: An async tcp port scanner.
"""

import sys
import socket
import asyncio
import time

async def test_port_number(host, port, timeout=1):

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
        if await test_port_number(host, port):
            print(f'{host}:{port} [OPEN]')
            open_ports.append(port)
        task_queue.task_done()


async def scanIP(limit=100, host="127.0.0.1", portsToScan=[21, 22, 80, 139, 443, 445, 3000, 4000, 8000, 8080]):
    task_queue = asyncio.Queue()
    open_ports = []

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


async def main():
    """
    Main function to take user input for IP address and scan ports.
    """

    # # Get IP address from the user
    ip = input("Enter the target IP address: ")
    print("\nScanning for open ports.")
    openPorts = await scanIP(host=ip)

# Run the script
if __name__ == "__main__":
    asyncio.run(main())