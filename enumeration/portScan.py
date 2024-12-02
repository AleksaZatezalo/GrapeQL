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

async def testPort(host, port, timeout=3):
    """
    Asyncronus function that takes a string representing a host, host,
    an integer representing a port, port, and an int representing timeout.
    It connects to a port and returns a bool representing if it is open.
    """

    coro = asyncio.open_connection(host, port)
    try:
        _, writer = await asyncio.wait_for(coro, timeout)
        writer.close()
        return True
    except:
        return False
    
async def portScan(host, ports):
    """
    Asyncronus function that takes a string representing a host, host,
    an array of integers representing a list of ports, ports.
    It returns an array of open ports from the list ports, on host.
    """
    
    print(f'Scanning {host}...')
    items = []
    coros = [testPort(host, port) for port in ports]
    results = await asyncio.gather(*coros)
    for port, result in zip(ports, results):
        if result :
            items.append(f'{host}:{port} [OPEN]')
    return items


# async def main():
#     host = "195.177.199.39"  # Replace with the target host
#     port_range = (0, 65535)  # Example range of ports
#     open_ports = await portScan(host, port_range)
#     time.sleep(2)
#     print(open_ports)

# # Run the main function
# if __name__ == "__main__":
#     asyncio.run(main())