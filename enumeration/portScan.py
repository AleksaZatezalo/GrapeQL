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

async def test_port_number(host, port, timeout=3):
    coro = asyncio.open_connection(host, port)

    try:
        _, writer = await asyncio.wait_for(coro, timeout)
        writer.close()
        return True
    except asyncio.TimeoutError:
        return False
    
async def main(host, ports):
    print(f'Scanning {host}...')
    coros = [test_port_number(host, port) for port in ports]
    results = await asyncio.gather(*coros)
    for port, result in zip(ports, results):
        if result :
            print(f'> {host}:{port} [OPEN]')


# define a host and ports to scan
host = 'python.org'
ports = range(1, 1024)
# start the asyncio program
asyncio.run(main(host, ports))