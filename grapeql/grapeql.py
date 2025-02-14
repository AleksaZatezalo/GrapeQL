#!/usr/bin/env python

"""
Author: Aleksa Zatezalo
Version: 1.1
Date: February 2025
Description: Main file for GrapeQL with command-line argument support
"""

import asyncio
import argparse
from vine import vine

async def main():
    """
    Main function to handle command-line arguments and perform graphql scanning.
    """
    parser = argparse.ArgumentParser(
        description='GraphQL Endpoint Scanner with Proxy Support',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '-t', '--target',
        required=True,
        help='Target IP address to scan'
    )
    
    parser.add_argument(
        '-p', '--proxy',
        required=True,
        help='Proxy address in format host:port (e.g., 127.0.0.1:8080)'
    )

    args = parser.parse_args()
    
    try:
        scanner = vine()
        introspection = await scanner.test(args.proxy, args.target)  
            
    except Exception as e:
        print(f"Error during scan: {str(e)}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code)