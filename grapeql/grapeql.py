#!/usr/bin/env python

"""
Author: Aleksa Zatezalo
Version: 1.2
Date: February 2025
Description: Main file for GrapeQL with command-line argument support and custom wordlist
"""

import asyncio
import argparse
from vine import vine

def load_wordlist(wordlist_path):
    """
    Load endpoints from a wordlist file.
    
    Args:
        wordlist_path: Path to the wordlist file
        
    Returns:
        list: List of endpoints from the file
    """
    try:
        with open(wordlist_path, 'r') as f:
            # Strip whitespace and empty lines
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error loading wordlist: {str(e)}")
        return None

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
    
    parser.add_argument(
        '-w', '--wordlist',
        help='Path to custom wordlist file containing GraphQL endpoints (one per line)'
    )

    args = parser.parse_args()
    
    try:
        scanner = vine()
        
        # Load custom wordlist if specified
        if args.wordlist:
            wordlist = load_wordlist(args.wordlist)
            if wordlist is None:
                return 1
            scanner.setApiList(wordlist)
            
        introspection = await scanner.test(args.proxy, args.target)
        
        if introspection:
            print("\nVulnerable endpoints found:")
            for endpoint in introspection:
                print(f"- {endpoint}")
        else:
            print("\nNo vulnerable endpoints found.")
            
    except Exception as e:
        print(f"Error during scan: {str(e)}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code)