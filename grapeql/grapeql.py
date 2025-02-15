"""
Author: Aleksa Zatezalo
Version: 1.3
Date: February 2025
Description: Main file for GrapeQL with command-line argument support and direct API testing
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
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error loading wordlist: {str(e)}")
        return None

async def test_single_endpoint(scanner: vine, api_url: str, proxy: str) -> int:
    """
    Test a single API endpoint for GraphQL introspection.
    
    Args:
        scanner: Initialized vine scanner
        api_url: Full URL of the API endpoint to test
        proxy: Proxy address in host:port format
        
    Returns:
        int: Exit code (0 for success, 1 for failure)
    """
    try:
        # Configure proxy
        proxy_host, proxy_port = proxy.split(':')
        scanner.configure_proxy(proxy_host, int(proxy_port))
        
        # Test single endpoint
        vulnerable = await scanner.introspection([api_url])
        
        if vulnerable:
            print("\nVulnerable endpoint found:")
            print(f"- {vulnerable[0]}")
        else:
            print("\nEndpoint is not vulnerable to introspection.")
            
        return 0
        
    except Exception as e:
        print(f"Error testing endpoint: {str(e)}")
        return 1

async def main():
    """
    Main function to handle command-line arguments and perform graphql scanning.
    """
    parser = argparse.ArgumentParser(
        description='GraphQL Endpoint Scanner with Proxy Support',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Create mutually exclusive group for target IP vs direct API
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        '-t', '--target',
        help='Target IP address to scan'
    )
    target_group.add_argument(
        '--api',
        help='Direct URL to test for GraphQL introspection (bypasses port scanning and directory busting)'
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
        
        # Direct API endpoint testing
        if args.api:
            return await test_single_endpoint(scanner, args.api, args.proxy)
            
        # Full scan mode
        else:
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