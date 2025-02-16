"""
Author: Aleksa Zatezalo
Version: 1.3
Date: February 2025
Description: Main file for GrapeQL with command-line argument support and direct API testing
"""
import asyncio
import argparse
from vine import vine
from root import root
from grapePrint import grapePrint

def loadWordlist(wordlist_path):
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

async def testSingleEndpoint(scanner: vine, api_url: str, proxy: str = None) -> int:
    """
    Test a single API endpoint for GraphQL introspection.
    
    Args:
        scanner: Initialized vine scanner
        api_url: Full URL of the API endpoint to test
        proxy: Optional proxy address in host:port format
        
    Returns:
        int: Exit code (0 for success, 1 for failure)
    """
    try:
        # Configure proxy if provided
        if proxy:
            proxy_host, proxy_port = proxy.split(':')
            scanner.configure_proxy(proxy_host, int(proxy_port))
        
        # Test single endpoint
        vulnerable = await scanner.introspection([api_url])
        
        if vulnerable:
            return vulnerable
        return 0
        
    except Exception as e:
        print(f"Error testing endpoint: {str(e)}")
        return 1

async def main():
    """
    Main function to handle command-line arguments and perform graphql scanning.
    """
    parser = argparse.ArgumentParser(
        description='GraphQL Endpoint Scanner with Optional Proxy Support',
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
        help='Optional proxy address in format host:port (e.g., 127.0.0.1:8080)'
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
            message = grapePrint()
            message.intro()
            introspection = await testSingleEndpoint(scanner, args.api, args.proxy)
            
        # Full scan mode
        else:
            # Load custom wordlist if specified
            if args.wordlist:
                wordlist = loadWordlist(args.wordlist)
                if wordlist is None:
                    return 1
                scanner.setApiList(wordlist)
                
            # Call test with None for proxy if not provided
            introspection = await scanner.test(args.proxy if args.proxy else None, args.target)
        
        if introspection:            
            dos_tester = root()
            # First set the endpoint and get schema
            if await dos_tester.setEndpoint(introspection[0], args.proxy if args.proxy else None):
                await dos_tester.test_endpoint_dos()
            else:
                print("Failed to set endpoint or retrieve schema")
            
    except Exception as e:
        print(f"Error during scan: {str(e)}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code)

