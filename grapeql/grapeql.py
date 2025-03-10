"""
Author: Aleksa Zatezalo
Version: 1.4
Date: February 2025
Description: Main file for GrapeQL with command-line argument support and enhanced DoS testing
"""

import asyncio
import argparse
import time
import json
from .vine import vine
from .root import root
from .crush import crush
from .seeds import seeds
from .juice import juice
from .grapePrint import grapePrint


def loadWordlist(wordlist_path):
    """
    Load endpoints from a wordlist file.

    Args:
        wordlist_path: Path to the wordlist file

    Returns:
        list: List of endpoints from the file
    """

    try:
        with open(wordlist_path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error loading wordlist: {str(e)}")
        return None


def load_json_file(file_path):
    """
    Load JSON data from a file.

    Args:
        file_path: Path to the JSON file

    Returns:
        dict: Parsed JSON data or None if error
    """
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading JSON file {file_path}: {str(e)}")
        return None


async def runFingerprinting(endpoint: str, proxy: str = None, headers=None, cookies=None) -> dict:
    """
    Run fingerprinting using the root class.

    Args:
        endpoint: The GraphQL endpoint to fingerprint
        proxy: Optional proxy string in host:port format
        headers: Optional dictionary of custom headers
        cookies: Optional dictionary of cookies

    Returns:
        dict: Information about the detected engine
    """

    fingerprinter = root()

    try:
        # Set endpoint and run introspection
        if await fingerprinter.setEndpoint(endpoint, proxy):
            # Set custom headers and cookies if provided
            if headers:
                fingerprinter.set_headers(headers)
            if cookies:
                fingerprinter.set_cookies(cookies)
                
            # Run fingerprinting
            engine_id = await fingerprinter.fingerprintEngine()
            return engine_id

    except Exception as e:
        print(f"Error during fingerprinting: {str(e)}")
        return {
            "engine": None,
            "schema_available": False,
            "endpoint": endpoint,
            "error": str(e),
        }


async def testSingleEndpoint(scanner, api_url, proxy, message, headers=None, cookies=None):
    """
    Test a single API endpoint for GraphQL introspection.

    Args:
        scanner: Initialized vine scanner
        api_url: Full URL of the API endpoint to test
        proxy: Optional proxy address in host:port format
        message: Printer instance
        headers: Optional dictionary of custom headers
        cookies: Optional dictionary of cookies

    Returns:
        int: Exit code (0 for success, 1 for failure)
    """

    try:
        # Configure proxy if provided
        if proxy:
            proxy_host, proxy_port = proxy.split(":")
            scanner.configureProxy(proxy_host, int(proxy_port))
            
        # Set custom headers and cookies if provided
        if headers:
            scanner.set_headers(headers)
        if cookies:
            scanner.set_cookies(cookies)

        # Test single endpoint
        vulnerable = await scanner.introspection([api_url])

        if vulnerable:
            return vulnerable
        return 0

    except Exception as e:
        print(f"Error testing endpoint: {str(e)}")
        return 1


async def runDosTests(endpoint: str, proxy: str = None, use_crush: bool = False, headers=None, cookies=None):
    """
    Run DoS testing using either root or crush class based on the argument.

    Args:
        endpoint: The GraphQL endpoint to test
        proxy: Optional proxy string in host:port format
        use_crush: Boolean flag to determine whether to use crush instead of root
        headers: Optional dictionary of custom headers
        cookies: Optional dictionary of cookies
    """

    message = grapePrint()

    if use_crush:
        dos_tester = crush()

    # Set the endpoint and get schema
    if await dos_tester.setEndpoint(endpoint, proxy):
        # Set custom headers and cookies if provided
        if headers:
            dos_tester.set_headers(headers)
        if cookies:
            dos_tester.set_cookies(cookies)
            
        await dos_tester.testEndpointDos()
    else:
        message.printMsg("Failed to set endpoint or retrieve schema", status="failed")


async def main():
    """
    Main function to handle command-line arguments and perform graphql scanning.
    """

    parser = argparse.ArgumentParser(
        description="GraphQL Endpoint Scanner with Optional Proxy Support",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Create mutually exclusive group for target IP vs direct API
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-t", "--target", help="Target IP address to scan")
    target_group.add_argument(
        "--api",
        help="Direct URL to test for GraphQL introspection (bypasses port scanning and directory busting)",
    )

    parser.add_argument(
        "-p",
        "--proxy",
        help="Optional proxy address in format host:port (e.g., 127.0.0.1:8080)",
    )

    parser.add_argument(
        "-c", "--crush", action="store_true", help="Flag for DoS testing"
    )

    parser.add_argument(
        "-w",
        "--wordlist",
        help="Path to custom wordlist file containing GrapQL API endpoints",
    )

    parser.add_argument(
        "-u",
        "--username",
        help="Username to use for testing (default: admin)",
        default="admin",
    )

    parser.add_argument(
        "-pw",
        "--password",
        help="Password to use for testing (default: changeme)",
        default="changeme",
    )
    
    # New arguments for headers and cookies
    parser.add_argument(
        "--header",
        action="append",
        help="Custom header in format 'name:value'. Can be specified multiple times.",
        dest="headers"
    )
    
    parser.add_argument(
        "--headers-file",
        help="Path to JSON file containing custom headers",
    )
    
    parser.add_argument(
        "--cookie",
        action="append",
        help="Cookie in format 'name:value'. Can be specified multiple times.",
        dest="cookies"
    )
    
    parser.add_argument(
        "--cookies-file",
        help="Path to JSON file containing cookies",
    )
    
    parser.add_argument(
        "--auth",
        help="Authorization token to include in requests",
    )
    
    parser.add_argument(
        "--auth-type",
        help="Authorization token type (e.g., Bearer, Basic). Default is Bearer.",
        default="Bearer"
    )

    args = parser.parse_args()

    try:
        scanner = vine()
        seed = seeds()
        juicey = juice()
        message = grapePrint()

        message.intro()
        
        # Process headers from command line arguments
        headers = {}
        if args.headers:
            for header in args.headers:
                try:
                    name, value = header.split(':', 1)
                    headers[name.strip()] = value.strip()
                except ValueError:
                    message.printMsg(f"Invalid header format: {header}. Expected 'name:value'", status="error")
        
        # Load headers from file if specified
        if args.headers_file:
            file_headers = load_json_file(args.headers_file)
            if file_headers:
                headers.update(file_headers)
        
        # Process cookies from command line arguments
        cookies = {}
        if args.cookies:
            for cookie in args.cookies:
                try:
                    name, value = cookie.split(':', 1)
                    cookies[name.strip()] = value.strip()
                except ValueError:
                    message.printMsg(f"Invalid cookie format: {cookie}. Expected 'name:value'", status="error")
        
        # Load cookies from file if specified
        if args.cookies_file:
            file_cookies = load_json_file(args.cookies_file)
            if file_cookies:
                cookies.update(file_cookies)
        
        # Set authentication token if provided
        if args.auth:
            headers['Authorization'] = f"{args.auth_type} {args.auth}" if args.auth_type else args.auth

        juicey.setCredentials(args.username, args.password)
        
        # Set custom headers and cookies
        if headers:
            juicey.set_headers(headers)
            # message.printMsg(f"Using {len(headers)} custom headers", status="success")
        
        if cookies:
            juicey.set_cookies(cookies)
            # message.printMsg(f"Using {len(cookies)} cookies", status="success")

        # Direct API endpoint testing
        if args.api:
            introspection = await testSingleEndpoint(
                scanner, args.api, args.proxy, message, headers, cookies
            )

        # Full scan mode
        else:
            # Load custom wordlist if specified
            if args.wordlist:
                wordlist = loadWordlist(args.wordlist)
                if wordlist is None:
                    return 1
                scanner.setApiList(wordlist)
                
            # Set custom headers and cookies
            if headers:
                scanner.set_headers(headers)
            
            if cookies:
                scanner.set_cookies(cookies)

            # Call test with None for proxy if not provided
            introspection = await scanner.test(
                args.proxy if args.proxy else None, args.target
            )

        if introspection:
            time.sleep(2)
            await runFingerprinting(
                endpoint=introspection[0], 
                proxy=args.proxy if args.proxy else None,
                headers=headers,
                cookies=cookies
            )

            time.sleep(2)
            await seed.setEndpoint(
                introspection[0], proxy=args.proxy if args.proxy else None
            )
            
            # Set custom headers and cookies for seeds
            if headers:
                seed.set_headers(headers)
            
            if cookies:
                seed.set_cookies(cookies)
                
            await seed.runAllChecks()

            await juicey.setEndpoint(
                introspection[0], proxy=args.proxy if args.proxy else None
            )

            await juicey.scanForInjection()

            if args.crush:
                await runDosTests(
                    endpoint=introspection[0],
                    proxy=args.proxy if args.proxy else None,
                    use_crush=True,
                    headers=headers,
                    cookies=cookies
                )

    except Exception as e:
        print(f"Error during scan: {str(e)}")
        return 1

    return 0


def run_cli():
    """
    Entry point for the command-line interface.
    """
    exit_code = asyncio.run(main())
    exit(exit_code)


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code)