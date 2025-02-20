"""
Author: Aleksa Zatezalo
Version: 1.4
Date: February 2025
Description: Main file for GrapeQL with command-line argument support and enhanced DoS testing
"""

import asyncio
import argparse
import time
from vine import vine
from root import root
from crush import crush
from seeds import seeds
from juice import juice
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
        with open(wordlist_path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error loading wordlist: {str(e)}")
        return None


async def runFingerprinting(endpoint: str, proxy: str = None) -> dict:
    """
    Run fingerprinting using the root class.

    Args:
        endpoint: The GraphQL endpoint to fingerprint
        proxy: Optional proxy string in host:port format

    Returns:
        dict: Information about the detected engine
    """

    fingerprinter = root()

    try:
        # Set endpoint and run introspection
        if await fingerprinter.setEndpoint(endpoint, proxy):
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


async def testSingleEndpoint(scanner, api_url, proxy, message):
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
            proxy_host, proxy_port = proxy.split(":")
            scanner.configureProxy(proxy_host, int(proxy_port))

        # Test single endpoint
        vulnerable = await scanner.introspection([api_url])

        if vulnerable:
            return vulnerable
        return 0

    except Exception as e:
        print(f"Error testing endpoint: {str(e)}")
        return 1


async def runDosTests(endpoint: str, proxy: str = None, use_crush: bool = False):
    """
    Run DoS testing using either root or crush class based on the argument.

    Args:
        endpoint: The GraphQL endpoint to test
        proxy: Optional proxy string in host:port format
        use_crush: Boolean flag to determine whether to use crush instead of root
    """

    message = grapePrint()

    if use_crush:
        dos_tester = crush()

    # Set the endpoint and get schema
    if await dos_tester.setEndpoint(endpoint, proxy):
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
    default="admin"
    )

    parser.add_argument(
        "-pw", 
        "--password",
        help="Password to use for testing (default: changeme)",
        default="changeme"
    )

    args = parser.parse_args()

    try:
        scanner = vine()
        seed = seeds()
        juicey = juice()
        message = grapePrint()

        message.intro()

        juicey.setCredentials(args.username, args.password)
    
        # Direct API endpoint testing
        if args.api:
            introspection = await testSingleEndpoint(
                scanner, args.api, args.proxy, message
            )

        # Full scan mode
        else:
            # Load custom wordlist if specified
            if args.wordlist:
                wordlist = loadWordlist(args.wordlist)
                if wordlist is None:
                    return 1
                scanner.setApiList(wordlist)

            # Call test with None for proxy if not provided
            introspection = await scanner.test(
                args.proxy if args.proxy else None, args.target
            )

        if introspection:
            time.sleep(2)
            await runFingerprinting(
                endpoint=introspection[0], proxy=args.proxy if args.proxy else None
            )

            time.sleep(2)
            await seed.setEndpoint(introspection[0], proxy=args.proxy if args.proxy else None)
            await seed.runAllChecks()

            await juicey.setEndpoint(introspection[0], proxy=args.proxy if args.proxy else None)    
            await juicey.scanForInjection()    

            if args.crush:
                await runDosTests(
                    endpoint=introspection[0],
                    proxy=args.proxy if args.proxy else None,
                    use_crush=True,
                )

    except Exception as e:
        print(f"Error during scan: {str(e)}")
        return 1

    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code)
