"""
Author: Aleksa Zatezalo
Version: 2.4
Date: March 2025
Description: Fixed main file for GrapeQL with proper session handling
"""

import asyncio
import argparse
import time
import json
from typing import Dict, List, Optional, Any

from .vine import vine
from .root import root
from .crush import crush
from .seeds import seeds
from .juice import juice
from .grapePrint import grapePrint
from .http_client import GraphQLClient
from .schema_manager import SchemaManager


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


async def runFingerprinting(endpoint: str, proxy: str = None, headers=None, cookies=None) -> Dict:
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
    message = grapePrint()

    try:
        # Set endpoint and run introspection
        if await fingerprinter.set_endpoint(endpoint, proxy):
            # Set custom headers and cookies if provided
            if headers:
                fingerprinter.set_headers(headers)
            if cookies:
                fingerprinter.set_cookies(cookies)
                
            # Run fingerprinting
            engine_info = await fingerprinter.fingerprintEngine()
            
            if engine_info:
                message.printMsg(f"Detected {engine_info['name']} GraphQL implementation", status="success")
                if "technology" in engine_info:
                    message.printMsg(f"Technology stack: {', '.join(engine_info['technology'])}", status="success")
                message.printMsg(f"Reference: {engine_info['url']}", status="success")
            
            # Ensure we close the client session
            await fingerprinter.close()
            return engine_info

    except Exception as e:
        message.printMsg(f"Error during fingerprinting: {str(e)}", status="error")
        # Ensure we close the client session even if there's an error
        await fingerprinter.close()
        return {
            "name": "unknown",
            "url": "",
            "engine_id": None,
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
        list: List of vulnerable endpoints or empty list
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
        return vulnerable

    except Exception as e:
        message.printMsg(f"Error testing endpoint: {str(e)}", status="error")
        return []


async def runDosTests(endpoint: str, proxy: str = None, headers=None, cookies=None):
    """
    Run DoS testing using crush class.

    Args:
        endpoint: The GraphQL endpoint to test
        proxy: Optional proxy string in host:port format
        headers: Optional dictionary of custom headers
        cookies: Optional dictionary of cookies
    """
    message = grapePrint()
    dos_tester = crush()

    try:
        # Set the endpoint and get schema
        if await dos_tester.set_endpoint(endpoint, proxy):
            # Set custom headers and cookies if provided
            if headers:
                dos_tester.set_headers(headers)
            if cookies:
                dos_tester.set_cookies(cookies)
                
            await dos_tester.testEndpointDos()
        else:
            message.printMsg("Failed to set endpoint or retrieve schema", status="failed")
    finally:
        # Ensure we close the session
        await dos_tester.close()


async def run_security_checks(endpoint: str, proxy: str = None, headers=None, cookies=None, username=None, password=None):
    """
    Run all security checks for an endpoint.
    
    Args:
        endpoint: GraphQL endpoint URL
        proxy: Optional proxy string
        headers: Optional headers dictionary
        cookies: Optional cookies dictionary
        username: Optional username for injection testing
        password: Optional password for injection testing
        
    Returns:
        dict: Results of security checks
    """
    message = grapePrint()
    basic_vulnerabilities = []
    injection_vulnerabilities = []
    engine_info = None
    
    # Run fingerprinting
    message.printMsg("Starting fingerprinting...", status="log")
    engine_info = await runFingerprinting(
        endpoint=endpoint, 
        proxy=proxy, 
        headers=headers, 
        cookies=cookies
    )
    
    # Run basic security checks
    message.printMsg("Starting basic security checks...", status="log")
    security_tester = seeds()
    try:
        if await security_tester.set_endpoint(endpoint, proxy):
            if headers:
                security_tester.set_headers(headers)
            if cookies:
                security_tester.set_cookies(cookies)
                
            basic_vulnerabilities = await security_tester.runAllChecks()
            
            if basic_vulnerabilities:
                message.printMsg(f"Found {len(basic_vulnerabilities)} potential vulnerabilities", status="warning")
            else:
                message.printMsg("No basic vulnerabilities found", status="success")
    finally:
        # Ensure we close the session
        await security_tester.close()
    
    # Run command injection tests
    message.printMsg("Starting injection tests...", status="log")
    injection_tester = juice()
    try:
        if await injection_tester.set_endpoint(endpoint, proxy):
            if headers:
                injection_tester.set_headers(headers)
            if cookies:
                injection_tester.set_cookies(cookies)
            if username and password:
                injection_tester.set_credentials(username, password)
                
            injection_vulnerabilities = await injection_tester.scanForInjection()
            
            if injection_vulnerabilities:
                message.printMsg(f"Found {len(injection_vulnerabilities)} injection vulnerabilities!", status="failed")
            else:
                message.printMsg("No injection vulnerabilities found", status="success")
    finally:
        # Ensure we close the session
        await injection_tester.close()
    
    # Return comprehensive results
    return {
        "engine": engine_info,
        "basic_vulnerabilities": basic_vulnerabilities,
        "injection_vulnerabilities": injection_vulnerabilities
    }


async def main():
    """
    Main function to handle command-line arguments and perform graphql scanning.
    """
    parser = argparse.ArgumentParser(
        description="GraphQL Security Testing Tool with Proxy Support",
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
    
    parser.add_argument(
        "--report",
        help="Generate a report file with the specified filename",
    )

    args = parser.parse_args()

    try:
        scanner = vine()
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
        
        # Set custom headers and cookies for the scanner
        if headers:
            scanner.set_headers(headers)
            
        if cookies:
            scanner.set_cookies(cookies)

        all_vulnerabilities = []
        vulnerable_endpoints = []
        
        # Direct API endpoint testing
        if args.api:
            message.printMsg(f"Testing specific endpoint: {args.api}", status="log")
            vulnerable_endpoints = await testSingleEndpoint(
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
                
            message.printMsg(f"Starting scan of target: {args.target}", status="log")
            vulnerable_endpoints = await scanner.test(
                args.proxy if args.proxy else None, args.target
            )

        # Clean up the scanner's client session
        if hasattr(scanner.client, "close"):
            await scanner.client.close()

        if not vulnerable_endpoints:
            message.printMsg("No vulnerable GraphQL endpoints found", status="log")
            return 0
            
        message.printMsg(f"Found {len(vulnerable_endpoints)} vulnerable GraphQL endpoints", status="success")
        
        # Run security checks for each vulnerable endpoint
        for endpoint in vulnerable_endpoints:
            message.printMsg(f"Running security checks on: {endpoint}", status="log")
            results = await run_security_checks(
                endpoint=endpoint,
                proxy=args.proxy,
                headers=headers,
                cookies=cookies,
                username=args.username,
                password=args.password
            )
            
            all_vulnerabilities.append({
                "endpoint": endpoint,
                "results": results
            })
            
            # Run DoS tests if requested
            if args.crush:
                message.printMsg(f"Running DoS tests on: {endpoint}", status="log")
                await runDosTests(
                    endpoint=endpoint,
                    proxy=args.proxy,
                    headers=headers,
                    cookies=cookies
                )
        
        # Generate report if requested
        if args.report and all_vulnerabilities:
            from .report import generate_report
            generate_report(args.report, all_vulnerabilities)
            message.printMsg(f"Report generated: {args.report}", status="success")

        return 0

    except Exception as e:
        message.printMsg(f"Error during scan: {str(e)}", status="error")
        return 1
    finally:
        # Make sure to clean up any lingering sessions
        # This is important for avoiding the "Unclosed client session" warnings
        if 'scanner' in locals() and hasattr(scanner, 'client') and hasattr(scanner.client, 'close'):
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.create_task(scanner.client.close())
                else:
                    loop.run_until_complete(scanner.client.close())
            except:
                pass


def run_cli():
    """
    Entry point for the command-line interface.
    """
    exit_code = asyncio.run(main())
    exit(exit_code)


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code)