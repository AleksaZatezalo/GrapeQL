"""
GrapeQL - A GraphQL Security Testing Tool.

Author: Aleksa Zatezalo
Version: 3.0.0
"""

import asyncio
import argparse
import json
import time
from typing import Dict, List, Optional

from .grapePrint import grapePrint
from .scanner import GraphQLScanner
from .test_modules import SecurityTester


async def run_security_tests(endpoint: str, proxy: Optional[str] = None, 
                            headers: Optional[Dict] = None, cookies: Optional[Dict] = None,
                            username: Optional[str] = None, password: Optional[str] = None,
                            dos_testing: bool = False, debug_mode: bool = False) -> Dict:
    """
    Run all security tests for an endpoint.
    
    Args:
        endpoint: GraphQL endpoint URL
        proxy: Optional proxy string
        headers: Optional headers dictionary
        cookies: Optional cookies dictionary
        username: Optional username for injection testing
        password: Optional password for injection testing
        dos_testing: Whether to run DoS tests
        debug_mode: Whether to enable debug mode
        
    Returns:
        dict: Results of security tests
    """
    message = grapePrint()
    scanner = GraphQLScanner()
    
    try:
        # Set debug mode if enabled
        if debug_mode:
            scanner.set_debug_mode(True)
            message.printMsg("Debug mode enabled", status="info")
        
        # Set authentication credentials if provided
        if username and password:
            scanner.set_credentials(username, password)
            message.printMsg(f"Using provided credentials for authentication testing", status="info")
        
        # Set custom headers and cookies if provided
        if headers:
            scanner.set_headers(headers)
        if cookies:
            scanner.set_cookies(cookies)
        
        # Configure proxy if provided
        if proxy:
            message.printMsg(f"Using proxy: {proxy} for all security tests", status="info")
            if not scanner.client.set_proxy_from_string(proxy):
                message.printMsg(f"Invalid proxy format: {proxy}", status="failed")
                return {"status": "failed", "error": f"Invalid proxy format: {proxy}"}
        
        # Set the endpoint
        if not await scanner.set_endpoint(endpoint):
            message.printMsg(f"Failed to connect to endpoint: {endpoint}", status="failed")
            return {"status": "failed", "error": "Could not connect to endpoint"}
        
        # Run security tests
        message.printMsg("Starting security tests...", status="log")
        # Pass the proxy to SecurityTester to ensure all tests use it
        tester = SecurityTester(scanner, proxy=proxy)
        results = await tester.run_all_tests(run_dos=dos_testing)
        
        return results
    finally:
        # Always clean up resources
        await scanner.close()


def load_json_file(file_path: str) -> Optional[Dict]:
    """
    Load JSON data from a file.
    
    Args:
        file_path: Path to the JSON file
        
    Returns:
        Optional[Dict]: Parsed JSON data or None if error
    """
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading JSON file {file_path}: {str(e)}")
        return None


async def main():
    """
    Main function to handle command-line arguments and perform GraphQL scanning.
    """
    parser = argparse.ArgumentParser(
        description="GrapeQL Security Testing Tool (Simplified Version)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Required arguments group
    required_group = parser.add_mutually_exclusive_group(required=True)
    required_group.add_argument(
        "-t", "--target", help="Target IP address to scan"
    )
    required_group.add_argument(
        "-e", "--endpoint",
        help="Direct GraphQL endpoint URL to test"
    )

    # Optional arguments
    parser.add_argument(
        "-p", "--proxy",
        help="Optional proxy address in format host:port (e.g., 127.0.0.1:8080)"
    )
    parser.add_argument(
        "-d", "--dos", 
        action="store_true", 
        help="Run DoS testing (may impact target performance)"
    )
    parser.add_argument(
        "-u", "--username",
        help="Username to use for testing (default: admin)",
        default="admin"
    )
    parser.add_argument(
        "-pw", "--password",
        help="Password to use for testing (default: changeme)",
        default="changeme"
    )
    
    # Debug mode
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode with verbose output"
    )
    
    # Headers and cookies
    parser.add_argument(
        "--header",
        action="append",
        help="Custom header in format 'name:value'. Can be specified multiple times.",
        dest="headers"
    )
    parser.add_argument(
        "--headers-file",
        help="Path to JSON file containing custom headers"
    )
    parser.add_argument(
        "--cookie",
        action="append",
        help="Cookie in format 'name:value'. Can be specified multiple times.",
        dest="cookies"
    )
    parser.add_argument(
        "--cookies-file",
        help="Path to JSON file containing cookies"
    )
    parser.add_argument(
        "--auth",
        help="Authorization token to include in requests"
    )
    parser.add_argument(
        "--auth-type",
        help="Authorization token type (e.g., Bearer, Basic). Default is Bearer.",
        default="Bearer"
    )
    
    # Output report
    parser.add_argument(
        "--report",
        help="Generate a report file with the specified filename"
    )

    # Parse arguments
    args = parser.parse_args()

    scanner = None
    
    try:
        message = grapePrint()
        message.intro()
        
        # Process headers from command line and file
        headers = {}
        if args.headers:
            for header in args.headers:
                try:
                    name, value = header.split(':', 1)
                    headers[name.strip()] = value.strip()
                except ValueError:
                    message.printMsg(f"Invalid header format: {header}. Expected 'name:value'", status="failed")
        
        if args.headers_file:
            file_headers = load_json_file(args.headers_file)
            if file_headers:
                headers.update(file_headers)
        
        # Process cookies from command line and file
        cookies = {}
        if args.cookies:
            for cookie in args.cookies:
                try:
                    name, value = cookie.split(':', 1)
                    cookies[name.strip()] = value.strip()
                except ValueError:
                    message.printMsg(f"Invalid cookie format: {cookie}. Expected 'name:value'", status="failed")
        
        if args.cookies_file:
            file_cookies = load_json_file(args.cookies_file)
            if file_cookies:
                cookies.update(file_cookies)
        
        # Set authorization token if provided
        if args.auth:
            headers['Authorization'] = f"{args.auth_type} {args.auth}" if args.auth_type else args.auth
        
        # Display proxy information
        if args.proxy:
            message.printMsg(f"Configured proxy: {args.proxy}", status="info")
            
        # Direct endpoint testing
        if args.endpoint:
            message.printMsg(f"Testing endpoint: {args.endpoint}", status="log")
            start_time = time.time()
            
            # Display credential information
            if args.username and args.password:
                message.printMsg(f"Using credentials - Username: {args.username}, Password: {args.password}", status="info")
            
            # Run all security tests
            results = await run_security_tests(
                endpoint=args.endpoint,
                proxy=args.proxy,
                headers=headers,
                cookies=cookies,
                username=args.username,
                password=args.password,
                dos_testing=args.dos,
                debug_mode=args.debug
            )
            
            # Generate report if requested
            if args.report and results:
                from .report import generate_report
                generate_report(args.report, [{"endpoint": args.endpoint, "results": results}])
                message.printMsg(f"Report generated: {args.report}", status="success")
                
            end_time = time.time()
            message.printMsg(f"Testing completed in {end_time - start_time:.2f} seconds", status="success")
        
        # IP address scanning
        else:
            message.printMsg(f"Starting scan of target: {args.target}", status="log")
            start_time = time.time()
            
            # Create scanner and discover endpoints
            scanner = GraphQLScanner()
            
            try:
                # Set debug mode if enabled
                if args.debug:
                    scanner.set_debug_mode(True)
                    message.printMsg("Debug mode enabled", status="info")
                
                # Set credentials
                if args.username and args.password:
                    scanner.set_credentials(args.username, args.password)
                    message.printMsg(f"Using credentials - Username: {args.username}, Password: {args.password}", status="info")
                
                # Set custom headers and cookies
                if headers:
                    scanner.set_headers(headers)
                if cookies:
                    scanner.set_cookies(cookies)
                    
                # Set proxy if provided
                if args.proxy:
                    message.printMsg(f"Using proxy: {args.proxy}", status="info")
                    if not scanner.client.set_proxy_from_string(args.proxy):
                        message.printMsg(f"Invalid proxy format: {args.proxy}", status="failed")
                        return 1
                
                # Discover endpoints
                endpoints = await scanner.discover_endpoints(args.target, args.proxy)
                
                if not endpoints:
                    message.printMsg("No GraphQL endpoints found", status="warning")
                    return 0
                    
                message.printMsg(f"Found {len(endpoints)} GraphQL endpoints", status="success")
                
                # Test each endpoint and collect results
                all_results = []
                for endpoint in endpoints:
                    message.printMsg(f"Testing endpoint: {endpoint}", status="log")
                    
                    # Run security tests
                    results = await run_security_tests(
                        endpoint=endpoint,
                        proxy=args.proxy,
                        headers=headers,
                        cookies=cookies,
                        username=args.username,
                        password=args.password,
                        dos_testing=args.dos,
                        debug_mode=args.debug
                    )
                    
                    all_results.append({"endpoint": endpoint, "results": results})
                
                # Generate report if requested
                if args.report and all_results:
                    from .report import generate_report
                    generate_report(args.report, all_results)
                    message.printMsg(f"Report generated: {args.report}", status="success")
                    
                end_time = time.time()
                message.printMsg(f"Scan completed in {end_time - start_time:.2f} seconds", status="success")
            
            finally:
                # Always clean up resources
                if scanner:
                    await scanner.close()
            
        return 0

    except Exception as e:
        message.printMsg(f"Error during execution: {str(e)}", status="failed")
        return 1
    
    finally:
        # Final cleanup for any remaining sessions
        if scanner:
            await scanner.close()
        
        # Force cleanup of any remaining asyncio resources
        # This helps prevent "Unclosed client session" warnings
        tasks = [task for task in asyncio.all_tasks() if task is not asyncio.current_task()]
        if tasks:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)


def run_cli():
    """
    Entry point for the command-line interface.
    """
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        exit_code = loop.run_until_complete(main())
        # Clean up pending tasks
        pending = asyncio.all_tasks(loop)
        if pending:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.close()
        exit(exit_code)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        exit(1)


if __name__ == "__main__":
    run_cli()