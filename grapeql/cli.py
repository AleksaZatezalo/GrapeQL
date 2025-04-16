"""
GrapeQL Command Line Interface
Author: Aleksa Zatezalo
Version: 2.0
Date: April 2025
Description: CLI for GrapeQL GraphQL Security Testing Tool
"""

import asyncio
import argparse
import sys
from typing import Dict, List, Optional

from .utils import GrapePrinter
from .client import GraphQLClient
from .fingerprint import Fingerprinter
from .injection_tester import InjectionTester
from .dos_tester import DosTester
from .info_tester import InfoTester
from .reporter import Reporter

class GrapeQL:
    """
    Main class for the GrapeQL CLI with options.
    """
    
    def __init__(self):
        """Initialize the GrapeQL CLI."""
        self.printer = GrapePrinter()
        self.reporter = Reporter()
        
    def parse_arguments(self):
        """
        Parse command line arguments with options.
        
        Returns:
            argparse.Namespace: Parsed arguments
        """
        parser = argparse.ArgumentParser(
            description="GrapeQL - GraphQL Security Testing Tool",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Test a specific GraphQL endpoint
  python -m grapeql --api https://example.com/graphql
  
  # Include DoS testing
  python -m grapeql --api https://example.com/graphql --dos
  
  # Generate a report
  python -m grapeql --api https://example.com/graphql --report report.md
  
  # Test with specific injection credentials
  python -m grapeql --api https://example.com/graphql --username test_user --password test_pass
  
  # Use multiple cookies
  python -m grapeql --api https://example.com/graphql --cookie "session:abc123" --cookie "csrftoken:xyz456"
            """
        )
        
        # Main argument for API endpoint
        parser.add_argument(
            "--api",
            required=True,
            help="URL of the GraphQL endpoint to test"
        )
        
        # DoS testing flag
        parser.add_argument(
            "--dos",
            action="store_true",
            help="Include Denial of Service testing (may cause performance issues)"
        )
        
        # Proxy configuration
        parser.add_argument(
            "--proxy",
            help="Proxy address in format host:port (e.g., 127.0.0.1:8080)"
        )
        
        # Authentication
        parser.add_argument(
            "--auth",
            help="Authorization token to include in requests"
        )
        
        parser.add_argument(
            "--auth-type",
            help="Authorization token type (e.g., Bearer, Basic). Default is Bearer.",
            default="Bearer"
        )
        
        # Cookie - modified to accept multiple cookies
        parser.add_argument(
            "--cookie",
            help="Cookie in format 'name:value' (can be used multiple times)",
            action="append",
            default=[]
        )
        
        # Reporting options
        parser.add_argument(
            "--report",
            help="File name for the report (e.g., report.md)"
        )
        
        parser.add_argument(
            "--report-format",
            help="Report format (markdown or json, default: markdown)",
            default="markdown",
            choices=["markdown", "json"]
        )
        
        # Injection testing credentials
        parser.add_argument(
            "--username",
            help="Username to use for injection testing (default: admin)"
        )
        
        parser.add_argument(
            "--password",
            help="Password to use for injection testing (default: changeme)"
        )
        
        return parser.parse_args()
    
    def setup_client(self, client, args):
        """
        Configure a client with command line arguments.
        
        Args:
            client: Client to configure
            args: Command line arguments
        """
        # Set proxy if provided
        if args.proxy:
            try:
                proxy_host, proxy_port = args.proxy.split(":")
                client.configure_proxy(proxy_host, int(proxy_port))
            except ValueError:
                self.printer.print_msg(
                    f"Invalid proxy format: {args.proxy}. Expected host:port",
                    status="error"
                )
        
        # Set authentication if provided
        if args.auth:
            client.set_authorization(args.auth, args.auth_type)
        
        # Set cookies if provided - updated to handle multiple cookies
        if args.cookie:
            for cookie_str in args.cookie:
                try:
                    name, value = cookie_str.split(":", 1)
                    client.set_cookie(name.strip(), value.strip())
                    self.printer.print_msg(
                        f"Set cookie {name.strip()}: {value.strip()}",
                        status="success"
                    )
                except ValueError:
                    self.printer.print_msg(
                        f"Invalid cookie format: {cookie_str}. Expected 'name:value'",
                        status="error"
                    )
    
    async def main(self):
        """
        Main entry point for the CLI.
        
        Returns:
            int: Exit code (0 for success, 1 for failure)
        """
        try:
            # Parse arguments
            args = self.parse_arguments()
            
            # Show intro
            self.printer.intro()
            
            # Set target in reporter
            self.reporter.set_target(args.api)
            
            # Run all tests on the endpoint
            self.printer.print_section(f"Testing endpoint: {args.api}")
            
            # Create a temporary client to set cookies and auth before introspection
            temp_client = GraphQLClient()
            temp_client.set_endpoint(args.api)
            
            # Set proxy if provided
            if args.proxy:
                try:
                    proxy_host, proxy_port = args.proxy.split(":")
                    temp_client.configure_proxy(proxy_host, int(proxy_port))
                except ValueError:
                    self.printer.print_msg(
                        f"Invalid proxy format: {args.proxy}. Expected host:port",
                        status="error"
                    )
            
            # Apply auth and cookies before any introspection query
            if args.auth:
                temp_client.set_authorization(args.auth, args.auth_type)
                
            if args.cookie:
                for cookie_str in args.cookie:
                    try:
                        name, value = cookie_str.split(":", 1)
                        temp_client.set_cookie(name.strip(), value.strip())
                        self.printer.print_msg(
                            f"Set cookie {name.strip()}: {value.strip()}",
                            status="success"
                        )
                    except ValueError:
                        self.printer.print_msg(
                            f"Invalid cookie format: {cookie_str}. Expected 'name:value'",
                            status="error"
                        )
                        
            # Pass the configured client to setup_endpoint calls to use for initial introspection
            
            # Fingerprinting
            fingerprinter = Fingerprinter()
            if await fingerprinter.setup_endpoint(args.api, args.proxy, temp_client):
                # No need to set up again, client is already configured
                await fingerprinter.fingerprint()
                self.reporter.add_findings(fingerprinter.get_findings())
            
            # Information disclosure tests
            info_tester = InfoTester()
            if await info_tester.setup_endpoint(args.api, args.proxy, temp_client):
                # No need to call setup_client again
                await info_tester.run_test()
                self.reporter.add_findings(info_tester.get_findings())
            
            # Command injection tests
            injection_tester = InjectionTester()
            if await injection_tester.setup_endpoint(args.api, args.proxy, temp_client):
                # No need to call setup_client again
                
                # Set custom credentials for injection testing if provided
                if args.username or args.password:
                    username = args.username or "admin"  # Use default if not provided
                    password = args.password or "changeme"  # Use default if not provided
                    injection_tester.set_credentials(username, password)
                    self.printer.print_msg(
                        f"Using custom injection testing credentials: {username}:{password}",
                        status="log"
                    )
                
                await injection_tester.run_test()
                self.reporter.add_findings(injection_tester.get_findings())
            
            # DoS tests - only run if the --dos flag is provided
            if args.dos:
                self.printer.print_msg(
                    "DoS testing enabled - this may cause performance issues for the target server",
                    status="warning"
                )
                dos_tester = DosTester()
                if await dos_tester.setup_endpoint(args.api, args.proxy, temp_client):
                    # No need to call setup_client again
                    await dos_tester.run_test()
                    self.reporter.add_findings(dos_tester.get_findings())
            else:
                self.printer.print_msg(
                    "DoS testing skipped (use --dos to enable)",
                    status="log"
                )
            
            # Generate report if requested
            if args.report:
                self.reporter.generate_report(
                    output_format=args.report_format,
                    output_file=args.report
                )
            else:
                # Just print the summary
                self.reporter.print_summary()
            
            return 0
            
        except KeyboardInterrupt:
            self.printer.print_msg("\nScan interrupted by user", status="warning")
            return 1
        except Exception as e:
            self.printer.print_msg(f"Error during scan: {str(e)}", status="error")
            return 1


def run_cli():
    """Entry point for the command-line interface."""
    grapeql = GrapeQL()
    exit_code = asyncio.run(grapeql.main())
    sys.exit(exit_code)


if __name__ == "__main__":
    run_cli()