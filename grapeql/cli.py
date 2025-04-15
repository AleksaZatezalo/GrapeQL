"""
GrapeQL Command Line Interface (Simplified)
Author: Aleksa Zatezalo
Version: 2.0
Date: April 2025
Description: Simplified CLI for GrapeQL GraphQL Security Testing Tool
"""

import asyncio
import argparse
import sys
from typing import Dict, List, Optional

from .utils import GrapePrinter
from .client import GraphQLClient
from .scanner import Scanner
from .fingerprint import Fingerprinter
from .injection_tester import InjectionTester
from .dos_tester import DosTester
from .info_tester import InfoTester
from .reporter import Reporter

class GrapeQL:
    """
    Main class for the GrapeQL CLI with simplified options.
    """
    
    def __init__(self):
        """Initialize the GrapeQL CLI."""
        self.printer = GrapePrinter()
        self.reporter = Reporter()
        
    def parse_arguments(self):
        """
        Parse command line arguments with simplified options.
        
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
        
        # Cookie
        parser.add_argument(
            "--cookie",
            help="Cookie in format 'name:value'",
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
        
        # Set cookie if provided
        if args.cookie:
            try:
                name, value = args.cookie.split(":", 1)
                client.set_cookie(name.strip(), value.strip())
            except ValueError:
                self.printer.print_msg(
                    f"Invalid cookie format: {args.cookie}. Expected 'name:value'",
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
            
            # Fingerprinting
            fingerprinter = Fingerprinter()
            if await fingerprinter.setup_endpoint(args.api, args.proxy):
                self.setup_client(fingerprinter.client, args)
                await fingerprinter.fingerprint()
                self.reporter.add_findings(fingerprinter.get_findings())
            
            # Information disclosure tests
            info_tester = InfoTester()
            if await info_tester.setup_endpoint(args.api, args.proxy):
                self.setup_client(info_tester.client, args)
                await info_tester.run_test()
                self.reporter.add_findings(info_tester.get_findings())
            
            # Command injection tests
            injection_tester = InjectionTester()
            if await injection_tester.setup_endpoint(args.api, args.proxy):
                self.setup_client(injection_tester.client, args)
                await injection_tester.run_test()
                self.reporter.add_findings(injection_tester.get_findings())
            
            # DoS tests - only run if the --dos flag is provided
            if args.dos:
                self.printer.print_msg(
                    "DoS testing enabled - this may cause performance issues for the target server",
                    status="warning"
                )
                dos_tester = DosTester()
                if await dos_tester.setup_endpoint(args.api, args.proxy):
                    self.setup_client(dos_tester.client, args)
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