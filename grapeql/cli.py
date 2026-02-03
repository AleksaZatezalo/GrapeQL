"""
GrapeQL Command Line Interface
Author: Aleksa Zatezalo
Version: 3.0
Date: February 2025
Description: CLI for GrapeQL GraphQL Security Testing Tool.
             New in v3: --log-file, --test-cases, --schema-file flags.
             Schema is retrieved once (or loaded from file) and forwarded to all modules.
             Response-time baseline is shared across modules for DoS threshold.
"""

import asyncio
import argparse
import json
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional

from .utils import GrapePrinter
from .client import GraphQLClient
from .fingerprint import Fingerprinter
from .injection_tester import InjectionTester
from .dos_tester import DosTester
from .info_tester import InfoTester
from .reporter import Reporter
from .logger import GrapeLogger
from .loader import TestCaseLoader
from .baseline import BaselineTracker


# Resolve the default test_cases directory shipped with the package
_DEFAULT_TEST_CASES_DIR = os.path.join(os.path.dirname(__file__), "test_cases")


class GrapeQL:
    """
    Main class for the GrapeQL CLI.
    """

    def __init__(self):
        self.printer = GrapePrinter()
        self.reporter = Reporter()
        self.printer_lock = threading.Lock()
        self.reporter_lock = threading.Lock()

    def parse_arguments(self):
        parser = argparse.ArgumentParser(
            description="GrapeQL - GraphQL Security Testing Tool",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Basic scan
  python -m grapeql --api https://example.com/graphql

  # Full scan with DoS, logging, and custom test cases
  python -m grapeql --api https://example.com/graphql \\
      --dos --log-file scan.log --test-cases ./my_tests

  # Use a pre-captured schema file (skip live introspection)
  python -m grapeql --api https://example.com/graphql \\
      --schema-file schema.json --report report.md
            """,
        )

        parser.add_argument(
            "--api", required=True, help="URL of the GraphQL endpoint to test"
        )

        parser.add_argument(
            "--dos",
            action="store_true",
            help="Include Denial of Service testing",
        )

        parser.add_argument("--proxy", help="Proxy address (host:port)")

        parser.add_argument("--auth", help="Authorization token")
        parser.add_argument(
            "--auth-type", help="Auth token type (default: Bearer)", default="Bearer"
        )

        parser.add_argument(
            "--cookie",
            help="Cookie in 'name:value' format (repeatable)",
            action="append",
            default=[],
        )

        parser.add_argument("--report", help="Report output file path")
        parser.add_argument(
            "--report-format",
            help="Report format (markdown or json)",
            default="markdown",
            choices=["markdown", "json"],
        )

        parser.add_argument("--username", help="Username for injection testing")
        parser.add_argument("--password", help="Password for injection testing")

        # ── New in v3 ────────────────────────────────────────────
        parser.add_argument(
            "--log-file",
            help="Path to structured log file. If omitted, logs go to stdout.",
        )
        parser.add_argument(
            "--test-cases",
            help="Directory containing YAML test case files (default: bundled)",
            default=_DEFAULT_TEST_CASES_DIR,
        )
        parser.add_argument(
            "--schema-file",
            help=(
                "Path to a JSON file containing the introspection schema "
                "(the __schema object). Skips live introspection."
            ),
        )

        return parser.parse_args()

    def _configure_client(self, client: GraphQLClient, args) -> None:
        """Apply proxy, auth, and cookies to a client."""
        if args.proxy:
            try:
                host, port = args.proxy.split(":")
                client.configure_proxy(host, int(port))
            except ValueError:
                self.printer.print_msg(
                    f"Invalid proxy format: {args.proxy}", status="error"
                )

        if args.auth:
            client.set_authorization(args.auth, args.auth_type)

        for cookie_str in args.cookie:
            try:
                name, value = cookie_str.split(":", 1)
                client.set_cookie(name.strip(), value.strip())
            except ValueError:
                self.printer.print_msg(
                    f"Invalid cookie format: {cookie_str}", status="error"
                )

    async def main(self):
        try:
            args = self.parse_arguments()
            self.printer.intro()

            # ── Shared infrastructure ────────────────────────────
            logger = GrapeLogger(log_file=args.log_file)
            loader = TestCaseLoader(args.test_cases)
            baseline = BaselineTracker()

            self.reporter.set_target(args.api)
            self.printer.print_section(f"Testing endpoint: {args.api}")

            # ── Build a single "source of truth" client ──────────
            #    Schema is retrieved ONCE here (or loaded from file)
            #    and then forwarded to every module via pre_configured_client.
            primary_client = GraphQLClient(logger=logger)
            primary_client.set_endpoint(args.api)
            self._configure_client(primary_client, args)

            if args.schema_file:
                # Load schema from JSON file instead of live introspection
                self.printer.print_msg(
                    f"Loading schema from {args.schema_file}", status="log"
                )
                with open(args.schema_file, "r") as f:
                    schema_data = json.load(f)
                # Support both {"__schema": {...}} and bare {...}
                if "__schema" in schema_data:
                    schema_data = schema_data["__schema"]
                if not primary_client.load_schema_from_dict(schema_data):
                    self.printer.print_msg(
                        "Failed to load schema from file", status="error"
                    )
                    return 1
            else:
                if not await primary_client.introspection_query():
                    self.printer.print_msg(
                        "Introspection failed — cannot proceed", status="error"
                    )
                    return 1

            # ── Parallel test execution ──────────────────────────

            async def run_fingerprint_test():
                fp = Fingerprinter(logger=logger, loader=loader, baseline=baseline)
                if await fp.setup_endpoint(args.api, args.proxy, primary_client):
                    await fp.fingerprint()
                    with self.reporter_lock:
                        self.reporter.add_findings(fp.get_findings())

            async def run_info_test():
                it = InfoTester(logger=logger, loader=loader, baseline=baseline)
                if await it.setup_endpoint(args.api, args.proxy, primary_client):
                    await it.run_test()
                    with self.reporter_lock:
                        self.reporter.add_findings(it.get_findings())

            async def run_injection_test():
                inj = InjectionTester(logger=logger, loader=loader, baseline=baseline)
                if await inj.setup_endpoint(args.api, args.proxy, primary_client):
                    if args.username or args.password:
                        inj.set_credentials(
                            args.username or "admin",
                            args.password or "changeme",
                        )
                    await inj.run_test()
                    with self.reporter_lock:
                        self.reporter.add_findings(inj.get_findings())

            def run_async_test(coro):
                return asyncio.run(coro())

            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = [
                    executor.submit(run_async_test, run_fingerprint_test),
                    executor.submit(run_async_test, run_info_test),
                    executor.submit(run_async_test, run_injection_test),
                ]
                for future in futures:
                    try:
                        future.result()
                    except Exception as e:
                        with self.printer_lock:
                            self.printer.print_msg(
                                f"Error during test: {str(e)}", status="error"
                            )

            # ── Print baseline summary ───────────────────────────
            summary = baseline.summary()
            agg = summary.get("_aggregate", {})
            if agg.get("count", 0) > 0:
                self.printer.print_msg(
                    f"Baseline: {agg['count']} samples, "
                    f"avg={agg['mean']:.3f}s, stddev={agg['stddev']:.3f}s",
                    status="log",
                )

            # ── DoS tests (sequential, after baseline is built) ──
            if args.dos:
                self.printer.print_msg(
                    "DoS testing enabled — server may become unresponsive",
                    status="warning",
                )
                dos = DosTester(logger=logger, loader=loader, baseline=baseline)
                if await dos.setup_endpoint(args.api, args.proxy, primary_client):
                    await dos.run_test()
                    self.reporter.add_findings(dos.get_findings())
            else:
                self.printer.print_msg(
                    "DoS testing skipped (use --dos to enable)", status="log"
                )

            # ── Report ───────────────────────────────────────────
            if args.report:
                self.reporter.generate_report(
                    output_format=args.report_format, output_file=args.report
                )
            else:
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
