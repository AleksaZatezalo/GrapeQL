"""
GrapeQL Command Line Interface
Author: Aleksa Zatezalo
Version: 3.1
Date: February 2025
Description: CLI for GrapeQL GraphQL Security Testing Tool.
             v3.1: Removed threading, added --modules for selective test execution,
             --schema-file now always uses supplied schema (introspection tested but not required).
"""

import asyncio
import argparse
import json
import os
import sys
from typing import List, Set

from .utils import GrapePrinter
from .auth_tester import AuthTester
from .client import GraphQLClient
from .fingerprint import Fingerprinter
from .injection_tester import InjectionTester
from .dos_tester import DosTester
from .info_tester import InfoTester
from .reporter import Reporter
from .logger import GrapeLogger
from .loader import TestCaseLoader
from .baseline import BaselineTracker


_DEFAULT_TEST_CASES_DIR = os.path.join(os.path.dirname(__file__), "test_cases")

ALL_MODULES = {"fingerprint", "info", "injection", "auth", "dos"}

class GrapeQL:
    """
    Main orchestrator for the GrapeQL CLI.

    Execution order (enforced regardless of --modules order):
        1. fingerprint  (populates baseline)
        2. info          (populates baseline)
        3. injection     (populates baseline)
        4. dos           (reads baseline threshold)
    """

    def __init__(self):
        self.printer = GrapePrinter()
        self.reporter = Reporter()

    # ------------------------------------------------------------------ #
    #  Argument parsing
    # ------------------------------------------------------------------ #

    def parse_arguments(self):
        parser = argparse.ArgumentParser(
            description="GrapeQL - GraphQL Security Testing Tool",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Basic scan (all modules except DoS)
  grapeql --api https://example.com/graphql

  # Only run fingerprint and injection modules
  grapeql --api https://example.com/graphql --modules fingerprint injection

  # Full scan including DoS
  grapeql --api https://example.com/graphql --modules fingerprint info injection dos

  # Use a pre-captured schema (introspection is still probed but not required)
  grapeql --api https://example.com/graphql --schema-file schema.json

  # Combine: specific modules + supplied schema + logging
  grapeql --api https://example.com/graphql \\
      --modules injection --schema-file schema.json --log-file scan.log
            """,
        )

        parser.add_argument(
            "--api", required=True, help="URL of the GraphQL endpoint to test"
        )
        parser.add_argument(
            "--modules",
            nargs="+",
            choices=sorted(ALL_MODULES),
            default=None,
            help=(
                "Which test modules to run. Choices: dos, fingerprint, info, injection. "
                "Default: fingerprint info injection (all except dos)."
            ),
        )
        parser.add_argument("--proxy", help="Proxy address (host:port)")
        parser.add_argument("--auth", help="Authorization token")
        parser.add_argument(
            "--auth-type", default="Bearer", help="Auth token type (default: Bearer)"
        )
        parser.add_argument(
            "--cookie",
            action="append",
            default=[],
            help="Cookie in 'name:value' format (repeatable)",
        )
        parser.add_argument("--report", help="Report output file path")
        parser.add_argument(
            "--report-format",
            default="markdown",
            choices=["markdown", "json"],
            help="Report format (default: markdown)",
        )
        parser.add_argument("--username", help="Username for injection testing")
        parser.add_argument("--password", help="Password for injection testing")
        parser.add_argument(
            "--log-file",
            help="Path to structured log file. If omitted, logs go to stdout.",
        )
        parser.add_argument(
            "--test-cases",
            default=_DEFAULT_TEST_CASES_DIR,
            help="Directory containing YAML test case files (default: bundled)",
        )
        parser.add_argument(
            "--schema-file",
            help=(
                "Path to a JSON introspection schema. When provided, this schema "
                "is used for all testing. Live introspection is still attempted "
                "to check whether it is enabled, but is not required."
            ),
        )

        return parser.parse_args()

    # ------------------------------------------------------------------ #
    #  Helpers
    # ------------------------------------------------------------------ #

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

    def _resolve_modules(self, args) -> List[str]:
        """
        Return an ordered list of modules to execute.

        Execution order is always: fingerprint → info → injection → dos
        regardless of the order the user specifies them.  This guarantees
        the baseline is populated before DoS reads it.
        """
        EXECUTION_ORDER = ["fingerprint", "info", "injection", "auth", "dos"]

        if args.modules is not None:
            requested: Set[str] = set(args.modules)
        else:
            requested = ALL_MODULES - {"dos"}

        return [m for m in EXECUTION_ORDER if m in requested]

    # ------------------------------------------------------------------ #
    #  Schema loading
    # ------------------------------------------------------------------ #

    async def _load_schema(self, client: GraphQLClient, args) -> bool:
        """
        Load the schema into *client*.

        --schema-file supplied:
            1. Load the file into the client (authoritative source).
            2. Probe live introspection as an informational check so the
               info module can report whether introspection is enabled.
            3. Restore file-based schema regardless of probe result.

        --schema-file NOT supplied:
            1. Run live introspection.  Fail if it does not succeed.
        """
        if args.schema_file:
            self.printer.print_msg(
                f"Loading schema from {args.schema_file}", status="log"
            )
            try:
                with open(args.schema_file, "r") as f:
                    schema_data = json.load(f)
            except (IOError, json.JSONDecodeError) as exc:
                self.printer.print_msg(
                    f"Failed to read schema file: {exc}", status="error"
                )
                return False

            if "__schema" in schema_data:
                schema_data = schema_data["__schema"]

            if not client.load_schema_from_dict(schema_data):
                self.printer.print_msg(
                    "Failed to parse schema file", status="error"
                )
                return False

            # Informational introspection probe
            self.printer.print_msg(
                "Probing live introspection (informational only)…", status="log"
            )
            introspection_enabled = await client.introspection_query()
            if introspection_enabled:
                self.printer.print_msg(
                    "Introspection is ENABLED on this endpoint", status="warning"
                )
            else:
                self.printer.print_msg(
                    "Introspection is disabled or returned errors", status="log"
                )

            # Restore file-based schema (introspection probe may have overwritten it)
            client.load_schema_from_dict(schema_data)
            return True

        else:
            if not await client.introspection_query():
                self.printer.print_msg(
                    "Introspection failed — supply a schema with --schema-file "
                    "or ensure introspection is enabled",
                    status="error",
                )
                return False
            return True

    # ------------------------------------------------------------------ #
    #  Module runners
    # ------------------------------------------------------------------ #
    async def _run_auth(self, client, args, logger, loader, baseline):
        self.printer.print_section("Authentication Testing")
        auth = AuthTester(logger=logger, loader=loader, baseline=baseline)
        if await auth.setup_endpoint(args.api, args.proxy, client):
            if args.auth:
                auth.set_auth_headers({"Authorization": f"{args.auth_type} {args.auth}"})
            await auth.run_test()
            self.reporter.add_findings(auth.get_findings())
    
    async def _run_fingerprint(self, client, args, logger, loader, baseline):
        self.printer.print_section("Fingerprinting")
        fp = Fingerprinter(logger=logger, loader=loader, baseline=baseline)
        if await fp.setup_endpoint(args.api, args.proxy, client):
            await fp.fingerprint()
            self.reporter.add_findings(fp.get_findings())

    async def _run_info(self, client, args, logger, loader, baseline):
        self.printer.print_section("Information Disclosure")
        it = InfoTester(logger=logger, loader=loader, baseline=baseline)
        if await it.setup_endpoint(args.api, args.proxy, client):
            await it.run_test()
            self.reporter.add_findings(it.get_findings())

    async def _run_injection(self, client, args, logger, loader, baseline):
        self.printer.print_section("Injection Testing")
        inj = InjectionTester(logger=logger, loader=loader, baseline=baseline)
        if await inj.setup_endpoint(args.api, args.proxy, client):
            if args.username or args.password:
                inj.set_credentials(
                    args.username or "admin",
                    args.password or "changeme",
                )
            await inj.run_test()
            self.reporter.add_findings(inj.get_findings())

    async def _run_dos(self, client, args, logger, loader, baseline):
        self.printer.print_section("Denial of Service")
        self.printer.print_msg(
            "DoS testing enabled — server may become unresponsive",
            status="warning",
        )
        dos = DosTester(logger=logger, loader=loader, baseline=baseline)
        if await dos.setup_endpoint(args.api, args.proxy, client):
            await dos.run_test()
            self.reporter.add_findings(dos.get_findings())

    # ------------------------------------------------------------------ #
    #  Main
    # ------------------------------------------------------------------ #

    async def main(self) -> int:
        try:
            args = self.parse_arguments()
            self.printer.intro()

            # ── Shared infrastructure ────────────────────────────
            logger = GrapeLogger(log_file=args.log_file)
            loader = TestCaseLoader(args.test_cases)
            baseline = BaselineTracker()

            self.reporter.set_target(args.api)
            self.printer.print_section(f"Testing endpoint: {args.api}")

            # ── Build primary client + load schema ───────────────
            primary_client = GraphQLClient(logger=logger)
            primary_client.set_endpoint(args.api)
            self._configure_client(primary_client, args)

            if not await self._load_schema(primary_client, args):
                return 1

            # ── Resolve and execute modules sequentially ─────────
            modules = self._resolve_modules(args)
            self.printer.print_msg(
                f"Modules: {', '.join(modules)}", status="log"
            )

            dispatch = {
                "fingerprint": self._run_fingerprint,
                "info": self._run_info,
                "injection": self._run_injection,
                "auth": self._run_auth,
                "dos": self._run_dos,
            }

            for module_name in modules:
                await dispatch[module_name](
                    primary_client, args, logger, loader, baseline
                )

            # ── Baseline summary ─────────────────────────────────
            summary = baseline.summary()
            agg = summary.get("_aggregate", {})
            if agg.get("count", 0) > 0:
                self.printer.print_msg(
                    f"Baseline: {agg['count']} samples, "
                    f"avg={agg['mean']:.3f}s, stddev={agg['stddev']:.3f}s",
                    status="log",
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