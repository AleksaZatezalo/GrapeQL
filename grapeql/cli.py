"""
GrapeQL Command Line Interface
Author: Aleksa Zatezalo
Version: 3.4
Date: February 2025
Description: CLI for GrapeQL GraphQL Security Testing Tool.
             v3.3: Added --listener-ip / --listener-port for OOB testing.
             v3.4: Added --ai-key / --ai-message for AI-assisted analysis.
"""

import asyncio
import argparse
import json
import os
import sys
from typing import List, Set

from .utils import GrapePrinter
from .ai_agent import AIAgent
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

MODULE_CLASSES = {
    "fingerprint": Fingerprinter,
    "info": InfoTester,
    "injection": InjectionTester,
    "auth": AuthTester,
    "dos": DosTester,
}

# Execution order: baseline-producing modules first, then consumers
EXECUTION_ORDER = ["fingerprint", "info", "injection", "auth", "dos"]


class GrapeQL:
    """
    Main orchestrator for the GrapeQL CLI.

    Execution order (enforced regardless of --modules order):
        1. fingerprint  (populates baseline)
        2. info          (populates baseline)
        3. injection     (populates baseline)
        4. auth          (populates baseline)
        5. dos           (reads baseline threshold)
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

  # Injection with OOB listener
  grapeql --api https://example.com/graphql \\
      --modules injection --listener-ip 10.0.0.5 --listener-port 4444

  # Use a pre-captured schema (introspection is still probed but not required)
  grapeql --api https://example.com/graphql --schema-file schema.json

  # Only run DVGA OOB payloads
  grapeql --api http://localhost:5013/graphql \\
      --modules injection --include dvga_oob

  # Combine: specific modules + supplied schema + logging
  grapeql --api https://example.com/graphql \\
      --modules injection --schema-file schema.json --log-file scan.log

  # Full scan with AI-assisted analysis
  grapeql --api https://example.com/graphql \\
      --report report.md --ai-key sk-ant-...

  # AI analysis with operator guidance
  grapeql --api https://example.com/graphql \\
      --report report.md --ai-key sk-ant-... \\
      --ai-message "Focus on SSRF and auth bypass chains"
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
                "Which test modules to run. Choices: auth, dos, fingerprint, info, injection. "
                "Default: fingerprint info injection auth (all except dos)."
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
            "--include",
            nargs="+",
            metavar="FILE",
            help=(
                "Only run test cases from these YAML files (basename, e.g. "
                "'dvga_oob.yaml sqli.yaml').  Extension is optional.  "
                "Applies across all modules."
            ),
        )
        parser.add_argument(
            "--schema-file",
            help=(
                "Path to a JSON introspection schema. When provided, this schema "
                "is used for all testing. Live introspection is still attempted "
                "to check whether it is enabled, but is not required."
            ),
        )

        # ── OOB listener ────────────────────────────────────────────
        parser.add_argument(
            "--listener-ip",
            help=(
                "IP address for the local OOB callback listener. "
                "Enables out-of-band injection testing when used with --listener-port."
            ),
        )
        parser.add_argument(
            "--listener-port",
            type=int,
            help=(
                "Port for the local OOB callback listener. "
                "Enables out-of-band injection testing when used with --listener-ip."
            ),
        )

        # ── AI analysis ─────────────────────────────────────────────
        parser.add_argument(
            "--ai-key",
            help=(
                "Anthropic API key for AI-assisted analysis.  When provided, "
                "findings are sent to Claude for an executive summary and "
                "recommended next steps appended to the report."
            ),
        )
        parser.add_argument(
            "--ai-message",
            help=(
                "Optional free-form message passed to the AI agent to guide "
                "its analysis (e.g. 'Focus on SSRF chains' or 'Ignore info findings')."
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

        Execution order is always: fingerprint -> info -> injection -> auth -> dos
        regardless of the order the user specifies them.
        """
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
            2. Probe live introspection as an informational check.
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

            self.printer.print_msg(
                "Probing live introspection (informational only)...", status="log"
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

            # Restore file-based schema
            client.load_schema_from_dict(schema_data)
            return True

        else:
            if not await client.introspection_query():
                self.printer.print_msg(
                    "Introspection failed -- supply a schema with --schema-file "
                    "or ensure introspection is enabled",
                    status="error",
                )
                return False
            return True

    # ------------------------------------------------------------------ #
    #  Generic module runner
    # ------------------------------------------------------------------ #

    async def _run_module(self, module_name, client, args, logger, loader, baseline):
        """Instantiate and run any test module by name."""
        cls = MODULE_CLASSES[module_name]
        self.printer.print_section(module_name.replace("_", " ").title() + " Testing")

        if module_name == "dos":
            self.printer.print_msg(
                "DoS testing enabled -- server may become unresponsive",
                status="warning",
            )

        instance = cls(logger=logger, loader=loader, baseline=baseline)

        if not await instance.setup_endpoint(args.api, args.proxy, client):
            return

        # Apply auth headers where relevant
        if args.auth:
            if module_name == "auth":
                instance.set_auth_headers(
                    {"Authorization": f"{args.auth_type} {args.auth}"}
                )

        # Apply credentials for injection testing
        if hasattr(instance, "set_credentials") and (args.username or args.password):
            instance.set_credentials(
                args.username or "admin",
                args.password or "changeme",
            )

        # Apply OOB listener config to injection tester
        if module_name == "injection" and args.listener_ip and args.listener_port:
            instance.set_listener(args.listener_ip, args.listener_port)

        await instance.run_test()
        self.reporter.add_findings(instance.get_findings())

    # ------------------------------------------------------------------ #
    #  Main
    # ------------------------------------------------------------------ #

    async def main(self) -> int:
        try:
            args = self.parse_arguments()
            self.printer.intro()

            # Validate listener args come as a pair
            if bool(args.listener_ip) != bool(args.listener_port):
                self.printer.print_msg(
                    "--listener-ip and --listener-port must be used together",
                    status="error",
                )
                return 1

            # -- Shared infrastructure --
            logger = GrapeLogger(log_file=args.log_file)
            loader = TestCaseLoader(args.test_cases)
            baseline = BaselineTracker()

            # Apply --include filter to restrict which YAML files are loaded
            if args.include:
                loader.set_include_files(args.include)
                self.printer.print_msg(
                    f"Include filter: {', '.join(args.include)}", status="log"
                )

            self.reporter.set_target(args.api)
            self.printer.print_section(f"Testing endpoint: {args.api}")

            # -- Build primary client + load schema --
            primary_client = GraphQLClient(logger=logger)
            primary_client.set_endpoint(args.api)
            self._configure_client(primary_client, args)

            if not await self._load_schema(primary_client, args):
                return 1

            # -- Resolve and execute modules sequentially --
            modules = self._resolve_modules(args)
            self.printer.print_msg(
                f"Modules: {', '.join(modules)}", status="log"
            )

            for module_name in modules:
                await self._run_module(
                    module_name, primary_client, args, logger, loader, baseline
                )

            # -- Baseline summary --
            summary = baseline.summary()
            agg = summary.get("_aggregate", {})
            if agg.get("count", 0) > 0:
                self.printer.print_msg(
                    f"Baseline: {agg['count']} samples, "
                    f"avg={agg['mean']:.3f}s, stddev={agg['stddev']:.3f}s",
                    status="log",
                )

            # -- AI analysis (optional) --
            if args.ai_key:
                agent = AIAgent(api_key=args.ai_key)
                ai_summary = await agent.analyse(
                    target=args.api,
                    findings=self.reporter.findings,
                    schema=primary_client.schema,
                    message=args.ai_message,
                )
                if ai_summary:
                    self.reporter.set_ai_summary(ai_summary)

            # -- Report --
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