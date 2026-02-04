"""
GrapeQL Authentication Tester
Author: Aleksa Zatezalo
Version: 3.1
Date: February 2025
Description: Tests for authentication bypass, IDOR, and field-level
             authorization failures in GraphQL APIs.

Strategies:
    header_bypass  — Replay queries with manipulated/missing auth headers
    idor           — Enumerate sequential IDs on queries with ID arguments
    raw_query      — Send specific queries without authentication
"""

import json
import time
from typing import Any, Dict, List, Optional

from .tester import VulnerabilityTester
from .utils import Finding


class AuthTester(VulnerabilityTester):
    """
    Tests authentication and authorization controls.

    Approach:
        1. Establish an authenticated baseline by running every query/mutation
           with the user-supplied credentials.
        2. Replay those same requests with manipulated headers (from YAML).
        3. Compare responses — if the unauthenticated response returns data
           that matches the authenticated baseline, auth is broken.

    If no auth headers are provided, skips baseline comparison and only
    tests unauthenticated access to endpoints.
    """

    MODULE_NAME = "auth"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._auth_headers: Dict[str, str] = {}
        self._baselines: Dict[str, Any] = {}

    # ------------------------------------------------------------------ #
    #  Configuration
    # ------------------------------------------------------------------ #

    def set_auth_headers(self, headers: Dict[str, str]) -> None:
        """Set the known-good authentication headers."""
        self._auth_headers = headers.copy()

    # ------------------------------------------------------------------ #
    #  Baseline
    # ------------------------------------------------------------------ #

    async def _establish_baseline(self) -> None:
        """
        Run every query with valid auth and store the responses.
        This is the "expected" behavior — later tests compare against it.
        """
        if self.logger:
            self.logger.log_request(
                module=self.MODULE_NAME,
                test="baseline",
                status="started",
                parameter="-",
            )

        original_headers = self.client.headers.copy()
        self.client.headers.update(self._auth_headers)

        for name, field in self.client.query_fields.items():
            query = self._build_minimal_query(name, field)
            if query:
                result, error = await self.client.graphql_query(query)
                if not error and result:
                    self._baselines[f"query:{name}"] = result

        for name, field in self.client.mutation_fields.items():
            if self._is_safe_to_probe(field):
                query = self._build_minimal_mutation(name, field)
                if query:
                    result, error = await self.client.graphql_query(query)
                    if not error and result:
                        self._baselines[f"mutation:{name}"] = result

        self.client.headers = original_headers

        if self.logger:
            self.logger.log_request(
                module=self.MODULE_NAME,
                test="baseline",
                status="complete",
                parameter=f"{len(self._baselines)} endpoints baselined",
            )

    # ------------------------------------------------------------------ #
    #  Test strategies
    # ------------------------------------------------------------------ #

    async def _test_header_bypass(self, test_case: Dict) -> None:
        """
        Replay baselined requests with manipulated headers.
        If the response still contains data, the auth check is broken.
        """
        name = test_case["name"]
        attack_headers = test_case.get("headers", {})
        description = test_case.get("description", "")

        original_headers = self.client.headers.copy()

        # Strip existing auth headers, apply attack headers
        self.client.headers = {
            k: v
            for k, v in original_headers.items()
            if k.lower() not in ("authorization", "cookie", "x-api-key")
        }
        self.client.headers.update(attack_headers)

        for endpoint_key, baseline_response in self._baselines.items():
            kind, field_name = endpoint_key.split(":", 1)

            if kind == "query":
                field = self.client.query_fields.get(field_name)
                query = self._build_minimal_query(field_name, field)
            else:
                field = self.client.mutation_fields.get(field_name)
                query = self._build_minimal_mutation(field_name, field)

            if not query:
                continue

            start = time.monotonic()
            result, error = await self.client.graphql_query(query)
            duration = time.monotonic() - start

            self._record_response_time(duration)

            if not error and self._response_matches_baseline(result, baseline_response):
                self.add_finding(Finding(
                    title=f"Auth Bypass: {name} on {field_name}",
                    severity="HIGH",
                    description=(
                        f"{description}. The {kind} '{field_name}' returned "
                        f"data identical to the authenticated baseline when "
                        f"using manipulated headers: {json.dumps(attack_headers)}. "
                        f"Evidence: {json.dumps(result, default=str)[:500]}"
                    ),
                    endpoint=self.client.endpoint or "",
                ))

                if self.logger:
                    self.logger.log_request(
                        module=self.MODULE_NAME,
                        test=name,
                        parameter=field_name,
                        payload=json.dumps(attack_headers),
                        status="VULNERABLE",
                        response=result,
                        duration=duration,
                    )
            else:
                if self.logger:
                    self.logger.log_request(
                        module=self.MODULE_NAME,
                        test=name,
                        parameter=field_name,
                        payload=json.dumps(attack_headers),
                        status="blocked",
                        response=result,
                        duration=duration,
                    )

        self.client.headers = original_headers

    async def _test_idor(self, test_case: Dict) -> None:
        """
        Enumerate sequential IDs on queries/mutations that accept ID arguments.
        """
        name = test_case["name"]
        id_range = test_case.get("id_range", [1, 20])

        id_fields: List[tuple] = []

        id_arg_names = {"id", "userid", "user_id", "accountid", "account_id"}

        for field_name, field in self.client.query_fields.items():
            args = field.get("args", [])
            for arg in args:
                if arg.get("name", "").lower() in id_arg_names:
                    id_fields.append((field_name, arg["name"], field, "query"))
                    break

        for field_name, field in self.client.mutation_fields.items():
            args = field.get("args", [])
            for arg in args:
                if arg.get("name", "").lower() in id_arg_names:
                    id_fields.append((field_name, arg["name"], field, "mutation"))
                    break

        for field_name, arg_name, field, kind in id_fields:
            accessible_ids: List[int] = []

            for test_id in range(id_range[0], id_range[1] + 1):
                selection = self._build_selection_set(field)
                if kind == "query":
                    query = f'{{ {field_name}({arg_name}: "{test_id}") {selection} }}'
                else:
                    query = f'mutation {{ {field_name}({arg_name}: "{test_id}") {selection} }}'

                start = time.monotonic()
                result, error = await self.client.graphql_query(query)
                duration = time.monotonic() - start

                self._record_response_time(duration)

                if not error and self._has_data(result):
                    accessible_ids.append(test_id)

            if len(accessible_ids) > 1:
                self.add_finding(Finding(
                    title=f"IDOR: {field_name} exposes sequential IDs",
                    severity="HIGH",
                    description=(
                        f"The {kind} '{field_name}' returned data for "
                        f"{len(accessible_ids)} different IDs via the "
                        f"'{arg_name}' argument. Accessible IDs: "
                        f"{accessible_ids[:10]}"
                        f"{'...' if len(accessible_ids) > 10 else ''}. "
                        f"Tested range {id_range[0]}-{id_range[1]}, "
                        f"{len(accessible_ids)} returned data."
                    ),
                    endpoint=self.client.endpoint or "",
                ))

    async def _test_raw_query(self, test_case: Dict) -> None:
        """Send a raw query with specific headers (e.g. introspection without auth)."""
        name = test_case["name"]
        query = test_case["query"]
        attack_headers = test_case.get("headers", {})
        description = test_case.get("description", "")

        original_headers = self.client.headers.copy()

        # Strip auth, apply attack headers
        self.client.headers = {
            k: v
            for k, v in original_headers.items()
            if k.lower() not in ("authorization", "cookie", "x-api-key")
        }
        self.client.headers.update(attack_headers)

        start = time.monotonic()
        result, error = await self.client.graphql_query(query)
        duration = time.monotonic() - start

        self._record_response_time(duration)

        if not error and self._has_data(result):
            self.add_finding(Finding(
                title=f"Unauth Access: {name}",
                severity="MEDIUM",
                description=(
                    f"{description}. Query returned data without authentication. "
                    f"Evidence: {json.dumps(result, default=str)[:500]}"
                ),
                endpoint=self.client.endpoint or "",
            ))

            if self.logger:
                self.logger.log_request(
                    module=self.MODULE_NAME,
                    test=name,
                    parameter="-",
                    payload=query,
                    status="VULNERABLE",
                    response=result,
                    duration=duration,
                )

        self.client.headers = original_headers

    # ------------------------------------------------------------------ #
    #  Query builders
    # ------------------------------------------------------------------ #

    def _build_minimal_query(self, name: str, field: Optional[Dict]) -> Optional[str]:
        """Build a minimal query for a field. Returns None if required args exist."""
        if not field:
            return None
        args = field.get("args", [])
        if any(self._is_required(a) for a in args):
            return None
        selection = self._build_selection_set(field)
        return f"{{ {name} {selection} }}"

    def _build_minimal_mutation(self, name: str, field: Optional[Dict]) -> Optional[str]:
        """Build a minimal mutation for a field. Returns None if required args exist."""
        if not field:
            return None
        args = field.get("args", [])
        if any(self._is_required(a) for a in args):
            return None
        selection = self._build_selection_set(field)
        return f"mutation {{ {name} {selection} }}"

    def _build_selection_set(self, field: Dict) -> str:
        """
        Build a selection set from a field's return type.
        Picks up to 5 scalar fields from the return type, falls back to __typename.
        """
        return_type = field.get("type", {})
        if not return_type:
            return "{ __typename }"

        type_name = self._unwrap_type(return_type)
        if type_name in ("String", "Int", "Float", "Boolean", "ID"):
            return ""

        # Look up the type in the schema to find scalar sub-fields
        if self.client.schema:
            for t in self.client.schema.get("types", []):
                if t.get("name") == type_name and t.get("fields"):
                    scalar_fields = [
                        f["name"]
                        for f in t["fields"]
                        if self._is_scalar_field(f)
                    ][:5]
                    if scalar_fields:
                        return "{ " + " ".join(scalar_fields) + " }"

        return "{ __typename }"

    # ------------------------------------------------------------------ #
    #  Type helpers
    # ------------------------------------------------------------------ #

    def _unwrap_type(self, type_info: Optional[Dict]) -> str:
        """Unwrap NON_NULL and LIST wrappers to get the base type name."""
        while type_info and type_info.get("kind") in ("NON_NULL", "LIST"):
            type_info = type_info.get("ofType", {})
        return type_info.get("name", "") if type_info else ""

    def _is_scalar_field(self, field: Dict) -> bool:
        """Check if a field returns a scalar type."""
        t = field.get("type", {})
        name = self._unwrap_type(t)
        return name in ("String", "Int", "Float", "Boolean", "ID")

    def _is_required(self, arg: Dict) -> bool:
        """Check if an argument is NON_NULL (required)."""
        return arg.get("type", {}).get("kind") == "NON_NULL"

    def _is_safe_to_probe(self, field: Dict) -> bool:
        """Heuristic: a mutation is 'safe' to baseline if it has no required args."""
        args = field.get("args", [])
        return not any(self._is_required(a) for a in args)

    # ------------------------------------------------------------------ #
    #  Response analysis
    # ------------------------------------------------------------------ #

    def _response_matches_baseline(self, response: Any, baseline: Any) -> bool:
        """
        Auth bypass confirmed if the unauthenticated response has the same
        data keys as the authenticated baseline.
        """
        if not isinstance(response, dict) or not isinstance(baseline, dict):
            return False

        resp_data = response.get("data")
        base_data = baseline.get("data")

        if resp_data is None or base_data is None:
            return False

        # If unauth has errors but auth didn't, it's not a bypass
        if response.get("errors") and not baseline.get("errors"):
            return False

        if isinstance(resp_data, dict) and isinstance(base_data, dict):
            return set(resp_data.keys()) == set(base_data.keys())

        return resp_data is not None

    def _has_data(self, response: Any) -> bool:
        """Check if a response contains non-null data."""
        if not isinstance(response, dict):
            return False
        data = response.get("data")
        if data is None:
            return False
        if isinstance(data, dict):
            return any(v is not None for v in data.values())
        return True

    # ------------------------------------------------------------------ #
    #  Main entry point
    # ------------------------------------------------------------------ #

    async def run_test(self) -> None:
        """Execute all authentication tests."""

        # Step 1: Baseline (only if auth headers were provided)
        if self._auth_headers:
            await self._establish_baseline()
        else:
            if self.logger:
                self.logger.log_request(
                    module=self.MODULE_NAME,
                    test="baseline",
                    status="skipped",
                    parameter="No auth headers — testing unauth access only",
                )

        # Step 2: Load test cases (auto-loaded by parent, but check)
        if not self.test_cases:
            self.test_cases = self.loader.load_module("auth") if self.loader else []

        if not self.test_cases:
            self.printer.print_msg(
                "No auth test cases found in test_cases/auth/", status="warning"
            )
            return

        # Step 3: Dispatch by strategy
        strategy_dispatch = {
            "header_bypass": self._test_header_bypass,
            "idor": self._test_idor,
            "raw_query": self._test_raw_query,
        }

        for tc in self.test_cases:
            strategy = tc.get("strategy", "")
            handler = strategy_dispatch.get(strategy)

            if handler:
                # header_bypass requires a baseline to compare against
                if strategy == "header_bypass" and not self._baselines:
                    continue
                await handler(tc)
            else:
                if self.logger:
                    self.logger.log_error(
                        module=self.MODULE_NAME,
                        test=tc.get("name", "unknown"),
                        message=f"Unknown auth strategy: {strategy}",
                    )