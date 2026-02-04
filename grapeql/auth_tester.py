"""
GrapeQL Authentication Tester
Author: Aleksa Zatezalo
Version: 3.1
Date: February 2025
Description: Tests for authentication bypass, IDOR, and field-level
             authorization failures in GraphQL APIs.
"""

import json
from typing import Any, Dict, List, Optional

from .tester import BaseTester


class AuthTester(BaseTester):
    """
    Tests authentication and authorization controls.

    Approach:
        1. Establish an authenticated baseline by running every query/mutation
           with the user-supplied credentials.
        2. Replay those same requests with manipulated headers (from YAML).
        3. Compare responses — if the unauthenticated response returns data
           that matches the authenticated baseline, auth is broken.
    """

    MODULE_NAME = "AuthTester"

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
        self.logger.log_request(
            module=self.MODULE_NAME,
            test="baseline",
            status="started",
            parameter="-",
        )

        original_headers = self.client.custom_headers.copy()
        self.client.custom_headers.update(self._auth_headers)

        for name, field in self.client.query_fields.items():
            query = self._build_minimal_query(name, field)
            if query:
                result = await self.client.graphql_query(query)
                self._baselines[f"query:{name}"] = result

        for name, field in self.client.mutation_fields.items():
            # Only probe mutations that look safe to call without side effects
            # (read-only-ish: ones returning data without required non-ID args)
            if self._is_safe_to_probe(field):
                query = self._build_minimal_mutation(name, field)
                if query:
                    result = await self.client.graphql_query(query)
                    self._baselines[f"mutation:{name}"] = result

        self.client.custom_headers = original_headers

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

        original_headers = self.client.custom_headers.copy()
        # Strip existing auth headers, apply attack headers
        self.client.custom_headers = {
            k: v
            for k, v in original_headers.items()
            if k.lower() not in ("authorization", "cookie", "x-api-key")
        }
        self.client.custom_headers.update(attack_headers)

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

            start = self._timer()
            result = await self.client.graphql_query(query)
            duration = self._timer() - start

            self.baseline.record(self.MODULE_NAME, duration)

            if self._response_matches_baseline(result, baseline_response):
                self._add_finding(
                    title=f"Auth Bypass: {name} on {field_name}",
                    severity="HIGH",
                    description=(
                        f"{description}. The {kind} '{field_name}' returned "
                        f"data identical to the authenticated baseline when "
                        f"using manipulated headers: {json.dumps(attack_headers)}"
                    ),
                    evidence=json.dumps(result, default=str)[:500],
                )

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
                self.logger.log_request(
                    module=self.MODULE_NAME,
                    test=name,
                    parameter=field_name,
                    payload=json.dumps(attack_headers),
                    status="blocked",
                    response=result,
                    duration=duration,
                )

        self.client.custom_headers = original_headers

    async def _test_idor(self, test_case: Dict) -> None:
        """
        Enumerate sequential IDs on queries/mutations that accept ID arguments.
        If we get data for IDs we shouldn't have access to, it's an IDOR.
        """
        name = test_case["name"]
        id_range = test_case.get("id_range", [1, 20])

        # Find all fields that take an id/ID argument
        id_fields = []
        for field_name, field in self.client.query_fields.items():
            args = field.get("args", {})
            for arg_name, arg_info in args.items():
                if arg_name.lower() in ("id", "userid", "user_id", "accountid"):
                    id_fields.append((field_name, arg_name, field, "query"))
                    break

        for field_name, field in self.client.mutation_fields.items():
            args = field.get("args", {})
            for arg_name, arg_info in args.items():
                if arg_name.lower() in ("id", "userid", "user_id", "accountid"):
                    id_fields.append((field_name, arg_name, field, "mutation"))
                    break

        accessible_ids = []

        for field_name, arg_name, field, kind in id_fields:
            for test_id in range(id_range[0], id_range[1] + 1):
                selection = self._build_selection_set(field)
                if kind == "query":
                    query = f'{{ {field_name}({arg_name}: "{test_id}") {selection} }}'
                else:
                    query = f'mutation {{ {field_name}({arg_name}: "{test_id}") {selection} }}'

                start = self._timer()
                result = await self.client.graphql_query(query)
                duration = self._timer() - start

                self.baseline.record(self.MODULE_NAME, duration)

                if self._has_data(result):
                    accessible_ids.append(test_id)

            if len(accessible_ids) > 1:
                self._add_finding(
                    title=f"IDOR: {field_name} exposes sequential IDs",
                    severity="HIGH",
                    description=(
                        f"The {kind} '{field_name}' returned data for "
                        f"{len(accessible_ids)} different IDs via the "
                        f"'{arg_name}' argument. Accessible IDs: "
                        f"{accessible_ids[:10]}{'...' if len(accessible_ids) > 10 else ''}"
                    ),
                    evidence=f"Tested range {id_range[0]}-{id_range[1]}, "
                    f"{len(accessible_ids)} returned data",
                )

            accessible_ids.clear()

    async def _test_raw_query(self, test_case: Dict) -> None:
        """Send a raw query with specific headers (e.g. introspection without auth)."""
        name = test_case["name"]
        query = test_case["query"]
        attack_headers = test_case.get("headers", {})
        description = test_case.get("description", "")

        original_headers = self.client.custom_headers.copy()
        self.client.custom_headers = {
            k: v
            for k, v in original_headers.items()
            if k.lower() not in ("authorization", "cookie", "x-api-key")
        }
        self.client.custom_headers.update(attack_headers)

        start = self._timer()
        result = await self.client.graphql_query(query)
        duration = self._timer() - start

        self.baseline.record(self.MODULE_NAME, duration)

        if self._has_data(result):
            self._add_finding(
                title=f"Unauth Access: {name}",
                severity="MEDIUM",
                description=f"{description}. Query returned data without authentication.",
                evidence=json.dumps(result, default=str)[:500],
            )

        self.client.custom_headers = original_headers

    # ------------------------------------------------------------------ #
    #  Helpers
    # ------------------------------------------------------------------ #

    def _build_minimal_query(self, name: str, field: Dict) -> Optional[str]:
        """Build a minimal query string for a given field."""
        if not field:
            return None
        selection = self._build_selection_set(field)
        args = field.get("args", {})
        if any(self._is_required(a) for a in args.values()):
            # Skip fields with required args we can't guess
            return None
        return f"{{ {name} {selection} }}"

    def _build_minimal_mutation(self, name: str, field: Dict) -> Optional[str]:
        """Build a minimal mutation string for a given field."""
        if not field:
            return None
        selection = self._build_selection_set(field)
        args = field.get("args", {})
        if any(self._is_required(a) for a in args.values()):
            return None
        return f"mutation {{ {name} {selection} }}"

    def _build_selection_set(self, field: Dict) -> str:
        """Build a selection set from a field's return type."""
        return_type = field.get("type", {})
        type_name = self._unwrap_type(return_type)
        if type_name in ("String", "Int", "Float", "Boolean", "ID"):
            return ""

        # Find the type in the schema and pick the first few scalar fields
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

    def _unwrap_type(self, type_info: Dict) -> str:
        """Unwrap NON_NULL and LIST wrappers to get the base type name."""
        while type_info and type_info.get("kind") in ("NON_NULL", "LIST"):
            type_info = type_info.get("ofType", {})
        return type_info.get("name", "")

    def _is_scalar_field(self, field: Dict) -> bool:
        """Check if a field returns a scalar type."""
        t = field.get("type", {})
        name = self._unwrap_type(t)
        return name in ("String", "Int", "Float", "Boolean", "ID")

    def _is_required(self, arg: Dict) -> bool:
        """Check if an argument is NON_NULL (required)."""
        return arg.get("type", {}).get("kind") == "NON_NULL"

    def _is_safe_to_probe(self, field: Dict) -> bool:
        """Heuristic: a mutation is 'safe' if it has no required args."""
        args = field.get("args", {})
        return not any(self._is_required(a) for a in args.values())

    def _response_matches_baseline(self, response: Any, baseline: Any) -> bool:
        """
        Compare two responses. Auth bypass is confirmed if the unauthenticated
        response contains the same data keys as the authenticated one.
        """
        if not isinstance(response, dict) or not isinstance(baseline, dict):
            return False

        resp_data = response.get("data")
        base_data = baseline.get("data")

        if resp_data is None or base_data is None:
            return False

        # If the unauth response has data and no errors, it's a match
        if response.get("errors") and not baseline.get("errors"):
            return False

        # Key-level comparison: same data keys present
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

    def _timer(self) -> float:
        import time
        return time.monotonic()

    # ------------------------------------------------------------------ #
    #  Main entry point
    # ------------------------------------------------------------------ #

    async def run_test(self) -> None:
        """Execute all authentication tests."""

        # Step 1: Establish authenticated baseline
        if self._auth_headers:
            await self._establish_baseline()
        else:
            self.logger.log_request(
                module=self.MODULE_NAME,
                test="baseline",
                status="skipped",
                parameter="No auth headers provided — testing unauth access only",
            )

        # Step 2: Load and execute YAML test cases
        test_cases = self.loader.load_module("auth")
        if not test_cases:
            self.logger.log_request(
                module=self.MODULE_NAME,
                test="load",
                status="warning",
                parameter="No auth test cases found",
            )
            return

        strategy_dispatch = {
            "header_bypass": self._test_header_bypass,
            "idor": self._test_idor,
            "raw_query": self._test_raw_query,
        }

        for tc in test_cases:
            strategy = tc.get("strategy", "")
            handler = strategy_dispatch.get(strategy)
            if handler:
                await handler(tc)
            else:
                self.logger.log_error(
                    module=self.MODULE_NAME,
                    test=tc.get("name", "unknown"),
                    message=f"Unknown strategy: {strategy}",
                )