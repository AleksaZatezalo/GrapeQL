"""
GrapeQL Web scan runner.

Mirrors the orchestration in ``grapeql.cli.GrapeQL.main`` but returns the
findings as plain dictionaries instead of printing / writing a report, so the
web API can serve them as JSON.
"""

from typing import Dict, List, Optional, Any

from grapeql.utils import Finding
from grapeql.client import GraphQLClient
from grapeql.logger import GrapeLogger
from grapeql.loader import TestCaseLoader
from grapeql.baseline import BaselineTracker
from grapeql.reporter import Reporter

from grapeql.fingerprint import Fingerprinter
from grapeql.info_tester import InfoTester
from grapeql.injection_tester import InjectionTester
from grapeql.auth_tester import AuthTester
from grapeql.dos_tester import DosTester

ALL_MODULES = ["fingerprint", "info", "injection", "auth", "dos"]

MODULE_CLASSES = {
    "fingerprint": Fingerprinter,
    "info": InfoTester,
    "injection": InjectionTester,
    "auth": AuthTester,
    "dos": DosTester,
}

# Enforced execution order regardless of request order.
EXECUTION_ORDER = ["fingerprint", "info", "injection", "auth", "dos"]


class ScanError(Exception):
    """Raised when a scan cannot be completed (e.g. schema unavailable)."""


def _resolve_modules(requested: Optional[List[str]]) -> List[str]:
    if requested:
        wanted = set(requested)
    else:
        # Default: everything except the destructive DoS module.
        wanted = set(ALL_MODULES) - {"dos"}
    return [m for m in EXECUTION_ORDER if m in wanted]


async def _load_schema(
    client: GraphQLClient, schema_dict: Optional[Dict[str, Any]]
) -> bool:
    """Load a supplied schema, or fall back to live introspection."""
    if schema_dict:
        if "__schema" in schema_dict:
            schema_dict = schema_dict["__schema"]
        if not client.load_schema_from_dict(schema_dict):
            raise ScanError("Failed to parse the supplied schema JSON.")
        # Informational: probe live introspection but don't require it.
        try:
            await client.introspection_query()
        except Exception:
            pass
        client.load_schema_from_dict(schema_dict)
        return True

    if not await client.introspection_query():
        raise ScanError(
            "Introspection failed and no schema was supplied. Provide a schema "
            "JSON or ensure introspection is enabled on the target."
        )
    return True


async def run_scan(
    *,
    target: str,
    modules: Optional[List[str]] = None,
    test_cases_dir: str,
    proxy: Optional[str] = None,
    auth: Optional[str] = None,
    auth_type: str = "Bearer",
    cookies: Optional[List[str]] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    schema_dict: Optional[Dict[str, Any]] = None,
    log_lines: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Run a GrapeQL scan and return a JSON-serialisable result dict:

        {
          "target": str,
          "modules": [str],
          "findings": [ {finding dict}, ... ],
          "counts": {"CRITICAL": n, ...},
        }
    """
    logger = GrapeLogger()
    loader = TestCaseLoader(test_cases_dir)
    baseline = BaselineTracker()
    reporter = Reporter()
    reporter.set_target(target)

    def log(msg: str) -> None:
        if log_lines is not None:
            log_lines.append(msg)

    # -- Primary client + schema --
    primary = GraphQLClient(logger=logger)
    primary.set_endpoint(target)

    if proxy:
        try:
            host, port = proxy.split(":")
            primary.configure_proxy(host, int(port))
        except ValueError:
            log(f"Invalid proxy format ignored: {proxy}")

    if auth:
        primary.set_authorization(auth, auth_type)

    for cookie_str in cookies or []:
        try:
            name, value = cookie_str.split(":", 1)
            primary.set_cookie(name.strip(), value.strip())
        except ValueError:
            log(f"Invalid cookie format ignored: {cookie_str}")

    await _load_schema(primary, schema_dict)

    resolved = _resolve_modules(modules)
    log(f"Running modules: {', '.join(resolved)}")

    # The stack identified by the fingerprint module (engine, technologies,
    # CVEs). Forwarded to the exploit agent as one of its PoC inputs.
    stack: Optional[Dict[str, Any]] = None

    for module_name in resolved:
        cls = MODULE_CLASSES[module_name]
        instance = cls(logger=logger, loader=loader, baseline=baseline)

        if not await instance.setup_endpoint(target, proxy, primary):
            log(f"Skipping {module_name}: endpoint setup failed.")
            continue

        if auth and module_name == "auth":
            instance.set_auth_headers({"Authorization": f"{auth_type} {auth}"})

        if hasattr(instance, "set_credentials") and (username or password):
            instance.set_credentials(username or "admin", password or "changeme")

        await instance.run_test()
        if module_name == "fingerprint":
            stack = getattr(instance, "stack", None)
        reporter.add_findings(instance.get_findings())
        log(f"Finished {module_name}: {len(instance.get_findings())} findings")

    findings: List[Finding] = reporter._sorted_findings()

    return {
        "target": target,
        "modules": resolved,
        "findings": [f.to_dict() for f in findings],
        "counts": reporter._severity_counts(),
        "total": len(findings),
        # Return the introspected schema so the exploit agent can craft
        # valid queries without the operator having to paste it in.
        "schema": primary.schema,
        # Return the fingerprinted stack (engine, technologies, CVEs) so the
        # exploit agent can tailor a PoC to the identified implementation.
        "stack": stack,
    }
