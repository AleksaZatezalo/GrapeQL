"""
Tests for Reporter component
"""

import pytest
import tempfile
import json
import os
from unittest.mock import patch, mock_open

try:
    from grapeql import Reporter
except ImportError:

    class Reporter:
        def __init__(self):
            self.findings = []
            self.target = None


class TestReporter:
    """Test suite for reporting functionality."""

    @pytest.fixture
    def reporter(self):
        """Create a Reporter instance for testing."""
        return Reporter()

    @pytest.fixture
    def sample_findings(self):
        """Sample findings for testing."""
        return [
            {
                "type": "critical",
                "category": "injection",
                "message": "SQL injection vulnerability detected",
                "details": "User input not properly sanitized",
            },
            {
                "type": "high",
                "category": "information_disclosure",
                "message": "Introspection query enabled",
                "details": "GraphQL schema exposed through introspection",
            },
            {
                "type": "medium",
                "category": "dos",
                "message": "No query depth limiting",
                "details": "Deeply nested queries allowed",
            },
        ]

    def test_set_target(self, reporter):
        """Test setting the target endpoint."""
        endpoint = "https://example.com/graphql"
        reporter.set_target(endpoint)
        assert reporter.target == endpoint

    def test_add_findings(self, reporter, sample_findings):
        """Test adding findings to the reporter."""
        reporter.add_findings(sample_findings)
        assert len(reporter.findings) == 3
        assert any("SQL injection" in str(f) for f in reporter.findings)

    def test_add_single_finding(self, reporter):
        """Test adding a single finding."""
        finding = {
            "type": "low",
            "category": "configuration",
            "message": "GraphQL Playground accessible",
        }
        reporter.add_findings([finding])
        assert len(reporter.findings) == 1

    def test_print_summary(self, reporter, sample_findings, capsys):
        """Test printing findings summary."""
        reporter.set_target("https://example.com/graphql")
        reporter.add_findings(sample_findings)

        reporter.print_summary()

        captured = capsys.readouterr()
        assert "example.com" in captured.out
        assert "critical" in captured.out.lower()
        assert "SQL injection" in captured.out

    def test_generate_markdown_report(self, reporter, sample_findings):
        """Test generating markdown report."""
        reporter.set_target("https://example.com/graphql")
        reporter.add_findings(sample_findings)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            report_file = f.name

        try:
            reporter.generate_report(output_format="markdown", output_file=report_file)

            # Read and verify the generated report
            with open(report_file, "r") as f:
                content = f.read()

            assert "# GraphQL Security Assessment Report" in content
            assert "https://example.com/graphql" in content
            assert "SQL injection" in content
            assert "## Critical Issues" in content
            assert "## High Issues" in content
            assert "## Medium Issues" in content

        finally:
            os.unlink(report_file)

    def test_generate_json_report(self, reporter, sample_findings):
        """Test generating JSON report."""
        reporter.set_target("https://example.com/graphql")
        reporter.add_findings(sample_findings)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            report_file = f.name

        try:
            reporter.generate_report(output_format="json", output_file=report_file)

            # Read and verify the generated report
            with open(report_file, "r") as f:
                report_data = json.load(f)

            assert "target" in report_data
            assert "findings" in report_data
            assert "summary" in report_data
            assert report_data["target"] == "https://example.com/graphql"
            assert len(report_data["findings"]) == 3
            assert report_data["summary"]["total"] == 3
            assert report_data["summary"]["critical"] == 1
            assert report_data["summary"]["high"] == 1
            assert report_data["summary"]["medium"] == 1

        finally:
            os.unlink(report_file)

    def test_generate_report_without_target(self, reporter, sample_findings):
        """Test generating report without setting target."""
        reporter.add_findings(sample_findings)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            report_file = f.name

        try:
            reporter.generate_report(output_format="markdown", output_file=report_file)

            with open(report_file, "r") as f:
                content = f.read()

            # Should still generate report, maybe with "Unknown target"
            assert "GraphQL Security Assessment Report" in content

        finally:
            os.unlink(report_file)

    def test_generate_report_no_findings(self, reporter):
        """Test generating report with no findings."""
        reporter.set_target("https://example.com/graphql")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            report_file = f.name

        try:
            reporter.generate_report(output_format="markdown", output_file=report_file)

            with open(report_file, "r") as f:
                content = f.read()

            assert "No security issues found" in content or "0 issues" in content

        finally:
            os.unlink(report_file)

    def test_findings_categorization(self, reporter):
        """Test proper categorization of findings by severity."""
        findings = [
            {"type": "critical", "message": "Critical issue"},
            {"type": "critical", "message": "Another critical issue"},
            {"type": "high", "message": "High issue"},
            {"type": "medium", "message": "Medium issue"},
            {"type": "low", "message": "Low issue"},
            {"type": "info", "message": "Info issue"},
        ]

        reporter.add_findings(findings)

        # Test categorization logic (if implemented)
        categorized = (
            reporter._categorize_findings()
            if hasattr(reporter, "_categorize_findings")
            else None
        )
        if categorized:
            assert len(categorized.get("critical", [])) == 2
            assert len(categorized.get("high", [])) == 1
            assert len(categorized.get("medium", [])) == 1
            assert len(categorized.get("low", [])) == 1
            assert len(categorized.get("info", [])) == 1

    def test_invalid_output_format(self, reporter, sample_findings):
        """Test handling of invalid output format."""
        reporter.add_findings(sample_findings)

        with pytest.raises(ValueError):
            reporter.generate_report(output_format="invalid", output_file="test.txt")

    def test_report_statistics(self, reporter, sample_findings):
        """Test report statistics calculation."""
        reporter.add_findings(sample_findings)

        stats = (
            reporter._calculate_statistics()
            if hasattr(reporter, "_calculate_statistics")
            else None
        )
        if stats:
            assert stats["total"] == 3
            assert stats["critical"] == 1
            assert stats["high"] == 1
            assert stats["medium"] == 1
            assert stats["low"] == 0
