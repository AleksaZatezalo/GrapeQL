"""
GrapeQL Reporter
Author: Aleksa Zatezalo
Version: 2.2
Date: February 2025
Description: Report generation for GrapeQL findings.
             v2.2: Added AI analysis section support.
"""

import os
import json
import time
import threading
from typing import Dict, List, Optional
from .utils import GrapePrinter, Finding

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_DEFAULT_COUNTS = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}


class Reporter:
    """Generates reports from GrapeQL findings in various formats."""

    def __init__(self):
        self.printer = GrapePrinter()
        self.findings: List[Finding] = []
        self.target = "unknown"
        self.scan_time = time.strftime("%Y-%m-%d_%H-%M-%S")
        self._ai_summary: Optional[str] = None
        self._lock = threading.Lock()

    def set_target(self, target: str) -> None:
        self.target = target

    def set_ai_summary(self, summary: str) -> None:
        """Store the AI-generated analysis section for inclusion in reports."""
        self._ai_summary = summary

    def add_findings(self, findings: List[Finding]) -> None:
        for finding in findings:
            self._add_finding_deduplicated(finding)

    def add_finding(self, finding: Finding) -> None:
        self._add_finding_deduplicated(finding)

    def _add_finding_deduplicated(self, finding: Finding) -> None:
        # Guard against concurrent additions when tests run in parallel
        with self._lock:
            if not any(
                f.title == finding.title and f.endpoint == finding.endpoint
                for f in self.findings
            ):
                self.findings.append(finding)

    # ------------------------------------------------------------------ #
    #  Shared helpers
    # ------------------------------------------------------------------ #

    def _severity_counts(self) -> Dict[str, int]:
        """Count findings by severity level."""
        counts = _DEFAULT_COUNTS.copy()
        for f in self.findings:
            key = f.severity if f.severity in counts else "INFO"
            counts[key] += 1
        return counts

    def _sorted_findings(self) -> List[Finding]:
        """Return findings sorted by severity (CRITICAL first)."""
        return sorted(
            self.findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 5)
        )

    # ------------------------------------------------------------------ #
    #  Console summary
    # ------------------------------------------------------------------ #

    def print_summary(self) -> None:
        self.printer.print_section("Findings Summary")

        if not self.findings:
            self.printer.print_msg("No vulnerabilities found", status="success")
            return

        counts = self._severity_counts()

        print("\nSeverity Breakdown:")
        _color_map = {
            "CRITICAL": f"{self.printer.RED}{self.printer.BOLD}",
            "HIGH": self.printer.RED,
            "MEDIUM": self.printer.YELLOW,
            "LOW": self.printer.BLUE,
        }
        for sev, count in counts.items():
            if count > 0:
                color = _color_map.get(sev, "")
                end = self.printer.END if color else ""
                print(f"  {color}{sev}: {count}{end}")

        print(f"\nTotal: {len(self.findings)} findings\n")

        if counts["CRITICAL"] > 0 or counts["HIGH"] > 0:
            self.printer.print_msg("Critical/High Severity Findings:", status="warning")
            for finding in self.findings:
                if finding.severity in ("CRITICAL", "HIGH"):
                    print(
                        f"{self.printer.RED}{finding.severity}: "
                        f"{finding.title} - {finding.endpoint}{self.printer.END}"
                    )

        if self._ai_summary:
            self.printer.print_section("AI Analysis")
            print(self._ai_summary)

    # ------------------------------------------------------------------ #
    #  Markdown report
    # ------------------------------------------------------------------ #

    def generate_markdown(self, output_file: str) -> None:
        counts = self._severity_counts()

        report = f"""# GrapeQL Security Assessment Report

## Target: {self.target}
## Date: {time.strftime("%Y-%m-%d %H:%M:%S")}

## Executive Summary

GrapeQL conducted a security assessment of the GraphQL API at {self.target}. This report details the findings and recommendations.

## Findings Summary

| Severity | Count |
|----------|-------|
"""
        for severity, count in counts.items():
            report += f"| {severity} | {count} |\n"

        report += f"\nTotal: {len(self.findings)} findings\n\n"
        report += "## Detailed Findings\n\n"

        for i, finding in enumerate(self._sorted_findings()):
            report += f"### {i+1}. {finding.title}\n\n"
            report += f"**Severity:** {finding.severity}\n\n"
            report += f"**Endpoint:** {finding.endpoint}\n\n"
            report += f"**Description:** {finding.description}\n\n"
            if finding.impact:
                report += f"**Impact:** {finding.impact}\n\n"
            if finding.remediation:
                report += f"**Remediation:** {finding.remediation}\n\n"
            report += "---\n\n"

        # Remediation summary
        report += "## Remediation Summary\n\n"
        remediations: Dict[str, List[str]] = {}
        for f in self.findings:
            if f.remediation:
                remediations.setdefault(f.remediation, []).append(f.title)

        for remediation, titles in remediations.items():
            report += f"### {remediation}\n\nApplies to:\n\n"
            for title in titles:
                report += f"- {title}\n"
            report += "\n"

        # AI Analysis section (appended after remediation summary)
        if self._ai_summary:
            report += "\n---\n\n"
            report += self._ai_summary
            report += "\n"

        try:
            os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
            with open(output_file, "w") as fh:
                fh.write(report)
            self.printer.print_msg(f"Report written to {output_file}", status="success")
        except Exception as e:
            self.printer.print_msg(f"Error writing report: {str(e)}", status="error")

    # ------------------------------------------------------------------ #
    #  JSON report
    # ------------------------------------------------------------------ #

    def generate_json(self, output_file: str) -> None:
        report_data = {
            "target": self.target,
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }

        if self._ai_summary:
            report_data["ai_analysis"] = self._ai_summary

        try:
            os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
            with open(output_file, "w") as fh:
                json.dump(report_data, fh, indent=2)
            self.printer.print_msg(
                f"JSON report written to {output_file}", status="success"
            )
        except Exception as e:
            self.printer.print_msg(
                f"Error writing JSON report: {str(e)}", status="error"
            )

    # ------------------------------------------------------------------ #
    #  Dispatch
    # ------------------------------------------------------------------ #

    def generate_report(
        self, output_format: str = "markdown", output_file: str = None
    ) -> None:
        if not output_file:
            self.printer.print_msg("No output file specified", status="error")
            return

        fmt = output_format.lower()
        if fmt in ("markdown", "md"):
            self.generate_markdown(output_file)
        elif fmt == "json":
            self.generate_json(output_file)
        else:
            self.printer.print_msg(
                f"Unsupported report format: {output_format}", status="error"
            )
            self.printer.print_msg("Supported formats: markdown, json", status="error")

        self.print_summary()