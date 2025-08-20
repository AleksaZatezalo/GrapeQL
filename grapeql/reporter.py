"""
GrapeQL Reporter
Author: Aleksa Zatezalo
Version: 2.0
Date: April 2025
Description: Report generation for GrapeQL findings
"""

import os
import json
import time
from typing import Dict, List, Optional
from .utils import GrapePrinter, Finding


class Reporter:
    """
    Generates reports from GrapeQL findings in various formats with options.
    """

    def __init__(self):
        """Initialize the reporter."""
        self.printer = GrapePrinter()
        self.findings = []
        self.target = "unknown"
        self.scan_time = time.strftime("%Y-%m-%d_%H-%M-%S")

    def set_target(self, target: str) -> None:
        """
        Set the target name for the report.

        Args:
            target: Target name or URL
        """
        self.target = target

    def add_findings(self, findings: List[Finding]) -> None:
        """
        Add findings to the report, avoiding duplicates.

        Args:
            findings: List of findings to add
        """
        for finding in findings:
            self._add_finding_deduplicated(finding)

    def add_finding(self, finding: Finding) -> None:
        """
        Add a single finding to the report, avoiding duplicates.

        Args:
            finding: Finding to add
        """
        self._add_finding_deduplicated(finding)

    def _add_finding_deduplicated(self, finding: Finding) -> None:
        """
        Add a finding to the report only if it's not a duplicate.

        A finding is considered a duplicate if a finding with the same title and endpoint
        already exists in the findings list.

        Args:
            finding: Finding to add
        """
        # Check if this finding is a duplicate
        is_duplicate = False
        for existing in self.findings:
            if (
                existing.title == finding.title
                and existing.endpoint == finding.endpoint
            ):
                is_duplicate = True
                break

        # Only add if not a duplicate
        if not is_duplicate:
            self.findings.append(finding)

    def print_summary(self) -> None:
        """Print a summary of findings to the console."""
        self.printer.print_section("Findings Summary")

        if not self.findings:
            self.printer.print_msg("No vulnerabilities found", status="success")
            return

        # Count findings by severity
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

        for finding in self.findings:
            severity = finding.severity.upper()
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts["INFO"] += 1

        # Print counts
        print("\nSeverity Breakdown:")

        if severity_counts["CRITICAL"] > 0:
            print(
                f"  {self.printer.RED}{self.printer.BOLD}CRITICAL: {severity_counts['CRITICAL']}{self.printer.END}"
            )

        if severity_counts["HIGH"] > 0:
            print(
                f"  {self.printer.RED}HIGH: {severity_counts['HIGH']}{self.printer.END}"
            )

        if severity_counts["MEDIUM"] > 0:
            print(
                f"  {self.printer.YELLOW}MEDIUM: {severity_counts['MEDIUM']}{self.printer.END}"
            )

        if severity_counts["LOW"] > 0:
            print(
                f"  {self.printer.BLUE}LOW: {severity_counts['LOW']}{self.printer.END}"
            )

        if severity_counts["INFO"] > 0:
            print(f"  INFO: {severity_counts['INFO']}")

        print(f"\nTotal: {len(self.findings)} findings\n")

        # Print top findings
        if severity_counts["CRITICAL"] > 0 or severity_counts["HIGH"] > 0:
            self.printer.print_msg("Critical/High Severity Findings:", status="warning")

            for finding in self.findings:
                if finding.severity.upper() in ["CRITICAL", "HIGH"]:
                    color = self.printer.RED
                    print(
                        f"{color}{finding.severity}: {finding.title} - {finding.endpoint}{self.printer.END}"
                    )

    def generate_markdown(self, output_file: str) -> None:
        """
        Generate a Markdown report of all findings.

        Args:
            output_file: File path to write the report to
        """
        # Create report content
        report = f"""# GrapeQL Security Assessment Report

## Target: {self.target}
## Date: {time.strftime("%Y-%m-%d %H:%M:%S")}

## Executive Summary

GrapeQL conducted a security assessment of the GraphQL API at {self.target}. This report details the findings and recommendations.

## Findings Summary

| Severity | Count |
|----------|-------|
"""

        # Count findings by severity
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

        for finding in self.findings:
            severity = finding.severity.upper()
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts["INFO"] += 1

        # Add severity counts to report
        for severity, count in severity_counts.items():
            report += f"| {severity} | {count} |\n"

        report += f"\nTotal: {len(self.findings)} findings\n\n"

        # Add detailed findings
        report += "## Detailed Findings\n\n"

        # Sort findings by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

        sorted_findings = sorted(
            self.findings, key=lambda f: severity_order.get(f.severity.upper(), 5)
        )

        # Add each finding to the report
        for i, finding in enumerate(sorted_findings):
            report += f"### {i+1}. {finding.title}\n\n"
            report += f"**Severity:** {finding.severity}\n\n"
            report += f"**Endpoint:** {finding.endpoint}\n\n"
            report += f"**Description:** {finding.description}\n\n"

            if finding.impact:
                report += f"**Impact:** {finding.impact}\n\n"

            if finding.remediation:
                report += f"**Remediation:** {finding.remediation}\n\n"

            # Removed curl_command section

            report += "---\n\n"

        # Add remediation summary
        report += "## Remediation Summary\n\n"

        # Collect unique remediations
        remediations = {}
        for finding in self.findings:
            if finding.remediation:
                if finding.remediation not in remediations:
                    remediations[finding.remediation] = []
                remediations[finding.remediation].append(finding.title)

        # Add each remediation to the report
        for remediation, findings in remediations.items():
            report += f"### {remediation}\n\n"
            report += "Applies to:\n\n"
            for finding_title in findings:
                report += f"- {finding_title}\n"
            report += "\n"

        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)

            with open(output_file, "w") as f:
                f.write(report)

            self.printer.print_msg(f"Report written to {output_file}", status="success")
        except Exception as e:
            self.printer.print_msg(f"Error writing report: {str(e)}", status="error")

    def generate_json(self, output_file: str) -> None:
        """
        Generate a JSON report of all findings.

        Args:
            output_file: File path to write the report to
        """
        # Create report data
        report_data = {
            "target": self.target,
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "findings_count": len(self.findings),
            "findings": [],
        }

        # Convert findings to dict but exclude curl_command
        for finding in self.findings:
            finding_dict = finding.to_dict()
            # Remove curl_command if it exists
            if "curl_command" in finding_dict:
                del finding_dict["curl_command"]
            report_data["findings"].append(finding_dict)

        # Convert to JSON
        report_json = json.dumps(report_data, indent=2)

        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)

            with open(output_file, "w") as f:
                f.write(report_json)

            self.printer.print_msg(
                f"JSON report written to {output_file}", status="success"
            )
        except Exception as e:
            self.printer.print_msg(
                f"Error writing JSON report: {str(e)}", status="error"
            )

    def generate_report(
        self, output_format: str = "markdown", output_file: str = None
    ) -> None:
        """
        Generate a report in the specified format.

        Args:
            output_format: Report format (markdown or json)
            output_file: File path to write the report to
        """
        if not output_file:
            self.printer.print_msg("No output file specified", status="error")
            return

        if output_format.lower() == "markdown" or output_format.lower() == "md":
            self.generate_markdown(output_file)
        elif output_format.lower() == "json":
            self.generate_json(output_file)
        else:
            self.printer.print_msg(
                f"Unsupported report format: {output_format}", status="error"
            )
            self.printer.print_msg("Supported formats: markdown, json", status="error")

        # Always print summary to console
        self.print_summary()
