"""
GrapeQL Utilities
Author: Aleksa Zatezalo
Version: 3.1
Date: February 2025
Description: Utility functions and classes for GrapeQL
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional


class GrapePrinter:
    """
    Colored console output formatting for the GrapeQL tool.
    """

    PURPLE = "\033[95m"
    CYAN = "\033[96m"
    DARKCYAN = "\033[36m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    END = "\033[0m"

    def print_grapes(self):
        """Print the GrapeQL ASCII art logo."""
        print(
            self.PURPLE
            + self.BOLD
            + """
                __
            __ {_/  
        \\_}\\ _
            _\\(_)_  
            (_)_)(_)_
            (_)(_)_)(_)
            (_)(_))_)
            (_(_(_)
            (_)_)
                (_)
        """
        )

    def print_title(self):
        """Print the GrapeQL title and author information."""
        print(self.PURPLE + self.BOLD + "GrapeQL By Aleksa Zatezalo\n\n" + self.END)

    def print_msg(self, message: str, status: str = "log"):
        """
        Print a formatted message with status indicator.

        Args:
            message: The message text to display
            status: "success", "warning", "error"/"failed", or "log" (default)
        """
        if status == "success":
            print(self.GREEN + "\n[+] " + message + self.END)
        elif status == "warning":
            print(self.YELLOW + "[!] " + message + self.END)
        elif status in ("error", "failed"):
            print(self.RED + "[-] " + message + self.END)
        else:
            print(self.CYAN + "[!] " + message + self.END)

    def print_notify(self):
        """Display example notifications for different message types."""
        time.sleep(0.25)
        print(self.BOLD + "EXAMPLE NOTIFICATIONS:" + self.END)
        time.sleep(0.5)
        self.print_msg("Good news is printed like this.", status="success")
        time.sleep(0.5)
        self.print_msg("Warnings are printed like this.", status="warning")
        time.sleep(0.5)
        self.print_msg("Errors are printed like this.", status="error")
        time.sleep(0.5)
        self.print_msg("Logs are printed like this.", status="log")
        time.sleep(0.5)

    def intro(self):
        """Display the complete GrapeQL introduction sequence."""
        self.print_grapes()
        self.print_title()
        self.print_notify()

    def print_vulnerability(
        self, title: str, severity: str, details: Optional[str] = None
    ):
        """Print a formatted vulnerability finding."""
        severity = severity.upper()
        color = self.RED if severity in ("HIGH", "CRITICAL") else (
            self.YELLOW if severity == "MEDIUM" else self.BLUE
        )
        print(f"\n{color}{self.BOLD}[{severity}] {title}{self.END}")
        if details:
            print(f"  {details}")

    def print_section(self, title: str):
        """Print a section header."""
        print(f"\n{self.BOLD}{self.PURPLE}=== {title} ==={self.END}\n")


@dataclass
class Finding:
    """Represents a security finding/vulnerability with standardized attributes."""

    title: str
    severity: str
    description: str
    endpoint: str
    impact: Optional[str] = None
    remediation: Optional[str] = None
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))

    def __post_init__(self):
        self.severity = self.severity.upper()

    def to_dict(self) -> Dict:
        """Convert finding to dictionary representation."""
        return {
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "endpoint": self.endpoint,
            "impact": self.impact,
            "remediation": self.remediation,
            "timestamp": self.timestamp,
        }

    def __str__(self) -> str:
        return f"{self.severity} - {self.title} - {self.endpoint}"