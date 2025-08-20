"""
GrapeQL Utilities
Author: Aleksa Zatezalo
Version: 2.0
Date: April 2025
Description: Utility functions and classes for GrapeQL
"""

import time
from typing import Dict, List, Optional, Any, Union


class GrapePrinter:
    """
    A class for handling colored console output formatting for the GrapeQL tool.
    Provides methods for printing formatted messages, banners, and notifications.
    """

    def __init__(self):
        """
        Initialize the GrapePrinter class with ANSI color and style codes.
        """
        self.PURPLE = "\033[95m"
        self.CYAN = "\033[96m"
        self.DARKCYAN = "\033[36m"
        self.BLUE = "\033[94m"
        self.GREEN = "\033[92m"
        self.YELLOW = "\033[93m"
        self.RED = "\033[91m"
        self.BOLD = "\033[1m"
        self.UNDERLINE = "\033[4m"
        self.END = "\033[0m"

    def print_grapes(self):
        """
        Print the GrapeQL ASCII art logo in purple.
        """
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
        """
        Print the GrapeQL title and author information.
        """
        print(self.PURPLE + self.BOLD + "GrapeQL By Aleksa Zatezalo\n\n" + self.END)

    def print_msg(self, message: str, status: str = "log"):
        """
        Print a formatted message with appropriate status indicators and colors.

        Args:
            message: The message text to display
            status: The type of message to display. Valid options are:
                - "success" (green with [+])
                - "warning" (yellow with [!])
                - "error" or "failed" (red with [-])
                - "log" (cyan with [!], default)
        """
        plus = "\n[+] "
        exclaim = "[!] "
        fail = "[-] "

        if status == "success":
            print(self.GREEN + plus + message + self.END)
        elif status == "warning":
            print(self.YELLOW + exclaim + message + self.END)
        elif status in ["error", "failed"]:
            print(self.RED + fail + message + self.END)
        else:  # default to log
            print(self.CYAN + exclaim + message + self.END)

    def print_notify(self):
        """
        Display example notifications for different message types.
        """
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
        """
        Display the complete GrapeQL introduction sequence.
        """
        self.print_grapes()
        self.print_title()
        self.print_notify()

    def print_vulnerability(
        self, title: str, severity: str, details: Optional[str] = None
    ):
        """
        Print a formatted vulnerability finding.

        Args:
            title: The vulnerability title
            severity: Severity level (LOW, MEDIUM, HIGH, CRITICAL)
            details: Optional details about the vulnerability
        """
        severity = severity.upper()

        if severity == "HIGH" or severity == "CRITICAL":
            color = self.RED
        elif severity == "MEDIUM":
            color = self.YELLOW
        else:
            color = self.BLUE

        print(f"\n{color}{self.BOLD}[{severity}] {title}{self.END}")

        if details:
            print(f"  {details}")

    def print_section(self, title: str):
        """
        Print a section header.

        Args:
            title: Section title
        """
        print(f"\n{self.BOLD}{self.PURPLE}=== {title} ==={self.END}\n")


class Finding:
    """
    Represents a security finding/vulnerability with standardized attributes.
    """

    def __init__(
        self,
        title: str,
        severity: str,
        description: str,
        endpoint: str,
        impact: Optional[str] = None,
        remediation: Optional[str] = None,
    ):
        """
        Initialize a new finding.

        Args:
            title: Title of the finding
            severity: Severity level (LOW, MEDIUM, HIGH, CRITICAL)
            description: Description of the finding
            endpoint: Affected endpoint
            impact: Optional impact description
            remediation: Optional remediation instructions
        """
        self.title = title
        self.severity = severity.upper()
        self.description = description
        self.endpoint = endpoint
        self.impact = impact
        self.remediation = remediation
        self.timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

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
        """String representation of the finding."""
        return f"{self.severity} - {self.title} - {self.endpoint}"


def load_wordlist(path: str) -> List[str]:
    """
    Load a wordlist file into a list of strings.

    Args:
        path: Path to wordlist file

    Returns:
        List[str]: Lines from the wordlist file
    """
    try:
        with open(path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error loading wordlist from {path}: {str(e)}")
        return []


def load_json_file(path: str) -> Optional[Dict]:
    """
    Load and parse a JSON file.

    Args:
        path: Path to JSON file

    Returns:
        Optional[Dict]: Parsed JSON data or None on error
    """
    try:
        with open(path, "r") as f:
            import json

            return json.load(f)
    except Exception as e:
        print(f"Error loading JSON from {path}: {str(e)}")
        return None
