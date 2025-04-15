"""
GrapeQL Base Vulnerability Tester
Author: Aleksa Zatezalo (Simplified by Claude)
Version: 2.0
Date: April 2025
Description: Base class for vulnerability testing modules
"""

from typing import Dict, List, Optional, Any, Tuple
from .client import GraphQLClient
from .utils import GrapePrinter, Finding

class VulnerabilityTester:
    """
    Base class for all vulnerability testing modules with common functionality.
    """
    
    def __init__(self):
        """Initialize the vulnerability tester with GraphQL client."""
        self.client = GraphQLClient()
        self.printer = GrapePrinter()
        self.findings = []
        self.test_name = "Base Vulnerability Test"
        
    async def setup_endpoint(self, endpoint: str, proxy: Optional[str] = None) -> bool:
        """
        Set up the testing environment with the target endpoint.
        
        Args:
            endpoint: GraphQL endpoint URL
            proxy: Optional proxy in host:port format
            
        Returns:
            bool: True if setup was successful
        """
        return await self.client.setup_endpoint(endpoint, proxy)
        
    def add_finding(self, finding: Finding) -> None:
        """
        Add a finding to the results.
        
        Args:
            finding: Finding object
        """
        self.findings.append(finding)
        severity = finding.severity.upper()
        
        if severity in ["HIGH", "CRITICAL"]:
            status = "failed"
        elif severity == "MEDIUM":
            status = "warning"
        else:
            status = "log"
            
        self.printer.print_msg(f"{severity}: {finding.title}", status=status)
        
    def set_credentials(self, username: str, password: str) -> None:
        """
        Set credentials for use in testing authentication-related issues.
        
        Args:
            username: Username for testing
            password: Password for testing
        """
        self.username = username
        self.password = password
        self.printer.print_msg(f"Set credentials: {username}:{password}", status="success")
        
    def get_findings(self) -> List[Finding]:
        """
        Get all findings from the test.
        
        Returns:
            List[Finding]: All findings
        """
        return self.findings
        
    async def run_test(self) -> List[Finding]:
        """
        Run all tests and return findings.
        This method should be overridden by subclasses.
        
        Returns:
            List[Finding]: Findings from the test
        """
        self.printer.print_msg("Base test class - no actual tests to run", status="warning")
        return self.findings