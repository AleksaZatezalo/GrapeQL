"""
GrapeQL Base Vulnerability Tester
Author: Aleksa Zatezalo
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
        
    async def setup_endpoint(self, endpoint: str, proxy: Optional[str] = None, pre_configured_client: Optional[GraphQLClient] = None) -> bool:
        """
        Set up the testing environment with the target endpoint.
        
        Args:
            endpoint: GraphQL endpoint URL
            proxy: Optional proxy in host:port format
            pre_configured_client: Optional pre-configured client with cookies, auth tokens, etc.
            
        Returns:
            bool: True if setup was successful
        """
        if pre_configured_client:
            # Copy all relevant properties from the pre-configured client
            self.client.endpoint = pre_configured_client.endpoint
            self.client.proxy_url = pre_configured_client.proxy_url
            self.client.headers = pre_configured_client.headers.copy()
            self.client.cookies = pre_configured_client.cookies.copy()
            self.client.auth_token = pre_configured_client.auth_token
            self.client.schema = pre_configured_client.schema
            self.client.query_fields = pre_configured_client.query_fields.copy() if pre_configured_client.query_fields else {}
            self.client.mutation_fields = pre_configured_client.mutation_fields.copy() if pre_configured_client.mutation_fields else {}
            
            # If the pre-configured client already has schema data, consider setup successful
            if pre_configured_client.schema:
                return True
                
        # Proceed with normal setup if no pre-configured client or it has no schema
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