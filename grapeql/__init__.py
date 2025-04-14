"""
GrapeQL - A GraphQL Security Testing Tool (Simplified Version)

Author: Aleksa Zatezalo
Version: 3.0.0
"""

from .grapePrint import grapePrint
from .http_client import GraphQLHTTPClient
from .scanner import GraphQLScanner
from .schema_analyzer import SchemaAnalyzer
from .test_modules import SecurityTester
from .report import generate_report

__version__ = '3.0.0'
__all__ = [
    'grapePrint',
    'GraphQLHTTPClient',
    'GraphQLScanner',
    'SchemaAnalyzer',
    'SecurityTester',
    'generate_report'
]

# Export main function for CLI usage
from .grapeql import run_cli