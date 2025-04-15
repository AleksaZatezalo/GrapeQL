"""
GrapeQL - A GraphQL Security Testing Tool

Author: Aleksa Zatezalo (Simplified by Claude)
Version: 2.0.0
Date: April 2025
"""

from .utils import GrapePrinter, Finding
from .client import GraphQLClient
from .scanner import Scanner
from .fingerprint import Fingerprinter
from .tester import VulnerabilityTester
from .injection_tester import InjectionTester
from .dos_tester import DosTester
from .info_tester import InfoTester
from .reporter import Reporter

__version__ = '2.0.0'
__author__ = 'Aleksa Zatezalo'
__all__ = [
    'GrapePrinter',
    'Finding',
    'GraphQLClient',
    'Scanner',
    'Fingerprinter',
    'VulnerabilityTester',
    'InjectionTester',
    'DosTester',
    'InfoTester',
    'Reporter'
]

# Export main function for CLI usage
from .cli import run_cli