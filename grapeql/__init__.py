"""
GrapeQL - A GraphQL Security Testing Tool

Author: Aleksa Zatezalo
Version: 2.0.0
"""

from .vine import vine
from .root import root
from .crush import crush
from .seeds import seeds
from .juice import juice
from .grapePrint import grapePrint
from .http_client import GraphQLClient
from .schema_manager import SchemaManager
from .base_tester import BaseTester
from .report import generate_report

__version__ = '2.0.0'
__all__ = [
    'vine', 
    'root', 
    'crush', 
    'seeds', 
    'juice', 
    'grapePrint',
    'GraphQLClient',
    'SchemaManager',
    'BaseTester',
    'generate_report'
]

# Export main function for CLI usage
from .grapeql import run_cli