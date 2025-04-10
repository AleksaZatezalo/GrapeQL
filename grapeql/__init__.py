"""
GrapeQL - A GraphQL Security Testing Tool

Author: Aleksa Zatezalo
Version: 2.0.0
"""

from grapeql.vine import vine
from grapeql.root import root
from grapeql.crush import crush
from grapeql.seeds import seeds
from grapeql.juice import juice
from grapeql.grapePrint import grapePrint
from grapeql.http_client import GraphQLClient
from grapeql.schema_manager import SchemaManager
from grapeql.base_tester import BaseTester
from grapeql.report import generate_report

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
from grapeql.grapeql import run_cli