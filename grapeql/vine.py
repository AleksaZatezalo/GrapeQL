"""
Author: Aleksa Zatezalo
Version: 1.0
Date: February 2025
Description: Enumeration script for GraphQL endpoints. Takes an IP and returns a list of endpoints with introspection enabled.
"""

import asyncio
import asyncio
import aiohttp
from grapePrint import grapePrint

class vine():
    
    def __init__(self):
        message = grapePrint()
        apiList = ["/graphql", "/graphql/playground", "/graphiql", "/api/explorer", "/graphql/v1", "/graphql/v2", "/graphql/v3", 
           "/api/graphql/v1", "/api/graphql/v2", "/api/public/graphql", "/api/private/graphql", "/admin/graphql", "/user/graphql"]