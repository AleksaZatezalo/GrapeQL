#!/usr/bin/env python

"""
Author: Aleksa Zatezalo
Version: 1.0
Date: October 2024
Description: A simple implementation of dirbuster.
"""

import requests
import asyncio
from aiohttp import ClientSession

apiList = ["/graphql", "/graphql/playground", "/graphiql", "/api/explorer", "/graphql/v1", "/graphql/v2", "/graphql/v3", 
           "/api/graphql/v1", "/api/graphql/v2", "/api/public/graphql", "/api/private/graphql", "/admin/graphql", "/user/graphql"]

async def dirb(session, base_url, path):
    """
    Constructs a full URL and scans it for a valid response.
    Returns the path if the URL is accessible (status 200), otherwise None.
    """
    full_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    try:
        async with session.get(full_url) as response:
            if response.status != 404:
                return full_url
    except Exception as e:
        # Handle exceptions, e.g., connection errors, invalid URLs
        return None

async def scanEndpoints(base_url):
    """
    Scans all endpoints in api_list asynchronously using dirb.
    Returns a list of valid paths.
    """
    async with ClientSession() as session:
        tasks = [dirb(session, base_url, path) for path in apiList]
        results = await asyncio.gather(*tasks)
    return [result for result in results if result]