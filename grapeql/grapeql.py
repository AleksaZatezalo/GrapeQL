#!/usr/bin/env python

"""
Author: Aleksa Zatezalo
Version: 1.0
Date: February 2025
Description: Main file for GrapeQL
"""

import asyncio
import asyncio
from vine import vine

async def main():
    """
    Main function to handle user input and perform graphql scanning.
    """

    introspection =  await vine().test()

# Example usage
if __name__ == "__main__":
    asyncio.run(main())
