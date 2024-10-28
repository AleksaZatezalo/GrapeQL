#!/usr/bin/env python

"""
Author: Aleksa Zatezalo
Version: 1.0
Date: October 2024
Description: A simple implementation of dirbuster.
"""

import requests
import asyncio

def dirb(url, path):
    """
    Constructs a new path based on URL and Path. Scans the newly constructed URL\Path. 
    """
    try:
        path = url + "/" + path
        r = requests.get(path)
        if r.status_code == 200:
           return path
    except:
       return None

def urlCreator(url, wordListPath):
    """
    Takes a URL ,url, and a word list containing directory names, wordListPath.
    It returns a list of URLs to scan.
    """

    # Construct a list of URLs to query based on a Wordlist
    urls = []
    with open(wordListPath) as file:
        while line := file.readline():
           result =  dirb(url, line.rstrip())
           urls.append(result)

    return urls

async def tryURL(url):
    """
    Takes a URL and verifies that it exists on a website.
    """

    pass


async def totalScan(urlList):
    """
    Takes a list of URL, urlList, and runs a scan ac
    """

    pass