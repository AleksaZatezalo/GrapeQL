#!/usr/bin/env python

"""
Author: Aleksa Zatezalo
Version: 1.0
Date: October 2024
Description: A simple implementation of dirbuster.
"""

import requests

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

def wordListScan(url, wordListPath):
    """
    Takes a URL ,url, and a word list containing directory names, wordListPath.
    It scans a serise of urls by combing url and wordListPath.
    """

    urls = []
    with open(wordListPath) as file:
        while line := file.readline():
           result =  dirb(url, line.rstrip())
           if result != None:
               urls.append(result)
    return urls