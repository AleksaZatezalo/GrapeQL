#!/usr/bin/env python

"""
Author: Aleksa Zatezalo
Version: 1.0
Date: October 2024
Description: A simple implementation of dirbuster.
"""

import requests

def dirb(url, path):
    try:
        path = url + "/" + path
        r = requests.get(path)
        if r.status_code == 200:
            print("\033[93m" + f"[!] {path} Found" + "\033[0m")
    except:
       pass

def wordListScan(url, wordlistPath):
    with open(wordlistPath) as file:
        while line := file.readline():
            dirb(url, line.rstrip())