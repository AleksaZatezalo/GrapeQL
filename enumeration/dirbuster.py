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
            print("\033[93m" + f"[!] {path} Found" + "\033[0m")
    except:
       pass

def wordListScan(url, wordListPath):
    """
    Takes a URL ,url, and a word list containing directory names, wordListPath.
    It scans a serise of urls by combing url and wordListPath.
    """

    with open(wordListPath) as file:
        while line := file.readline():
            dirb(url, line.rstrip())

def promptBust():
    """
    Has the user pass details for a directory bust via standard output.
    """

    target_hosts = input("Enter the host url: ")
    wordlist = (input("Enter the location of your wordlist: "))
    wordListScan(target_hosts, wordlist)

promptBust()