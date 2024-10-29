#!/usr/bin/env python

"""
Author: Aleksa Zatezalo
Version: 1.0
Date: October 2024
Description: An basic web enumeration tool for GrapeQL.
"""

from ..grapeio.grapeio import printMsg


def printDirBust(results):
    """
    Prints each url in results, an array of urls, one by one in the GrapeIO Style.    
    """

    for url in results:
        printMsg(f'{url} is valid. \n')

def printPortScan(results):
    """
    Prints each port in results, an array of port, one by one in the GrapeIO Style.
    """

    for port in results:
        printMsg(f'Port {port} open on Host. \n')

def executeDirBust(host, wordList=None):
    """
    Executes a dirb style scan on the supplied host. Uses default wordlist 
    unless otherwise specified.
    """
    
    pass

def executePortScan(host, portList=None):
    """
    Executes a nmap style scan on the supplied host. Uses default portlist 
    unless otherwise specified.

    """
    
    pass