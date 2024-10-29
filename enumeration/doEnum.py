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
    """

    pass

def printPortScan(results):
    """
    """

    for port in results:
        printMsg(f'Port {port} open on Host. \n')

def executeDirBust():
    """
    """
    
    pass

def executePortScan():
    """
    """
    
    pass


printPortScan([10, 22, 25, 80])