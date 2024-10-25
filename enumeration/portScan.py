#!/usr/bin/env python

"""
Author: Aleksa Zatezalo
Version: 1.0
Date: October 2024
Description: A very basic port scanner that prints information to standard outout.
"""

import sys
import socket

def printOpen(host, port):
    print("\033[93m" + f"[!] Port {port} is open on {host}." + "\033[0m")

def scanPort(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)  # Set a connection timeout

    result = sock.connect_ex((host, port))
    if result == 0:
        printOpen(host, port)
    sock.close()

def scan_ports(host, start_port, end_port):
    print(f"Scanning ports on {host}...")

    for port in range(start_port, end_port + 1):
        scanPort(host, port)   
        
def promptScan():
    target_hosts = input("Enter the host IP address: ")
    start_port = int(input("Enter the starting port: "))
    end_port = int(input("Enter the ending port: "))
    scan_ports(target_hosts, start_port, end_port)

