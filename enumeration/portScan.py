#!/usr/bin/env python

"""
Author: Aleksa Zatezalo
Version: 1.0
Date: October 2024
Description: A very basic port scanner that prints information to standard outout.
"""

import sys
import socket

def scanPort(host, port):
    """
    Takes one string host, and an int port and attempts to conntect.
    Information will be printed to standard output.
    """

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)  # Set a connection timeout

    result = sock.connect_ex((host, port)) 
    sock.close()
    return result

def scan_ports(host, start_port, end_port):
    """
    Takes a string representing a url called host, and two integers called start_port and end_port.
    It scans the ports on host from start_port to end_port.
    """
    ports = []
    print(f"Scanning ports on {host}...")
    for port in range(start_port, end_port + 1):
        if (scanPort(host, port) == 0):
            ports.append(port)   
    
    return ports

def promptScan():
    """
    Prompts the user to enter scan details using standard input and standard output.
    """
    
    target_hosts = input("Enter the host IP address: ")
    start_port = int(input("Enter the starting port: "))
    end_port = int(input("Enter the ending port: "))
    print(scan_ports(target_hosts, start_port, end_port))