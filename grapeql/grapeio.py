#!/usr/bin/env python

"""
Author: Aleksa Zatezalo
Version: 1.0
Date: October 2024
Description: ASCII Art and 'graphics' for GrapeQL. 
"""

import time
import asyncio
from portScan import scanIP
from dirBuster import scanEndpoints

class color:
   PURPLE = '\033[95m'
   CYAN = '\033[96m'
   DARKCYAN = '\033[36m'
   BLUE = '\033[94m'
   GREEN = '\033[92m'
   YELLOW = '\033[93m'
   RED = '\033[91m'
   BOLD = '\033[1m'
   UNDERLINE = '\033[4m'
   END = '\033[0m'

def printGrapes():
    """
    Prints ASCII Grapes in purple color to standard output. 
    """
    
    print(color.PURPLE + color.BOLD +  """
              __
        __ {_/  
       \_}\\ _
          _\(_)_  
         (_)_)(_)_
        (_)(_)_)(_)
         (_)(_))_)
          (_(_(_)
           (_)_)
            (_)
    """)

def printTitle():
    """
    Prints title sentance in purple color to standard output. 
    """
    
    print(color.PURPLE + color.BOLD + "GrapeQL Version By Aleksa Zatezalo\n\n" + color.END)

def printWelcome():
    """
    Prints a welcome message in purple color to standard output. 
    """
    
    msg = "Welcome to GrapeQL, the GraphQL vuln scanner.For more infor type " + color.BOLD + "`help`.\n"
    print(color.PURPLE +  msg + color.END)

def printPrompt():
    """
    Prints a prompt in purple to standard output.
    """
    print(color.PURPLE +  "\n[GrapeQL] >" + color.END)

def printMsg(message, status="log"):
    """
    Prints various types of logs to standard output.
    """
    
    plus = "[+] "
    exclaim ="[!] "
    fail = "[-] "

    match status:
        case "success":
            print(color.GREEN + plus + message + color.END)
        case "warning":
            print(color.YELLOW + exclaim + message + color.END)
        case "failed":
            print(color.RED + fail + message + color.END)
        case "log":
            print(color.CYAN + exclaim + message + color.END)

def printNotify():
    """
    Prints messages about notifications and logs. 
    """

    time.sleep(0.25)
    print(color.BOLD + "EXAMPLE NOTIFICATIONS: " + color.END)
    time.sleep(0.5)
    printMsg("Warnings are printed like this.", status="warning")
    time.sleep(0.5)
    printMsg("Errors are printed like this.", status="failed")
    time.sleep(0.5)
    printMsg("Good news is printed like this.", status="success")
    time.sleep(0.5)
    printMsg("Logs are printed like this.\n", status="log")
    time.sleep(0.5)

def intro():
    """
    Prints the introductory banner and prompt to standard output.
    """
    printGrapes()
    printTitle()
    printWelcome()
    printNotify()


def parse_url():
    """
    Prompts the user to enter a URL in the form "http://IP:PORT".
    Splits the URL into its components (protocol, IP, and port) and prints the IP and port.
    
    Returns:
        tuple: A tuple containing the protocol (str), IP (str), and port (str).
    """
    url = input("Enter a URL in the format 'http://IP:PORT': ").strip()
    try:
        # Ensure the URL starts with "http://" or "https://"
        if not url.startswith(("http://", "https://")):
            raise ValueError("URL must start with 'http://' or 'https://'")

        # Split the URL into protocol and the remaining part
        protocol, rest = url.split("://")
        
        # Split the remaining part into IP and port
        ip, port = rest.split(":")
        
        # Print the results
        print(f"Protocol: {protocol}")
        print(f"IP: {ip}")
        print(f"Port: {port}")
        
        return protocol, ip, port
    except ValueError as e:
        print(f"Invalid input: {e}")
        return None

async def main():
    """
    Main function to handle user input and perform both port scanning and endpoint scanning.
    """
    # Get IP and URL from the user
    ip = input("Enter the IP address to scan ports (e.g., 127.0.0.1): ").strip()

    print("\nStarting port scan...")
    # Perform port scanning
    open_ports = await scanIP(host=ip)
    if open_ports:
        print(f"\nOpen ports on {ip}: {open_ports}")
    else:
        print(f"\nNo open ports found on {ip}.")

    url = input("Enter the URL to scan endpoints (e.g., http://127.0.0.1:8080): ").strip()
    print("\nStarting endpoint scan...")
    # Perform endpoint scanning
    valid_endpoints = await scanEndpoints(base_url=url)
    if valid_endpoints:
        print(f"\nValid endpoints on {url}: {valid_endpoints}")
    else:
        print(f"\nNo valid endpoints found on {url}.")

# Example usage
if __name__ == "__main__":
    intro()
    asyncio.run(main())
