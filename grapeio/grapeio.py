#!/usr/bin/env python

"""
Author: Aleksa Zatezalo
Version: 1.0
Date: October 2024
Description: ASCII Art and 'graphics' for GrapeQL. 
"""


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

    print(color.BOLD + "EXAMPLE NOTIFICATIONS: " + color.END)
    printMsg("Warnings are printed like this.", status="warning")
    printMsg("Errors are printed like this.", status="failed")
    printMsg("Good news is printed like this.", status="success")
    printMsg("Logs are printed like this\n.", status="log")

def intro():
    """
    Prints the introductory banner and prompt to standard output.
    """
    printGrapes()
    printTitle()
    printWelcome()
    printNotify()
    printPrompt()