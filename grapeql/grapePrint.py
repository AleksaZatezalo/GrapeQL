"""
Author: Aleksa Zatezalo
Version: 1.0
Date: October 2024
Description: ASCII Art and 'graphics' for GrapeQL. 
"""

import time

class grapePrint():

    def __init__(self):

        self.PURPLE = '\033[95m'
        self.CYAN = '\033[96m'
        self.DARKCYAN = '\033[36m'
        self.BLUE = '\033[94m'
        self.GREEN = '\033[92m'
        self.YELLOW = '\033[93m'
        self.RED = '\033[91m'
        self.BOLD = '\033[1m'
        self.UNDERLINE = '\033[4m'
        self.END = '\033[0m'

    def printGrapes(self):
        """
        Prints ASCII Grapes in purple color to standard output. 
        """
        
        print(self.PURPLE + self.BOLD +  """
                __
            __ {_/  
        \\_}\\ _
            _\\(_)_  
            (_)_)(_)_
            (_)(_)_)(_)
            (_)(_))_)
            (_(_(_)
            (_)_)
                (_)
        """)

    def printTitle(self):
        """
        Prints title sentance in purple color to standard output. 
        """
        
        print(self.PURPLE + self.BOLD + "GrapeQL By Aleksa Zatezalo\n\n" + self.END)

    def printWelcome(self):
        """
        Prints a welcome message in purple color to standard output. 
        """
        
        msg = "Welcome to GrapeQL, the GraphQL vuln scanner.\n"
        print(self.PURPLE +  msg + self.END)

    def printPrompt(self):
        """
        Prints a prompt in purple to standard output.
        """

        print(self.PURPLE +  "\n[GrapeQL] >" + self.END)

    def printMsg(self, message, status="log"):
        """
        Prints various types of logs to standard output.
        """
        
        plus = "[+] "
        exclaim ="[!] "
        fail = "[-] "

        match status:
            case "success":
                print(self.GREEN + plus + message + self.END)
            case "warning":
                print(self.YELLOW + exclaim + message + self.END)
            case "failed":
                print(self.RED + fail + message + self.END)
            case "log":
                print(self.CYAN + exclaim + message + self.END)

    def printNotify(self):
        """
        Prints messages about notifications and logs. 
        """

        time.sleep(0.25)
        print(self.BOLD + "EXAMPLE NOTIFICATIONS: " + self.END)
        time.sleep(0.5)
        self.printMsg("Warnings are printed like this.", status="warning")
        time.sleep(0.5)
        self.printMsg("Errors are printed like this.", status="failed")
        time.sleep(0.5)
        self.printMsg("Good news is printed like this.", status="success")
        time.sleep(0.5)
        self.printMsg("Logs are printed like this.\n", status="log")
        time.sleep(0.5)

    def intro(self):
        """
        Prints the introductory banner and prompt to standard output.
        """
        self.printGrapes()
        self.printTitle()
        self.printWelcome()
        self.printNotify()