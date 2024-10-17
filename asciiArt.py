"""
Author: Aleksa Zatezalo
Date: October 2024
Description: A repository of ASCII Art for GrapeQL.
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
    
    msg = "Welcome to GrapeQL, the GraphQL vuln scanner.\nType `help` to see your options.\n"
    print(color.PURPLE +  msg + color.END)

def printPrompt():
    """
    Prints a prompt in purple to standard output.
    """
    print(color.PURPLE +  "[GrapeQL] >" + color.END)

def intro():
    """
    Prints the introductory banner and prompt to standard output.
    """
    printGrapes()
    printTitle()
    printWelcome()
    printPrompt()

def printMsg(message, status="log"):
    """
    Prints various types of logs to standard output.
    """
    if (status == "success"):
        pass
    if (status == "warning"):
        pass
    if (status == "failed"):
        pass
    if (status == "log"):
        pass

intro()