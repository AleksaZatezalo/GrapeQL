"""
Author: Aleksa Zatezalo
Version: 1.1
Date: April 2025
Description: ASCII Art and 'graphics' for GrapeQL with improved test result reporting.
"""

import time

class grapePrint:
    """
    A class for handling colored console output formatting for the GrapeQL tool.

    This class provides methods for printing formatted messages, banners, and notifications
    with various colors and styles using ANSI escape codes.
    """

    def __init__(self):
        """
        Initialize the grapePrint class with ANSI color and style codes.

        Sets up color codes for:
        - Standard color
        - Text styles
        - Reset code
        """

        self.PURPLE = "\033[95m"
        self.CYAN = "\033[96m"
        self.DARKCYAN = "\033[36m"
        self.BLUE = "\033[94m"
        self.GREEN = "\033[92m"
        self.YELLOW = "\033[93m"
        self.RED = "\033[91m"
        self.BOLD = "\033[1m"
        self.UNDERLINE = "\033[4m"
        self.END = "\033[0m"

    def printGrapes(self):
        """
        Print the GrapeQL ASCII art logo in purple.

        Displays a grape-themed ASCII art banner with purple coloring
        and bold text styling.
        """

        print(
            self.PURPLE
            + self.BOLD
            + """
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
        """
        )

    def printTitle(self):
        """
        Print the GrapeQL title and author information.

        Displays the tool name and author in purple, bold text,
        followed by line breaks.
        """

        print(self.PURPLE + self.BOLD + "GrapeQL By Aleksa Zatezalo\n\n" + self.END)

    def printMsg(self, message: str, status: str = "log"):
        """
        Print a formatted message with appropriate status indicators and colors.

        Args:
            message: The message text to display
            status: The type of message to display. Valid options are:
                   - "success" (green with [+])
                   - "warning" (yellow with [!])
                   - "failed" (red with [-])
                   - "log" (cyan with [!], default)
                   - "info" (blue with [i])
                   - "passed" (green with [✓])
        """

        plus = "\n[+] "
        exclaim = "[!] "
        fail = "[-] "
        info = "[i] "
        passed = "[✓] "

        match status:
            case "success":
                print(self.GREEN + plus + message + self.END)
            case "warning":
                print(self.YELLOW + exclaim + message + self.END)
            case "failed":
                print(self.RED + fail + message + self.END)
            case "log":
                print(self.CYAN + exclaim + message + self.END)
            case "info":
                print(self.BLUE + info + message + self.END)
            case "passed":
                print(self.GREEN + passed + message + self.END)

    def printTestResult(self, test_name: str, vulnerable: bool = False, details: str = None):
        """
        Print the result of a specific test.
        
        Args:
            test_name: Name of the test that was performed
            vulnerable: Whether a vulnerability was found
            details: Optional details about the test result
        """
        if vulnerable:
            self.printMsg(f"Test '{test_name}' found vulnerabilities", status="failed")
            if details:
                self.printMsg(f"Details: {details}", status="warning")
        else:
            self.printMsg(f"Test '{test_name}' passed - no vulnerabilities found", status="passed")
            if details:
                self.printMsg(f"Details: {details}", status="info")
    
    def printScanSummary(self, tests_run: int, vulnerabilities_found: int, scan_time: float = None):
        """
        Print a summary of a scan.
        
        Args:
            tests_run: Number of tests run
            vulnerabilities_found: Number of vulnerabilities found
            scan_time: Optional scan duration in seconds
        """
        if vulnerabilities_found > 0:
            self.printMsg(
                f"Scan complete: Found {vulnerabilities_found} vulnerabilities across {tests_run} tests", 
                status="warning" if vulnerabilities_found > 0 else "success"
            )
        else:
            self.printMsg(
                f"Scan complete: No vulnerabilities found across {tests_run} tests", 
                status="passed"
            )
            
        if scan_time is not None:
            self.printMsg(f"Scan duration: {scan_time:.2f} seconds", status="info")

    def printNotify(self):
        """
        Display example notifications for different message types.

        Shows examples of all available message formats with delays
        between each example for better readability. Includes:
        - Warning messages (yellow)
        - Error messages (red)
        - Success messages (green)
        - Log messages (cyan)
        - Info messages (blue)
        - Passed test messages (green)
        """

        time.sleep(0.25)
        print(self.BOLD + "EXAMPLE NOTIFICATIONS:" + self.END)
        time.sleep(0.5)
        self.printMsg("Good news is printed like this.", status="success")
        time.sleep(0.5)
        self.printMsg("Warnings are printed like this.", status="warning")
        time.sleep(0.5)
        self.printMsg("Errors are printed like this.", status="failed")
        time.sleep(0.5)
        self.printMsg("Logs are printed like this.", status="log")
        time.sleep(0.5)
        self.printMsg("Informational messages are printed like this.", status="info")
        time.sleep(0.5)
        self.printMsg("Passed tests are printed like this.", status="passed")
        time.sleep(0.5)
        self.printTestResult("Example Test", vulnerable=False)
        time.sleep(0.5)

    def intro(self):
        """
        Display the complete GrapeQL introduction sequence.

        Shows the full introductory banner including:
        - ASCII art logo
        - Title and author information
        - Welcome message
        - Example notifications
        """

        self.printGrapes()
        self.printTitle()
        self.printNotify()