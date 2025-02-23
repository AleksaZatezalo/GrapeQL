"""
Author: Aleksa Zatezalo
Version: 1.0
Date: February 2025
Description: Base class used to execute test cases.
"""

# To Do
# Baseclass - everything else is payload generation
# Make into a package
# Easily extendible
# Open tickets to SQLi Implementation
# Open tickets open source

class base:

    def __init__(self):
        """Initialize the DoS tester with default settings and printer."""
        pass

        # self.message = grapePrint()
        # self.proxy_url: Optional[str] = None
        # self.schema: Optional[Dict] = None
        # self.endpoint: Optional[str] = None
        # self.query_type: Optional[str] = None
        # self.types: Dict[str, Dict] = {}

    def printVulnerabilityDetails():
        pass

    def configureProxy(self, proxy_host: str, proxy_port: int):
        pass

    async def runIntrospection(self, session: aiohttp.ClientSession) -> bool:
        pass

    def setCredentials(self, username: str, password: str):
        pass
    
    def generateCommandInjectionPayloads(self) -> List[str]:
        pass

    async def testForCommandInjection():
        pass