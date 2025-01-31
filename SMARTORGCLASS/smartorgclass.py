import hashlib
import hmac
import json
import base64
import logging

import urllib3
import urllib.parse

from typing import List

from .utils import request_call

logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SmartOrg(object):
    """A class for interfacing with SmartOrg kirk API

    """

    def __init__(self, username: str, password: str, server: str, timeout:float = 30., verify: bool=True):
        """Generates Hmac needed for authorization to PNAV 8.x. and then calls the getToken() mehod to generate initial JWT token

        Args:
            username (str): 
                string representing a registered username
            password (str): 
                string with the registered user's password
            server (str):
                string representing the SmartOrg server to communicate with i.e.:
                'dev.smartorg.com',
                'trials.smartorg.com,
                etc.
            timeout:
                (optional) How many seconds to wait for the server to send data before giving up, as a float
            verify:
                (optional) boolean which controls whether we verify the server’s TLS certificate


        """
        self.username = username
        self.server = server
        self.verify = verify
        self.timeout = timeout
        self.token = None

        self.headers = {
            "Authorization": None,
            "Content-Type": "application/json",
            "cache-control": "no-cache",
        }



        path = b"/wizard-api/framework/login/a/" + self.username.encode()
        body = b"{}"

        key = hashlib.md5(password.encode()).hexdigest().encode()
        signature = hmac.new(key, path, hashlib.sha256)
        signature.update(body)
        
        self.getToken(signature.hexdigest())

    def getToken(self,myHMAC: str) -> str:
        """Generates authorization token.

        Args:
            myHMAC:
                string containing hmac login credentials

        POST:  /wizard-api/framework/login/a/{username}

        Body:
            {<br>
            "Authorization":
                "applicationname {self.username}:{myHMAC}".encode('utf-8'),<br>
            "Content-Type": 
                "application/json",<br>
             "cache-control": 
                "no-cache"<br>
            }

        Returns:
            string containing JWT token
        """
        url = (
            "https://" + self.server + "/wizard-api/framework/login/a/" + self.username
        )
        body = {}
        self.headers['Authorization'] = f"applicationname {self.username}:{myHMAC}".encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    

    """
    Section: domain
    
    This section contains the domain API calls.
    """
    
    # Set default tree view filter
    def setDefaultTreeViewFilters(self,portfolioName: str, newConfig: dict):
        """Set default tree view filter

        Args:
            portfolioName:
                string with name of portfolio
            newConfig:
                dictionary with following schema:
                {
                'excludedTags':[{list of tags to exclude'}],
                'filterlogic':string containing filter logic e.g. '(LineOfBusiness:ConsumerProducts or LineOfBusiness:HouseholdAppliances) and ProjectHealth:Yellow'   
                }

        API:
            POST:  domain/admin/default-tree-filters
            domain/admin/default-tree-filters

        Returns:
            {'status': 0, 'message': 'Portfolio is exported'}
        """
        url = f"https://{self.server}/kirk/domain/admin/default-tree-filters"

        body = {
            'portfolioName': portfolioName,
            'newConfig': newConfig
        }
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    

    # Preview global table
    def previewGlobalTable(self, tableName: str):
        """Preview global table

         Args:
            tableName: 
                string containing name of global table to download

        API:
            GET:  domain/admin/global-table?tableName=<tableName>

        Returns:
            Preview of global table
        """
        url = "https://" + self.server + "/kirk/domain/admin/global-table?tableName="+tableName

        body = {}
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("GET", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None


    # Get list of global tables
    def getListOfGlobalTables(self):
        """Get list of global tables

        API:
            GET:  domain/admin/global-tables

        Returns:
            List of global tables in the Database Manager
        """
        url = "https://" + self.server + "/kirk/domain/admin/global-tables"

        body = {}
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("GET", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    

    # Delete global table
    def deleteGlobalTable(self, tableName: str):
        """Delete global table

        Args:
            tableName: 
                string containing name of global table to delete

        API:
            DELETE:  domain/admin/global-tables?tableName=<tableName>

        Returns:
            {'status': 201, '_id': 'YWxs'}
        """
        url = "https://" + self.server + "/kirk/domain/admin/global-tables?tableName="+tableName

        body = {}
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("DELETE", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    
    # Upload global table from excel
    # def uploadGlobalTableExcel(self, tableName: str,excelFile: str):
    #     """Upload global table from excel

    #     API:
    #         POST:  domain/admin/global-tables?tableName=<tableName>

    #     Returns:
    #         ???
    #     """
    #     url = "https://" + self.server + "/kirk/domain/admin/global-tables?tableName="+tableName

    #     body = {}

    #      # Open the file in binary mode
    #     with open(excel_file_path, 'rb') as file:
    #         # Create the files dictionary to send with the request
    #         files = {'file': (file.name, file, 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')}
            
    #         # Make the POST request and return the response
    #         return self.api_post(path, files)
    #     self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

    #     response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
    #     if response:
    #         data = response.json()["data"]
    #         self.token = response.json()["token"]
    #         return data
    #     return None


    # Get list of all users
    def getAllUsers(self):
        """Get list of all users

        API:
            GET:  /framework/admin/user/list

        Returns:
            List of dicts containing astro_users documents from database
        """
        url = "https://" + self.server + "/kirk/framework/admin/user/list"
        body = {}
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("GET", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    

    # Export portfolio
    def exportPortfolio(self,nodeID: str):
        """Export portfolio 

        Args:
            nodeID: 
                _id of top-most (root) node of portfolio

        Description:
            Exports portfolio with root node of nodeID to /opt/rangal/1.0.0/tmp/export/

        API:
            POST:  domain/admin/portfolio/export

        Returns:
            {'status': 0, 'message': 'Portfolio is exported'}
        """
        url = "https://" + self.server + "/kirk/domain/admin/portfolio/export/"+nodeID

        body = {}
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    
    # Fetch all exported portfolios paths
    def fetchAllExportedPortfolioPaths(self):
        """Fetch all exported portfolios paths

        API:
            GET:  domain/admin/portfolio/exported

        Returns:
            List of 64-bit encoded exported portfolio paths inside a dict with keys: ['status','message','encodedExportedPortfolioList']

        Notes:
            Decode 64-bit encoded data using the base64 built-in libary:
                >>> import base64
                >>> encodedPath = 'L29wdC9yYW5nYWwvMS4wLjAvdG1wL2V4cG9ydC9OZXcgUHJvZHVjdCBJbnRyb2R1Y3Rpb24vMjAyMzA5MjguMTA1MjAw'
                >>> decodedPath = base64.b64decode(encodedPath)
                >>> decodedPath
                b'/opt/rangal/1.0.0/tmp/export/New Product Introduction/20230928.105200'
                >>> decodedPath.decode('utf-8')
                '/opt/rangal/1.0.0/tmp/export/New Product Introduction/20230928.105200'

        """
        url = "https://" + self.server + "/kirk/domain/admin/portfolio/exported"

        body = {}
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("GET", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    
    # Import portfolio from exported portfolios
    def importPortfolio(self,includeData: bool, pathToImportFiles64, newTreeName64):
        """Import portfolio from exported portfolios

         Args:
            includeData: boolean to indicate whether to include data in portfolio import
            pathToImportFiles64: 64-bit encoded path to portolio files to be imported
            newTree64: 64-bit encoded name of new portofolio to which to import to

        Notes:
            Encode strings in python using the base64 built-in libary:
                >>> import base64
                >>> name = 'Test Portfolio'
                >>> base64.b64encode(name.encode('utf-8'))
                b'VGVzdCBQb3J0Zm9saW8='

        API:
            POST:  domain/admin/portfolio/import

        Returns:
            {'status': 0, 'message': 'Portfolio is imported'}
        """
        url = "https://" + self.server + "/kirk/domain/admin/portfolio/import"

        body = {
            'include_data': includeData,
            'path_to_import_files64': pathToImportFiles64,
            'new_tree_name64': newTreeName64
        }
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    


    # Create new porfolio
    def createPortfolio(self,newPortfolioName: str):
        """Create new portfolio

         Args:
            newPortfolioName: string representing name of new portfolio

        API:
            POST:  domain/admin/portfolio/new

        Returns:
            {'status': 0, 'message': 'Create a new portfolio', 'nodeID': <nodeID of porfolio root node>}
        """
        url = "https://" + self.server + "/kirk/domain/admin/portfolio/new"

        body = {
            'treeID': newPortfolioName
        }
      
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    

    # Set group and template restrictions for a portfolio
    def setGroupsAndTemplatesRestrictions(self, treeID: str, groups: List[str], templates: List[str]):
        """Set group and template restrictions for a portfolio

        Args:
            treeID: string representing name of portfolio
            groups: list of groups as strings
            templates:  list of templates as strings

        API:
            PUT:  domain/admin/portfolio/restrict/both

        Returns:
            Nothing
        """
        url = f"https://{self.server}/kirk/domain/admin/portfolio/restrict/both/{urllib.parse.quote(treeID)}"

        # Make sure administrators group is always included and the first item in list
        if groups[0]!='administrators':
            groups = 'administrators' + groups
        body = {
            'groups': groups,
            'templates': templates
        }
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("PUT", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None


    # Get group restrictions for a portfolio
    def getGroupRestrictions(self, treeID: str):
        """Get group restrictions for a portfolio

        Args:
            treeID: string representing name of portfolio

        API:
            GET:  domain/admin/portfolio/restrict/group
        Returns:
            Dictionary containing two keys:  'restrictedGroups' and 'remainingGroups' which contain list values of group names
        """
        url = f"https://{self.server}/kirk/domain/admin/portfolio/restrict/group/{urllib.parse.quote(treeID)}"
        body = {}
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("GET", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    

    # Set group restrictions for a portfolio
    def setGroupRestrictions(self, treeID: str, chosenGroups: List[str]):
        """Set group restrictions for a portfolio

        Args:
            treeID: string representing name of portfolio
            chosenGroups: list of groups as strings

        API:
            PUT:  domain/admin/portfolio/restrict/group

        Returns:
            Nothing
        """
        url = f"https://{self.server}/kirk/domain/admin/portfolio/restrict/group/{urllib.parse.quote(treeID)}"
        
        # Make sure administrators group is always included and the first item in list
        if chosenGroups[0]!='administrators':
            chosenGroups = 'administrators' + chosenGroups
        
        body = {
            'chosen': chosenGroups
        }
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("PUT", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None

    
    # Get template restrictions for a portfolio
    def getTemplateRestrictions(self, treeID: str):
        """Get template restrictions for a portfolio

        Args:
            treeID: string representing name of portfolio

        API:
            GET:  domain/admin/portfolio/restrict/template
        Returns:
            Dictionary containing two keys:  'restrictedTemplates' and 'remainingTemplates' which contain list values of templates
        """
        url = f"https://{self.server}/kirk/domain/admin/portfolio/restrict/template/{urllib.parse.quote(treeID)}"
        body = {}
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("GET", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    

    # Set template restrictions for a portfolio
    def setTemplateRestrictions(self, treeID: str, chosenTemplates: List[str]):
        """Set template restrictions for a portfolio

        Args:
            treeID: string representing name of portfolio
            chosenTemplates:  list of templates as strings

        API:
            PUT:  domain/admin/portfolio/restrict/template

        Returns:
            Nothing
        """
        url = f"https://{self.server}/kirk/domain/admin/portfolio/restrict/template/{urllib.parse.quote(treeID)}"
        body = {
            'chosen': chosenTemplates
        }
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("PUT", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    
    # Get all available templates for a node
    def getAllTemplates(self, node_id: str):
        """Get available templates for a node

        Args:
            node_id: string node id 

        API:
            GET:  domain/admin/templates/all
        Returns:
            returns a list of dicts with info for all available templates
        """
        url = f"https://{self.server}/kirk/domain/admin/templates/all/{node_id}"
        body = {}
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("GET", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None

    # Get categories for a portfolio
    def getAssignCategory(self, treeID: str):
        """Get categories and category assignments for a portfolio

        Args:
            treeID: string representing name of a portfolio

        API:
            POST:  domain/category/assign/display
        Returns:
            returns a dictionary with two main keys:  'tagData' and 'categoryConfig'
            'tagData'  contains a list of dicts showing the category assignments for each node in the portfolio
            'categoryConfig' retunrns a list of dicts showing all the categories, category settings and category entries
        """
        url = f"https://{self.server}/kirk/domain/category/assign/display/{urllib.parse.quote(treeID)}"
        body = {}
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    
    # Arrange order of categories
    def arrangeCategoriesConfig(self, 
                           rootNodeID: str,
                           categoriesConfig: List[dict]
                           ):
        """Arrange order of categories

        Args:
            rootNodeID (str): 
                string with astro_node _id of portfolio root node
            categoriesConfig (List[dict]):
                list of category dicts in order of arrangement

        API:
            POST:  domain/category/config/arrange
        Returns:
            True or False
        """
        url = f"https://{self.server}/kirk/domain/category/config/arrange/{rootNodeID}"
        body = {
            'categoriesConfig': categoriesConfig, 
        }
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    


    # Delete category
    def deleteCategoryConfig(self, 
                           rootNodeID: str,
                           categoryName: setDefaultTreeViewFilters
                           ):
        """Delete category

        Args:
            rootNodeID (str): 
                string astro_node _id of portfolio root node
            categoryName (str):
                string with name of category to delete

        API:
            DELETE:  domain/category/config/delete

        Returns:
            True or False
        """
        url = f"https://{self.server}/kirk/domain/category/config/delete/{rootNodeID}/{urllib.parse.quote(categoryName)}"
        body = {}
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("DELETE", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    


    # Get categories for a portfolio
    def categoryConfigFor(self, rootNodeID: str):
        """Get categories for a portfolio

        Args:
            rootNodeID: string representing node _id for the root node  of a portfolio

        API:
            GET:  domain/category/config/list
        Returns:
            returns a list of dicts showing all the categories, category settings and category entries
        """
        url = f"https://{self.server}/kirk/domain/category/config/list/{rootNodeID}"
        body = {}
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("GET", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    
    # Get categories for a node
    def categoryLogFor(self, nodeID: str):
        """Get categories for a node 

        Args:
            nodeID: string representing node _id for a node

        API:
            GET:  domain/categoryLog
        Returns:
            returns a list of dicts categories selected for node
        """
        url = f"https://{self.server}/kirk/domain/categoryLog/{nodeID}"
        body = {}
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("GET", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    
    # Save a new category or update an existing category configuration
    def saveCategoryConfig(self, 
                           rootNodeID: str,
                           categoryConfig: dict,
                           renameEntriesTracker: List[dict],
                           changedCategoryName: dict = {}
                           ):
        """Save a new category or update an existing category configuration

        Args:
            rootNodeID (str): 
                string astro_node _id of portfolio root node
            categoryConfig (dict):

            renameEntriesTracker (List[dict]):
                [{'entry': <entry_name>, 'state': False, 'vals': None, 'isDuplicate':False}]
            changedCategoryName (dict,optional):
                default value = {}

        API:
            POST:  domain/category/config/save
        Returns:
            True or False
        """
        url = f"https://{self.server}/kirk/domain/category/config/save/{rootNodeID}"
        body = {
            'categoryConfig': categoryConfig, 
            'renameEntriesTracker': renameEntriesTracker, 
            'changedCategoryName': changedCategoryName
        }
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    



    # Save description for a node
    def saveDescription(self, nodeID: str, description: str):
        """Save description for a node

        Args:
            nodeID: string representing node _id for a node
            description:  64-bit encoded(urllib.parse encoded(html text).encode('utf-8')).decode()

            Example:
                >>> import base64
                >>> import urllib.parse
                >>> htmlText = '<h1>This is a test</h1>'
                >>> description = base64.b64encode(urllib.parse.quote(htmlText).encode('utf-8')).decode()
                >>> description
                'JTNDaDElM0VUaGlzJTIwaXMlMjBhJTIwdGVzdCUzQy9oMSUzRQ=='

        API:
            PUT:  domain/description/save
        Returns:
            returns {'status': 0, 'message': 'Successfully saved description'}
        """
        url = f"https://{self.server}/kirk/domain/description/save/{base64.b64encode(nodeID.encode()).decode()}"
        body = {
            'description': description
        }
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("PUT", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    

    # Get dropdown tags for node
    def dropdownTagsFor(self, nodeID: str, filter: str=None):
        """Get dropdown tags for node

        Args:
            nodeID: 
                string representing node _id for a node
            filter:
                NOT IMPLEMENTED in this wrapper - string representing tree-filter selections

        API:
            GET:  domain/dropdownTags
        Returns:
            returns list of strings containing dropdown tags for node in format:  'dropdownInputName:url-encoded(64-bit encoded(value))'
        """

        # url = f"https://{self.server}/kirk/domain/dropdownTags/{nodeID}/{urllib.parse.quote(filter)}"
        url = f"https://{self.server}/kirk/domain/dropdownTags/{nodeID}"
        body = {}
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("GET", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    

    # Perform goal analysis
    def performGoalAnalysis(self, 
                            nodeID: str, 
                            packedRangeInfo: dict, 
                            packedMenuInfo: dict,
                            packedReportOptions: str = "e30=",
                            packedExcludeFilterTags: str = "W10=",
                            actionID: str = None
        ):
        """Perform goal analysis

        Args:
            nodeID: 
                string representing node _id for a node
            packedRangeInfo: 
                string with 64-bit encoded range info dictionary
                Example of unencoded dict:
                {"analyzeOn":"value","lowerBound":0.05,"upperBound":0.08}
                where "analyzeOn" is either "value" or "prob"
            packedMenuInfo:
                string with 64-bit encoded menu info dictionary
                Example of unencoded dict (NOTE: found in "Command": "GOAL_ANALYSIS" in template):
                {"RollupKeys":["grossMarginBaseYearPlus3","grossMarginBaseYearPlus5",
                "grossMarginBaseYearPlus10","grossRevenueBaseYearPlus3","grossRevenueBaseYearPlus5","grossRevenueBaseYearPlus10"],
                "Source":"GrossMargin_RevenueFullDistribution","MVSType":"MVSFromFittedPoints"}
            packedReportOptions:
                string with 64-bit encoded report options dict
                Default value:  "e30=",  decoded value:  {}



            Example:
                >>> import base64
                >>> import urllib.parse
                >>> htmlText = '<h1>This is a test</h1>'
                >>> description = base64.b64encode(urllib.parse.quote(htmlText).encode('utf-8')).decode()
                >>> description
                'JTNDaDElM0VUaGlzJTIwaXMlMjBhJTIwdGVzdCUzQy9oMSUzRQ=='

        API:
            POST:  domain/goal-analysis
        Returns:
            returns dictionary containing the following schema
            ['data']->['data','legends','siblingLegends','settings']
            ['data']['data']->['RollupKeys', 'Source', 'MVSType', 'rangeInfo', 'DataForEachKey']
        """
        url = f"https://{self.server}/kirk/domain/goal-analysis/{nodeID}"
        

        body = {
            "action_id": None,
            "packed_menu_info": packedMenuInfo,
            "packed_range_info": packedRangeInfo,
            "packed_report_options": packedReportOptions,
            "packed_exclude_filter_tags":packedExcludeFilterTags
        }


        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    
    # Get guidance for a node
    def getGuidance(self, nodeID: str):
        """Get guidance for a node
        
        Args:
            nodeID: string representing node _id for a node

        API:
            GET:  domain/guidance
        Returns:
            returns 64-bit encoded and utf-8 encoded string containing html text for guidance
            import base64 and urllib.parse and then decode return value using
            a = so.getGuidance(nodeID)
            urllib.parse.unquote(base64.b64decode(a).decode())
        """
        url = f"https://{self.server}/kirk/domain/guidance/{nodeID}"
        body = {}
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("GET", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    
    # Save guidance for a node
    def saveGuidance(self, nodeID: str, guidance: str):
        """Save guidance for a node
        
        Args:
            nodeID: 
                string representing node _id for a node
            guidance:
                64-bit and utf-8 encoded string for html text to save in guidance
                Example:
                    htmltext = '<h1>Guidance Test</h1>'
                    base64.b64encode(urllib.parse.quote(htmltext).encode()).decode()
                    'JTNDaDElM0VHdWlkYW5jZSUyMFRlc3QlM0MvaDElM0U='

        API:
            PUT:  domain/guidance
        Returns:
            {'status': 0, 'message': 'Successfully saved guidance'}
        """
        url = f"https://{self.server}/kirk/domain/guidance/{base64.b64encode(nodeID.encode()).decode()}"
        body = {
            'guidance': guidance
        }
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("PUT", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    

    # Get data for Inav Experiment Management
    # def getDataForInavExpMgmt(self, nodeID: str):
    #     """Get data for Inav Experiment Management
        
    #     Args:
    #         nodeID: string representing node _id for a node

    #     API:
    #         GET:  domain/inav/tornado/get

    #     Returns:
    #         returns 64-bit encoded and utf-8 encoded string containing html text for guidance
    #         import base64 and urllib.parse and then decode return value using
    #         a = so.getGuidance(nodeID)
    #         urllib.parse.unquote(base64.b64decode(a).decode())
    #     """
    #     url = f"https://{self.server}/kirk/domain/inav/tornado/get/{nodeID}"
    #     body = {}
    #     self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

    #     response = request_call("GET", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
    #     if response:
    #         data = response.json()["data"]
    #         self.token = response.json()["token"]
    #         return data
    #     return None
    

    # De-override input in common data
    def deoverrideInput(self, targetNodeID: str, inputKey: str):
        """De-override input in common data
        
        Args:
            targetNodeID: 
                string representing nodeID for the sub-portfolio common data to be overridden
            intputKey:
                string representing input key to be de-overridden in common data

        API:
            PUT:  domain/input/deoverride
        Returns:
            {'status': True, 'valueChanged': True}
        """
        url = f"https://{self.server}/kirk/domain/input/deoverride"
        body = {
            'targetNodeID': targetNodeID,
            'inputKey': inputKey
        }
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("PUT", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    
     # Override input in common data
    def overrideInput(self, targetNodeID: str, sourceNodeID: str, inputKey: str):
        """Override input in common data
        
        Args:
            targetNodeID: 
                string representing nodeID for the sub-portfolio common data to be overridden
            sourceNodeID:
                string representing nodeID of root node for portfolio
            inputKey:
                string representing input key to be overridden in common data

        API:
            PUT:  domain/input/override
        Returns:
            {'status': True, 'valueChanged': True}
        """
        url = f"https://{self.server}/kirk/domain/input/override"
        body = {
            'targetNodeID': targetNodeID,
            'sourceNodeID': sourceNodeID,
            'inputKey': inputKey
        }
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("PUT", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    

    # Get sub-tree
    def getSubtree(self, loadNodeList: List[str]):
        """Get sub-tree

        Args:
            loadNodeList: list of strings with nodeID's to load.  Nodes in this list should not be leaves.
            Note that the list can contain multiple sub-portfolios to load the info for
        API:
            POST:  domain/nav/get-subtree
        Returns:
            returns a list of astro_node dicts for each node below the specified sub-node(s) in loadNodeList
        """
        url = f"https://{self.server}/kirk/domain/nav/get-subtree"
        body = {
            'node_ids': loadNodeList
        }
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    
    # Get list of children for a node
    # def getChildren(self, nodeID: str):
    #     """Get list of children for a node

    #     Args:
    #         nodeID (str): string represented selected node
           
    #     API:
    #         POST:  domain/nav/get-children
    #     Returns:
    #         returns a list of astro_node dicts children below selected node
    #     """
    #     url = f"https://{self.server}/kirk/domain/nav/get-children/{nodeID}"
    #     body = {}
    #     self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

    #     response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
    #     if response:
    #         data = response.json()["data"]
    #         self.token = response.json()["token"]
    #         return data
    #     return None
    

    # Get action menu for node
    def actionMenuFor(self, nodeID: str):
        """Get action menu for node
        
        Args:
            nodeID: string representing node _id for selected node

        API:
            GET:  domain/nav/menu
        Returns:
            returns dictionary with schema
            ['menuItems']->['Actions','Management'] where ['Action'] is a list of action menu items
        """
        url = f"https://{self.server}/kirk/domain/nav/menu/{nodeID}"
        body = {}
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("GET", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    

    # Get portfolios
    def portfolios(self):
        """Get portfolios
        
        Args:
            none

        API:
            GET:  domain/nav/portfolios

        Returns:
            dictionary with ['portfolios','membership'] where ['portfolios'] is a list of astro_nodes for the portfolios
        """
             
        url = f"https://{self.server}/kirk/domain/nav/portfolios"
        body = {}
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("GET", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None


    # Get tree
    def treeFor(self, portfolioName: str):
        """Get tree
        
        Args:
            portfolioName
                string with name of portfolio

        API:
            GET:  domain/nav/tree

        Returns:
            list of astro_node dicts for tree
        """
             
        url = f"https://{self.server}/kirk/domain/nav/tree/{urllib.parse.quote(portfolioName)}"
        body = {}
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("GET", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    

    # Get first N levels of tree
    def firstNLevelTreeFor(self, portfolioName: str, nLevel: int, selectedNodeID: str=None):
        """Get first N levels of tree
        
        Args:
            portfolioName
                string with name of portfolio
            nLevel
                number of levels of tree to return
                nlevel is currently hardcoded to 4 in the BE code
            selectedNodeID
                string with selected nodeID Default: None

        API:
            POST:  domain/nav/tree-first-n-level

        Returns:
            dictionary with following keys:  ['nodeList', 'defaultReportOptions', 'defaultTreeViewFilters', 'defaultTreeColors']
        """
             
        url = f"https://{self.server}/kirk/domain/nav/tree-first-n-level/{urllib.parse.quote(portfolioName)}/{nLevel}"
        body = {
            'selectedNodeId': selectedNodeID
        }
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    
    # Cut a node from tree and paste it below a parent node
    def cutPasteNode(self, targetParentNodeID: str, nodeToPaste: str):
        """Cut a node from tree and paste it below a parent node
        
        Args:
            targetParentNodeID
                string with parent nodeID under which to paste the selected node
            nodeToPaste
                string with selected nodeID to cut from tree

        API:
            POST:  domain/node/cutpaste

        Returns:
            {'status': 0, 'message': 'cut and pasted data'}
        """
             
        url = f"https://{self.server}/kirk/domain/node/cutpaste"
        body = {
            'target_parent_id': targetParentNodeID,
            'node_to_paste': nodeToPaste
        }
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    

    # Delete a node
    def deleteNode(self, nodeID: str):
        """Delete a node

        Note that deleting a node moves it to the recycle bin. 
        To permanently delete a node, it must be deleting from 
        the recycle bin using the permanentDeleteRecord API call
        
        Args:
            nodeID
                string with nodeID to be deleted

        API:
            DELETE:  domain/node/doc

        Returns:
            Example - {'deletedNodes': [{'_id': 'copyff17d0f22dac11efba0d002248b4d3f8', 'name': 'Shoe Inserts (1)', 'data': 'copyff1e66b02dac11efba0d002248b4d3f8', 'path': ['61009451167e487b988e5a07_20210827.135659_20230928.105045', '6100947f8cc80bf8f3e0241a_20210827.135659_20230928.105045', '6671c321f6981c28a3a24391']}], 'undeletedNodes': []}
        """
             
        url = f"https://{self.server}/kirk/domain/node/doc/{nodeID}"
        body = {}
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("DELETE", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    

    # Get node
    def nodeBy(self, nodeID: str):
        """Get document from astro_nodes collection for document nodeID
        
        Args:
            nodeID
                string with nodeID

        API:
            GET:  domain/node/doc

        Returns:
            dictionary containg nodeID document from astro_nodes collection
        """
             
        url = f"https://{self.server}/kirk/domain/node/doc/{nodeID}"
        body = {}
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("GET", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    

    # Create new node
    def createNode(self, 
                   parentNodeID: str, 
                   newNodeName: str,
                   templateName: str,
                   platformOrLeaf: str = "Leaf", 
                   parentTags: List[str]=None,
                   newNodeTags: List[str]=['all'],
                   newNodeDropdownTags: List[str]=None
                   ):
        """Create new node
        
        Args:
            parentNodeID
                string parent nodeID
            newNodeName
                string with new name
            templateName
                string with template name
            platformOrLeaf
                string with either "Leaf" or "Platform"
            parentTags
                list of strings containing parent tags, Default: None
            newNodeTags
                default:  ['all']
            newNodeDropDownTags
                default: None

        API:
            POST:  domain/node/doc

        Returns:
            {'status': 0, 'message': 'Created a new node', 'nodeID': '6672017bdb5391908411ff23'}
        """
             
        url = f"https://{self.server}/kirk/domain/node/doc"
        body = {
            "nodeID": parentNodeID,
            "newNodeName": newNodeName,
            "templateName": templateName,
            "platformOrLeaf": platformOrLeaf,
            "parentTags": parentTags,
            "newNodeTags": newNodeTags,
            "newNodeDropdownTags": newNodeDropdownTags
        }
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        

# Edit node
    def editNode(self, 
                   nodeID: str, 
                   newNodeName: str,
                   templateName: str,
                   children: List[str]=[],
                   saveNodeTags: List[str]=None
                   ):
        """Edit node
        
        Args:
            nodeID
                string containing nodeID to be edited
            newNodeName
                string with name for node
            templateName
                string with template name
            children
                list of children nodeIDs,  Default: []
            saveNodeTags
                default: None

        API:
            PUT:  domain/node/doc

        Returns:
            {'status': 0, 'message': 'Edit a node'}
        """
             
        url = f"https://{self.server}/kirk/domain/node/doc"
        body = {
            "nodeID": nodeID,
            "newNodeName": newNodeName,
            "templateName": templateName,
            "children": children,
            "saveNodeTags": saveNodeTags
        }
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("PUT", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
        
    # Fetch input data
    def fetchInputData(self, treeID: str, nodeID: str):
        """Fetch input data
        
        Get the input data from astro_data for specified node
        including comments and history
        
        Args:
            treeID
                string with name of portfolio
            nodeID
                string with nodeID

        API:
            POST:  domain/node/download/input

        Returns:
            dictionary with following keys
            ['status','data']
            ['data'] contains ['report','nodeName']
            ['report'] contains string with all inputs including labels, values, comments 
            and history
        """
             
        url = f"https://{self.server}/kirk/domain/node/download/input"
        body = {
            'tree_id': treeID,
            'node_id': nodeID
        }
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    
    # Paste node
    def pasteNode(self, targetParentNodeID: str, nodeToPaste: str):
        """Paste node
    
        
        Args:
            targetParentNodeID
                string with nodeID of target parent node
            nodeToPaste
                string with nodeID to be copied and pasted

        API:
            POST:  domain/node/paste

        Returns:
            {'status': 0, 'message': 'pasted data'}
        """
             
        url = f"https://{self.server}/kirk/domain/node/paste"
        body = {
            'target_parent_id': targetParentNodeID,
            'node_to_paste': nodeToPaste
        }
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    

    # Make node (and optionally sub-nodes) read-only
    def makeReadOnly(self, nodeID: str, includeAllChildren: str):
        """Make node (and optionally sub-nodes) read-only
    
        
        Args:
            nodeID
                string with nodeID of node to make read-only
            includeAllChildren
                string which can be either "True" or "False"

        API:
            POST:  domain/node/readonly

        Returns:
            {'status': 0, 'message': 'Made node and its descendants readonly', 'nodeID': '6671c321f6981c28a3a24391'}
            or
            {'status': 0, 'message': 'Made this node readonly', 'nodeID': '6671c321f6981c28a3a24391'}
        """
             
        url = f"https://{self.server}/kirk/domain/node/readonly"
        body = {
            'node_id': nodeID,
            'attribute': 'r',
            'include_all_children': includeAllChildren
        }
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    
    # Make node (and optionally sub-nodes) editable
    def makeEditable(self, nodeID: str, includeAllChildren: str):
        """Make node (and optionally sub-nodes) editable
    
        
        Args:
            nodeID
                string with nodeID of node to make read-only
            includeAllChildren
                string which can be either "True" or "False"

        API:
            POST:  domain/node/readonly

        Returns:
            {'status': 0, 'message': 'Made node and its descendants editable', 'nodeID': '6671c321f6981c28a3a24391'}
            or
            {'status': 0, 'message': 'Made this node editable', 'nodeID': '6671c321f6981c28a3a24391'}
        """
             
        url = f"https://{self.server}/kirk/domain/node/readonly"
        body = {
            'node_id': nodeID,
            'attribute': 'rw',
            'include_all_children': includeAllChildren
        }
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    
    # Get node by POST
    def nodeByPost(self, nodeID: str):
        """Get node by POST
        
        Args:
            nodeID
                string with nodeID of node to get
            

        API:
            POST:  domain/nodeByPost

        Returns:
            dictionary containing document from astro_nodes for nodeID
        """
             
        url = f"https://{self.server}/kirk/domain/nodeByPost"
        body = {
            'nodeID': nodeID
        }
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    

    # Get simple outputs for a node
    def getSimpleOutputs(self, nodeID: str):
        """Get simple outputs for a node
        
        Args:
            nodeID
                string with nodeID of node to get
            

        API:
            GET:  domain/output

        Returns:
            dictionary with simple outputs from astro_data for nodeID
        """
             
        url = f"https://{self.server}/kirk/domain/output/{nodeID}"
        body = {}
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("GET", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    

    # Get ACL (access control list) for portfolio
    def getAcl(self, treeID: str):
        """Get ACL (access control list) for portfolio
        
        Args:
            treeID
                string with name of portfolio
            

        API:
            GET:  domain/portfolio/acl

        Returns:
            dictionary with simple outputs from astro_data for nodeID
        """
             
        url = f"https://{self.server}/kirk/domain/portfolio/acl/{urllib.parse.quote(treeID)}"
        body = {}
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("GET", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    

    # Set ACL (access control list) for portfolio
    def setAcl(self, treeID: str, acl: dict):
        """Set ACL (access control list) for portfolio
        
        Args:
            treeID
                string with name of portfolio
            acl
                dictionary with following schema
                {'group':
                    {'portfolioAdmins':[<list of groupIDs strings],
                    'editors':[<list of groupIDs strings],
                    'viewers':[<list of groupIDs strings]}
                }
            

        API:
            PUT:  domain/portfolio/acl

        Returns:
            Nothing
        """
             
        url = f"https://{self.server}/kirk/domain/portfolio/acl/{urllib.parse.quote(treeID)}"
        body = {
            'acl': acl
        }
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("PUT", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    
    # Get change log for node
    def changeLog(self, nodeID: str):
        """Get change log for node
        
        Args:
            nodeID
                string with nodeID for node
            

        API:
            GET:  domain/portfolio/changes

        Returns:
            list of dicts containing the node change log information
        """
             
        url = f"https://{self.server}/kirk/domain/portfolio/changes/{nodeID}"
        body = {}
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("GET", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    
    # Get portfolio configuration
    def getPortfolioConfig(self, treeID: str):
        """Get portfolio configuration
        
        Args:
            treeID
                string with name of portfolio
            

        API:
            GET:  domain/portfolio/config

        Returns:
            dictionary with keys ['chart', 'table', 'timestamp', 'inputScreen', 'treeID']
        """
             
        url = f"https://{self.server}/kirk/domain/portfolio/config/{urllib.parse.quote(treeID)}"
        body = {}
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("GET", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    
    # Save portfolio configuration
    def savePortfolioConfig(self, treeID: str, portfolioConfig: dict):
        """Save portfolio configuration
        
        Args:
            treeID
                string with name of portfolio
            portfolioConfig
                dictionary with configurations for portfolio 
            

        API:
            POST:  domain/portfolio/config

        Returns:
            ???
        """
             
        url = f"https://{self.server}/kirk/domain/portfolio/config/{urllib.parse.quote(treeID)}"
        body = {
            'portfolioConfig': portfolioConfig
        }
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    
    # Get orphanned node count for a portfolio
    def getOrphanNodesCount(self, treeID: str):
        """Get orphanned node count for a portfolio
        
        Args:
            treeID
                string with name of portfolio
            

        API:
            GET:  domain/portfolio/orphan

        Returns:
            dictionary with keys ['chart', 'table', 'timestamp', 'inputScreen', 'treeID']
        """
             
        url = f"https://{self.server}/kirk/domain/portfolio/orphan/{urllib.parse.quote(treeID)}"
        body = {}
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("GET", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None

    # Delete orphanned nodes for a portfolio
    def fixOrphanNodesCount(self, treeID: str):
        """Delete orphanned nodes for a portfolio
        
        Args:
            treeID
                string with name of portfolio
            

        API:
            DELETE:  domain/portfolio/orphan

        Returns:
            number of orphanned nodes that have been deleted from portfolio
        """
             
        url = f"https://{self.server}/kirk/domain/portfolio/orphan/{urllib.parse.quote(treeID)}"
        body = {}
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("DELETE", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None

    # Recalculate leaves starting at a particular node in tree
    def recalculatePortfolio(self, treeID: str, recalType: str, startNodeID: str, numberOfNodes: int):
        """Recalculate leaves starting at a particular node in tree
        
        Args:
            treeID
                string with name of portfolio
            recalType
                string - choices are "unlocked", "invalid" or "all"
            startNodeID
                string containing nodeID for node in tree to begin recalculation
            numberOfNodes
                integer with number of leaf nodes to recalculate
            

        API:
            POST:  domain/portfolio/recalculate

        Returns:
            {'status': 200, 'message': 'Demo 2021 Make Sell Portfolio is recalculated', 'results': {'treeID': 'Demo 2021 Make Sell Portfolio', 'seriesId': '667348dd4fc23930c303f208', 'recalcResults': {'successCount': 4, 'failedNodes': [], 'timeConsumed': 4.270499255508184}, 'orphanNodes': 0}}
        """
             
        url = f"https://{self.server}/kirk/domain/portfolio/recalculate/{urllib.parse.quote(treeID)}"
        body = {
            'recalType': recalType,
            'startNodeId': startNodeID,
            'numberOfNodes': numberOfNodes
        }
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None


    # Get recalculation record for a portfolio
    def getRecalculateRecord(self, treeID: str):
        """Get recalculation record for a portfolio
        
        Args:
            treeID
                string with name of portfolio
            
        API:
            GET:  domain/portfolio/recalculate

        Returns:
            list of dicts containing the records for all recalculations
        """
             
        url = f"https://{self.server}/kirk/domain/portfolio/recalculate/{urllib.parse.quote(treeID)}"
        body = {}
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("GET", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None

    # Get user priviledge for a node
    def getUserPriviledge(self, nodeID: str):
        """Get user priviledge for a node for the current user
        
        Args:
            nodeID
                string with nodeID of node
            
        API:
            GET:  domain/portfolio/userPrivilege

        Returns:
            user priviledge as a number
            PORTFOLIO_ADMIN = 3
            CONTRIBUTOR = 2
            OBSERVER = 1
            NO_ACCESS = 0
        """
             
        url = f"https://{self.server}/kirk/domain/portfolio/userPrivilege/{urllib.parse.quote(nodeID)}"
        body = {}
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("GET", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None

    # Permanently delete record from recycle bin
    def permanentDeleteRecord(self, nodeID: str, recordID: str):
        """Permanently delete record from recycle bin
        
        Args:
            nodeID
                string with sub-tree nodeID to which to recover recycled node
            recordID
                string with nodeID of recycled node to be recovered
            
        API:
            DELETE:  domain/recycle-bin/

        Returns:
            {'status': 0}
        """
             
        url = f"https://{self.server}/kirk/domain/recycle-bin/{nodeID}/{recordID}"
        body = {}
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("DELETE", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None



    # Get list of nodes in the recycle bin for selected node
    def listRecycleBin(self, nodeID: str):
        """Get list of nodes in the recycle bin for selected node
        
        Args:
            nodeID
                string with nodeID of node
            
        API:
            GET:  domain/recycle-bin/

        Returns:
            List of previously deleted leaves for a node
        """
             
        url = f"https://{self.server}/kirk/domain/recycle-bin/{nodeID}"
        body = {}
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("GET", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    
    # Move node to recycle bin
    def moveToRecycle(self, nodeID: str):
        """Move node to recycle bin
        
        Args:
            nodeID
                string with sub-tree nodeID to which to recover recycled node
            recordID
                string with nodeID of recycled node to be recovered
            
        API:
            POST:  domain/recycle-bin/

        Returns:
            {'deletedNodes': [{'_id': '6671ecb8173cbc2854eafe95', 
            'name': 'test2', 'data': '6671ecb9173cbc2854eafe96', 
            'path': ['61009451167e487b988e5a07_20210827.135659_20230928.105045', 
            '6100947f8cc80bf8f3e0241a_20210827.135659_20230928.105045', 
            '6671c321f6981c28a3a24391']}], 'undeletedNodes': []}
        """
             
        url = f"https://{self.server}/kirk/domain/recycle-bin/{nodeID}"
        body = {}
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None


    # Recover node from recycle bin back to original sub-tree
    def recoverFromRecycle(self, nodeID: str, recordID: str):
        """Recover node from recycle bin back to original sub-tree
        
        Args:
            nodeID
                string with sub-tree nodeID to which to recover recycled node
            recordID
                string with nodeID of recycled node to be recovered
            
        API:
            PUT:  domain/recycle-bin/

        Returns:
            List of previously deleted leaves for a node
        """
             
        url = f"https://{self.server}/kirk/domain/recycle-bin/{nodeID}/{recordID}"
        body = {}
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("PUT", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    

    # Save Smart Text for a node
    def saveSmartText(self, nodeID: str, smartText: str):
        """Save Smart Text for a node
        
        Args:
            nodeID: 
                string representing node _id for a node
            guidance:
                64-bit and utf-8 encoded string for html text to save in guidance
                Example:
                    smartTextDict = {"test1":"<p>this is a test of test1</p>","test2":"<p>this is a test of test2</p>"}
                    smartTextUrlEncoded = urllib.parse.quote(json.dumps(smartTextDict))
                    base64.b64encode(smartTextUrlEncoded.encode()).decode()
                    'JTdCJTIydGVzdDElMjIlM0ElMjIlM0NwJTNFdGhpcyUyMGlzJTIwYSUyMHRlc3QlMjBvZiUyMHRlc3QxJTNDJTJGcCUzRSUyMiUyQyUyMnRlc3QyJTIyJTNBJTIyJTNDcCUzRXRoaXMlMjBpcyUyMGElMjB0ZXN0JTIwb2YlMjB0ZXN0MiUzQyUyRnAlM0UlMjIlN0Q='

        API:
            PUT:  domain/smart-text/save
        Returns:
            {'status': 0, 'message': 'Successfully saved guidance'}
        """
        url = f"https://{self.server}/kirk/domain/smart-text/save/{nodeID}"
        body = {
            'smartText': smartText
        }
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("PUT", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    

    # Get tags for a node
    def tagsFor(self, nodeID: str, filter: str=''):
        """Get tags for a node
        
        Args:
            nodeID:
                string with nodeID of node
            filter:
                string containing filters
            
        API:
            GET:  domain/tags

        Returns:
            list of tags
        """
             
        url = f"https://{self.server}/kirk/domain/tags/{nodeID}"
        if filter:
            url = url+'/'+urllib.parse.quote(filter)
        body = {}
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("GET", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    

    # Save tags data for a node in categories action menu
    def saveTagsData(self, nodeID: str, nodeTagList: List[List[str]], categoryData: dict, menuID: str=''):
        """Save tags data for a node in categories action menu
        
        Args:
            nodeID:
                string with nodeID of node
            nodeTagList:
                list of list of strings of tags for path starting at node and going up to top of tree
                [
                    ["copy093eb0645f0411ee948c002248b4d3f8","all,
                        Line_Of_Business:ConsumerProducts,Project_Status:Proposed,Country:Brazil,Project_Health:Green"],
                    ["copy08c995fe5f0411ee948c002248b4d3f8","all,
                        Line_Of_Business:ConsumerProducts,Line_Of_Business:SportingGoods,Project_Status:Proposed,Country:Brazil,
                        Country:Argentina,Project_Health:Green,Project_Health:Yellow,Project_Health:Red"],
                    ["copy08c990c25f0411ee948c002248b4d3f8","all,
                        Line_Of_Business:ConsumerProducts,Line_Of_Business:SportingGoods,Line_Of_Business:IndustrialProducts,
                        Line_Of_Business:HouseholdAppliances,Project_Status:Proposed,Country:Brazil,Country:Argentina,
                        Project_Health:Green,Project_Health:Yellow,Project_Health:Red"],
                    ["61009451167e487b988e5a07_20210827.135659_20230925.161007_20230928.123639","all,Line_Of_Business:ConsumerProducts,
                        Line_Of_Business:SportingGoods,Line_Of_Business:IndustrialProducts,Line_Of_Business:HouseholdAppliances,
                        Project_Status:Proposed,Country:Brazil,Country:Argentina,Project_Health:Green,Project_Health:Yellow,Project_Health:Red"]
                ] 
            categoryData:
                dictionary containing previous category before being changed
            menuID:
                string with menuID from action menu
            
        API:
            POST:  domain/tagsData

        Returns:
            ???
        """
             
        url = f"https://{self.server}/kirk/domain/tagsData/{nodeID}"
        body = {
            'nodeTagList': nodeTagList, 
            'categoryData': categoryData,
            'menuID': menuID
        }
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    

    # Save tags data for a node
    def saveTags(self, nodeID: str, nodeTagList: List[List[str]]):
        """Save tags data for a node
        
        Args:
            nodeID:
                string with nodeID of node
            nodeTagList:
                list of list of strings of tags for path starting at node and going up to top of tree
                [
                    ["copy093eb0645f0411ee948c002248b4d3f8","all,
                        Line_Of_Business:ConsumerProducts,Project_Status:Proposed,Country:Brazil,Project_Health:Green"],
                    ["copy08c995fe5f0411ee948c002248b4d3f8","all,
                        Line_Of_Business:ConsumerProducts,Line_Of_Business:SportingGoods,Project_Status:Proposed,Country:Brazil,
                        Country:Argentina,Project_Health:Green,Project_Health:Yellow,Project_Health:Red"],
                    ["copy08c990c25f0411ee948c002248b4d3f8","all,
                        Line_Of_Business:ConsumerProducts,Line_Of_Business:SportingGoods,Line_Of_Business:IndustrialProducts,
                        Line_Of_Business:HouseholdAppliances,Project_Status:Proposed,Country:Brazil,Country:Argentina,
                        Project_Health:Green,Project_Health:Yellow,Project_Health:Red"],
                    ["61009451167e487b988e5a07_20210827.135659_20230925.161007_20230928.123639","all,Line_Of_Business:ConsumerProducts,
                        Line_Of_Business:SportingGoods,Line_Of_Business:IndustrialProducts,Line_Of_Business:HouseholdAppliances,
                        Project_Status:Proposed,Country:Brazil,Country:Argentina,Project_Health:Green,Project_Health:Yellow,Project_Health:Red"]
                ]
        API:
            POST:  domain/tags

        Returns:
            ???
        """
             
        url = f"https://{self.server}/kirk/domain/tags/{nodeID}"
        body = {
            'nodeTagList': nodeTagList, 
        }
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    
    # Save Assign Category tags for a node
    def saveAssignCategoryTagsData(self, nodeID: str, nodeTagList: List[List[str]], CategoryData: dict):
        """Save Assign Category tags for a node
        
        Args:
            nodeID:
                string with nodeID of node
            nodeTagList:
                list of list of strings of tags for path starting at node and going up to top of tree
                [
                    ["copy093eb0645f0411ee948c002248b4d3f8","all,
                        Line_Of_Business:ConsumerProducts,Project_Status:Proposed,Country:Brazil,Project_Health:Green"],
                    ["copy08c995fe5f0411ee948c002248b4d3f8","all,
                        Line_Of_Business:ConsumerProducts,Line_Of_Business:SportingGoods,Project_Status:Proposed,Country:Brazil,
                        Country:Argentina,Project_Health:Green,Project_Health:Yellow,Project_Health:Red"],
                    ["copy08c990c25f0411ee948c002248b4d3f8","all,
                        Line_Of_Business:ConsumerProducts,Line_Of_Business:SportingGoods,Line_Of_Business:IndustrialProducts,
                        Line_Of_Business:HouseholdAppliances,Project_Status:Proposed,Country:Brazil,Country:Argentina,
                        Project_Health:Green,Project_Health:Yellow,Project_Health:Red"],
                    ["61009451167e487b988e5a07_20210827.135659_20230925.161007_20230928.123639","all,Line_Of_Business:ConsumerProducts,
                        Line_Of_Business:SportingGoods,Line_Of_Business:IndustrialProducts,Line_Of_Business:HouseholdAppliances,
                        Project_Status:Proposed,Country:Brazil,Country:Argentina,Project_Health:Green,Project_Health:Yellow,Project_Health:Red"]
                ]
            categoryData:
                dictonary containing key for with category name being changed and a sub-dictionary with
                {lastVal: <<last category entry value>>, msg: <<text>>, universalTableComment: <<text stating where this value is being changed>>}
        API:
            POST:  domain/tagsDataFromAssignCate

        Returns:
            ???
        """
             
        url = f"https://{self.server}/kirk/domain/tagsDataFromAssignCate/{nodeID}"
        body = {
            'nodeTagList': nodeTagList, 
            'categoryData': CategoryData
        }
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    

    # Download spreadsheet template for a node
    def downloadSpreadsheet(self, nodeID: str):
        """Download spreadsheet template for a node
        
        Args:
            nodeID:
                string with nodeID of node
        
        API:
            POST:  domain/template-report

        Returns:
            dictionary with keys:  'templateName', 'extension', and 'modelData'
            where 'templateName' is string of template name, 'extendion' is file extension to save to 
            and 'modelData' contains the 64-bit encoded excel spreadsheet 

        Note:
            To save 'modelData' as an excel file to your computer
                import base64
                binary_data = base64.b64deecode(response['modelData'])
                with open(<<filename to save excel file to>>+"."+response['extension'], 'wb') as file:
                    file.write(binary_data)

        """
             
        url = f"https://{self.server}/kirk/domain/template-report/{nodeID}"
        body = {}
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None


    # Get templates for a node
    def templatesFor(self, nodeID: str):
        """Get templates for a node
        
        Args:
            nodeID:
                string with nodeID of node
        
        API:
            GET:  domain/templates/list

        Returns:
            dictionary 'templates' key and list of dicts containing templates that are in the list of Chosen Templates for this node

        """
             
        url = f"https://{self.server}/kirk/domain/templates/list/{nodeID}"
        body = {}
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("GET", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    

    # Get field list for universal table for a node
    def getFieldList(self, 
                            nodeID: str, 
                            schema: dict, 
                            packedReportOptions: str = "e30=", 
                            packedExcludeFilterTags: str = "W10="
                            ):
        """Get field list for universal table for a node
        
        Args:
            nodeID (str):
                string with nodeID of node
            schema (dict):

            packedReportOptions (str, optional):
                string with 64-bit encoded report options dict
                Default value:  "e30=",  decoded value:  {}
            packedExcludeFilterOptions (str, optional):
                string with 64-bit encoded report options dict
                Default value:  "W10=",  decoded value:  []

        
        API:
            POST:  domain/universal/io/fields

        Returns:
            dictionary 
        """
             
        url = f"https://{self.server}/kirk/domain/universal/io/fields"

        testSchema={
                "id": "Maturity Assessment",
                "access": {
                    "portfolioAdmin": True,
                    "contributor": False,
                    "cateContributor": False,
                    "observer": False
                },
                "templates": {
                    "Demo2021MakeSellMatureAssessment": {
                        "templateName": "Demo2021MakeSellMatureAssessment",
                        "leaf": {
                            "inputKeys": [
                                "techMaturity",
                                "valueProp",
                                "manufacturing",
                                "tam"
                            ],
                            "inputTables": {},
                            "outputTables": {}
                        }
                    }
                }
            }

        body = {
            'nodeID': nodeID,
            'schema': schema,
            'packedReportOptions': packedReportOptions,
            'packedExcludeFilterTags': packedExcludeFilterTags
        }
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    

    # Delete universal table schema to root (top-node)
    def deleteUnivSchemaToRoot(self, nodeID: str, schemaName: str):
        """Delete universal table schema to root (top-node)
        
        Args:
            nodeID (str):
                string with nodeID of node
            schemaName (str):
                Name of schema to be deleted from top node

        API:
            POST:  domain/universal/io/schema/delete

        Returns:
            {'status': 0, 'message': 'Universal table davetestnew2 is deleted'}
        """
             
        url = f"https://{self.server}/kirk/domain/universal/io/schema/delete"

        
        body = {
            'node_id': nodeID,
            'schema_name': schemaName
        }
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None


    # Get display name list for a node and its template
    def getDisplayNameList(self, 
                            templateName: str,
                            leafOrPlatform: str,
                            nodeID: str, 
                            ):
        """Get display name list for a node and its template
        
        Args:
            templateName (str): 
                string with name of template
            leafOrPlatform (str):
                string with either "leaf" or "platform"
            nodeID (str):
                string with nodeID of node
           

        
        API:
            POST:  domain/universal/io/schema/fields

        Returns:
            dictionary containing the following keys:  
            ['inputs', 'outputs', 'tableInputs', 'tableOutputs', 'categories']
            Under each sub-key is a list of dicts with a json config for each of the inputs, outputs, etc.
        """
             
        url = f"https://{self.server}/kirk/domain/universal/io/schema/fields"
        body = {
            "template_name": templateName,
            "leaf_or_platform": leafOrPlatform,
            "node_id": nodeID
        }
        
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None


    # Save universal table schema to root (top-node)
    def saveUnivSchemaToRoot(self, nodeID: str, schema: dict, oldName: str = None):
        """Save universal table schema to root (top-node)
        
        Args:
            nodeID (str):
                string with nodeID of node
            schema (dict):
                ???
            oldName (str, optional):
                string with old name of schema to be replaced, Default value = None

        API:
            POST:  domain/universal/io/schema/save

        Returns:
            {'status': 0, 'message': "Universal table 'davetestnew2' is saved", 'schemaName': 'davetestnew2'}
        """
             
        url = f"https://{self.server}/kirk/domain/universal/io/schema/save"

        testSchema = {
            "id": "davetestnew2",
            "access": {
                "portfolioAdmin": True,
                "contributor": False,
                "cateContributor": False,
                "observer": False
            },
            "templates": {
                "Demo2021MakeSellMatureAssessment": {
                    "templateName": "Demo2021MakeSellMatureAssessment",
                    "leaf": {
                        "inputKeys": [
                            "share",
                            "tam",
                            "marketingFteRate"
                        ],
                        "inputTables": {},
                        "outputTables": {}
                    }
                }
            }           
            }

        body = {
            'nodeID': nodeID,
            'schema': schema,
            "oldName": oldName
        }
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None



    # Save inputs and/or categories that have changed in universal table
    def universalSaveInputs(self, treeID: str, inputs: List[dict], comment: str, menuID: str):
        """Save inputs and/or categories that have changed in universal table
        
        Args:
            treeID (str):
                string with name of portfolio
            inputs List(dict):
                list of dicts containing schema with inputs and categories to save changes to
            comment (str):
                string containing comment about this change/update
            menuID (str):
                string in the form of:  "UniversalIO:"+schemaName

        API:
            POST:  domain/universal/io/table/save

        Returns:
            {'status': 0, 'msg': 'Universal table data saved!', 'failureList': []}
        """
             
        url = f"https://{self.server}/kirk/domain/universal/io/table/save"

        exampleInputs = [
                {
                    "id": "61018b4ba2f47065daefeba1_20210827.135659_20230928.105045",
                    "details": {
                        "nodeName": "Oven",
                        "inputs": {
                            "tam": {
                                "0": "90000",
                                "1": "12500"
                            }
                        },
                        "categories": {}
                    }
                }
            ]
        
        body = {
            "tree_id": treeID,
            "inputs": inputs,
            "comment": comment,
            "menu_id": menuID
        }
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None

    # Fetch calculation engine log
    def fetchCalculationEngineLog(self,linesFromBottom: int):
        """Fetch calculation engine log
        
        Args:
            linesFromBottom (int): 
                number of lines to fetch from bottom of log
        
        API:
            GET:  framework/admin/calcengine/log

        Returns:
            dictionary with 'message' and 'EncodeLog' keys
            'EncodeLog' value is string which needs to be url-decoded 
            and then 64-bit decoded

        """
             
        url = f"https://{self.server}/kirk/framework/admin/calcengine/log/{linesFromBottom}"
        body = {}
        
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("GET", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None


    # Delete group
    def deleteGroup(self, groupID: str):
        """Delete group
        
        Args:
            groupID (str):
                string with group ID to delete
        
        API:
            DELETE:  framework/admin/group/doc/{groupID}

        Returns:
            'delete group <<name of new group>>'

        """
             
        url = f"https://{self.server}/kirk/framework/admin/group/doc/{groupID}"
        body = {}
        
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("DELETE", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None




    # Create new group
    def createNewGroup(self, groupName: str, description: str, downloadModel: bool):
        """Create new group
        
        Args:
            groupName (str):
                string with name of new group
            description (str):
                string with description of group
            downloadModel (bool):
                flag whether to allow group to download template model
        
        API:
            POST:  framework/admin/group/doc

        Returns:
            'added group <<name of new group>>'

        """
             
        url = f"https://{self.server}/kirk/framework/admin/group/doc"
        body = {
            'groupName': groupName,
            'groupDescription': description,
            'canDownloadModel': downloadModel
        }
        
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None


    # Edit group info
    def editGroup(self, groupID: str, groupName: str, description: str, downloadModel: bool):
        """Edit group info
        
        Args:
            groupID (str):
                string with group ID to be edited
            groupName (str):
                string with edit to groupName
            description (str):
                string with edit to group description
            downloadModel (bool):
                change to whether to download template model
        
        API:
            PUT:  framework/admin/group/doc/{groupID}

        Returns:
            'added group <<name of new group>>'

        """
             
        url = f"https://{self.server}/kirk/framework/admin/group/doc/{groupID}"
        body = {
            'groupName': groupName,
            'groupDescription': description,
            'canDownloadModel': downloadModel
        }
        
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("PUT", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None




    # Get List of Chosen Groups for a Portfolio
    def getListOfChosenGroups(self,treeID: str):
        """Get List of Chosen Groups for a Portfolio
        
        Args:
            treeID (str): 
                string with name of portfolio (top-most node)
        
        API:
            GET:  framework/admin/chosen/group/{urllib.parse.quote(treeID)}

        Returns:
            list of dictionaries containing each group with access to this portfolio

        """
             
        url = f"https://{self.server}/kirk/framework/admin/chosen/group/{urllib.parse.quote(treeID)}"
        body = {}
        
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("GET", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None

    # Get List of Groups
    def getListOfGroups(self):
        """Get List of Groups
        
        
        API:
            GET:  framework/admin/group/list

        Returns:
            list of dictionaries containing groups in server

        """
             
        url = f"https://{self.server}/kirk/framework/admin/group/list"
        body = {}
        
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("GET", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    

    # Set password for user
    def adminSetPassword(self, username: str, password: str):
        """Set password for user

        Args:
            username (str):
                string with username
            password (str):
                string with new password


        
        API:
            POST:  framework/admin/password

        Returns:
            'modifyUser'

        """     
        url = f"https://{self.server}/kirk/framework/admin/password"
        body = {
            'username': username,
            'newpassword': password
        }
        
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None


    # Fetch all pypeer logs
    def fetchAllPypeerLog(self):
        """Fetch all pypeer logs (Not working)
        API:
            POST:  framework/admin/pypeer/all_logs

        Returns:
            ???

        """     
        url = f"https://{self.server}/kirk/framework/admin/pypeer/all_logs"
        body = {}
        
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    

    # Fetch pypeer logs
    def fetchPypeerLog(self,
                       daysFromToday: int,
                       startTime = None,
                       endTime = None,
                       userName: str = None,
                       logType = None
                       ):
        """Fetch pypeer logs

            POST:  framework/admin/pypeer/log

        Returns:
            ???

        """     
        url = f"https://{self.server}/kirk/framework/admin/pypeer/log"
        body = {
            "daysFromToday": daysFromToday,
            "startTime": startTime,
            "endTime": endTime,
            "userName": userName,
            "logType": logType
        }
        
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    

    # Delete user
    def deleteUser(self, userID: str):
        """Delete user
        
        Args:
            userID (str):
                string with userID

        API:
            DELETE:  framework/admin/user/doc

        Returns:
            Example return: 
            'deleted user Tommy and removed from 1 group(s)'

        """
             
        url = f"https://{self.server}/kirk/framework/admin/user/doc/{userID}"
        body = {}
        
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("DELETE", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None



    # Get user profile by userID
    def getUserProfileByID(self, userID: str):
        """Get user profile by userID
        
        Args:
            userID (str):
                string with userID

        API:
            GET:  framework/admin/user/doc

        Returns:
            Example return: 
            {'_id': '669fdeab4f446a5b2228dd47', 'username': 'Tommy', 'name': 'Thompson, Tommy', 
            'passwordAttempts': 0, 'locked': False, 'description': '', 'created': 'Tue Jul 23 16:47:39 2024', 
            'password_change_time': '2024-07-23 16:47:39.651595', 'email': 'tom@mail.com', 'phone1': ',', 
            'organisation': '', 'email_verified': True}

        """
             
        url = f"https://{self.server}/kirk/framework/admin/user/doc/{userID}"
        body = {}
        
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("GET", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None


    # Create new user
    def newUser(self, username: str, name: str, password: str, email: str, defaultGroupName: str, phone1:str = ",", organisation: str = ""):
        """Create new user
        
        Args:
            username (str):
                string with username
            name (str):
                string in form of "<<Last Name>>, <<First Name>>"
            password (str):
                string with password
            email (str):
                valid email address
            defaultGroupName (str):
                string containing the name of one of the available groups
            phone1 (str) optional:
                string with phone number
            organisation (str) optional:
                string with name of organization associated with the user
            
        API:
            POST:  framework/admin/user/doc

        Returns:
            returns string containing userID

        """
             
        url = f"https://{self.server}/kirk/framework/admin/user/doc"
        body = {
            'username': username,
            'name': name,
            'password': password,
            'phone1': phone1,
            'email': email,
            'organisation': organisation,
            'defaultGroup': defaultGroupName
        }
        
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    

    # Modify existing user
    def modifyExistingUser(self, userID: str, username: str, name: str, email: str, defaultGroupName: str, phone1:str = ",", organisation: str = ""):
        """Modify existing user
        
        Args:
            userID (str):
                string containing userID
            username (str):
                string with username
            name (str):
                string in form of "<<Last Name>>, <<First Name>>"
            email (str):
                valid email address
            defaultGroupName (str):
                string containing the name of one of the available groups
            phone1 (str) optional:
                string with phone number
            organisation (str) optional:
                string with name of organization associated with the user
            
        API:
            PUT:  framework/admin/user/doc

        Returns:
            returns 'User modified!'

        """
             
        url = f"https://{self.server}/kirk/framework/admin/user/doc"
        body = {
            'userID': userID,
            'username': username,
            'name': name,
            'phone1': phone1,
            'email': email,
            'organisation': organisation,
            'defaultGroup': defaultGroupName
        }
        
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("PUT", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None





    # Get List of Users
    def getListOfUsers(self):
        """Get List of Users
        
        
        API:
            GET:  framework/admin/user/list

        Returns:
            list of dictionaries containing users in server

        """
             
        url = f"https://{self.server}/kirk/framework/admin/user/list"
        body = {}
        
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("GET", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None


    # Update user admin settings
    def updateUserAdminSettings(self, userID: str, adminSettings: dict):
        """Update user admin settings
        
        Args:
            userID (str): 
                string with userID
            adminSettings (dict):
                dictionary with keys:
                    passwordChange: bool
                    resetToFirstLogin: bool

        API:
            PUT:  framework/admin/user/settings

        Returns:
            Possible return:  {'status': 0,
 'messages': ['Force user to change password on next login.',
  'Reset user to first login state.']}

        """
             
        url = f"https://{self.server}/kirk/framework/admin/user/settings"
        body = {
            'userID': userID,
            'passwordChange': adminSettings['passwordChange'],
            'resetToFirstLogin': adminSettings['resetToFirstLogin']
        }
        
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("PUT", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None



    # Add a user to a group
    def groupAddUser(self, groupID: str, userID: str):
        """Add a user to a group
        
        Args:
            groupID (str):
                string with groupID
            userID (str): 
                string with userID

        API:
            POST:  framework/admin/usergroup

        Returns:
            Possible responses:
            'User <user_name> added to group Testing'
            'User <user_name> already in group Testing'

        """
             
        url = f"https://{self.server}/kirk/framework/admin/usergroup"
        body = {
            "user_id": userID,
            "group_id": groupID,
            "action": "add"
        }
        
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None


    # Remove a user to a group
    def groupRemoveUser(self, groupID: str, userID: str):
        """Remove a user to a group
        
        Args:
            groupID (str):
                string with groupID
            userID (str): 
                string with userID

        API:
            POST:  framework/admin/usergroup

        Returns:
            'User <user_name> removed from group Testing'

        """
             
        url = f"https://{self.server}/kirk/framework/admin/usergroup"
        body = {
            "user_id": userID,
            "group_id": groupID,
            "action": "delete"
        }
        
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None



    # Get welcome message
    def getWelcomeMessage(self, messageType: str):
        """Get welcome message
        
        Args:
            messageType (str):
                either "LICENSE" or "SECURITY_WARNING_WB"

        API:
            GET:  framework/admin/welcome/message

        Returns:
            {'status': 0,
                'data':
                {
                    '_id':string with id of message in astro_message,
                    'type': 'LICENSE' or 'SECURITY_WARNING_WB',
                    'config':
                    {
                        'state': 0,
                        'message': url-encoded(64-bit encoded text message)
                    }
                }
            }
        """
             
        url = f"https://{self.server}/kirk/framework/admin/welcome/message/{messageType}"
        body = {}
        
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("GET", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None

    # Set welcome message
    def setWelcomeMessage(self, messageType: str, message: str, state:int):
        """Set welcome message
        
        Args:
            messageType (str):
                either "LICENSE" or "SECURITY_WARNING_WB"
            message (str):
                64-bit encoded(url-encoded message)
            state (int):
                0 - Do not show
                1 - Show if the license is NOT accepted
                2 - Show on every login

        API:
            POST:  framework/admin/welcome/message

        Returns:
            {'status': 0, 'messages': ['Message saved']}
        """
             
        url = f"https://{self.server}/kirk/framework/admin/welcome/message/{messageType}"
        body = {
            'message': message,
            'state': state
        }
        
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None


    # Get API version number
    def getApiVersionNumber(self):
        """Get API version number
        
        Args:
            none

        API:
            GET:  framework/api/version/number

        Returns:
             {'controllerVersion': '5.15.0', 'calcEngineMessage': {'tooOld': False}, 'monoMessage': {'tooOld': False}}
            Note:  No JWT token is returned as this API doesn't require authentication
        """
             
        url = f"https://{self.server}/kirk/framework/api/version/number"
        body = {}
        
        # No authorization is needed for this API call
        self.headers['Authorization'] = None

        response = request_call("GET", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        
        if response:
            # No JWT token is returned for this API call
            return response.json()
        return None

    # Get calculation engine info
    def getCalculationEngineInfo(self):
        """Get calculation engine info
        
        Args:
            none

        API:
            GET:  framework/calcengine/version

        Returns:
            {'versionNumber': '2.3.3', 'logLevel': 'error'}
            Note:  No JWT token is returned as this API doesn't require authentication
        """
             
        url = f"https://{self.server}/kirk/framework/calcengine/version"
        body = {}
        
        # No authorization is needed for this API call
        self.headers['Authorization'] = None

        response = request_call("GET", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        
        if response:
            # No JWT token is returned for this API call
            return response.json()
        return None

    # Get server configuration
    def getServerConfig(self):
        """Get server configuration
        
        Args:
            none

        API:
            GET:  framework/config

        Returns:
            {'defaultAuth': 'PSW',
            'apiVersion': {'controllerVersion': '5.15.0',
            'calcEngineMessage': {'tooOld': False},
            'monoMessage': {'tooOld': False}},
            'clientAdminEmail': 'support@smartorg.com',
            'zendeskToggle': True,
            'downloadModelToggle': True,
            'richTextBox': None,
            'disableTutorial': False,
            'isInav': True,
            'calcEngineAccess': False,
            'userPortfolioAccess': False,
            'wizardUserAccess': False,
            'isCorteva': False}
            Note:  No JWT token is returned as this API doesn't require authentication
        """
             
        url = f"https://{self.server}/kirk/framework/config"
        body = {}
        
        # No authorization is needed for this API call
        self.headers['Authorization'] = None

        response = request_call("GET", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        
        if response:
            # No JWT token is returned for this API call
            return response.json()
        return None

    # Get server date and time
    def getServerDateTime(self):
        """Get server date and time
        
        Args:
            none

        API:
            GET:  framework/datetime

        Returns:
            'Aug 06 2024 21:30:58 (UTC)'
            Note:  No JWT token is returned as this API doesn't require authentication
        """
             
        url = f"https://{self.server}/kirk/framework/datetime"
        body = {}
        
        # No authorization is needed for this API call
        self.headers['Authorization'] = None

        response = request_call("GET", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        
        if response:
            # No JWT token is returned for this API call
            return response.json()
        return None


    # Get user profile for current user
    def getUserProfile(self):
        """Get user profile for current user
        
        API:
            GET:  framework/user/detail

        Returns:
            Example return:
            {'_id': '6515d5647c74eac067b1a8b4', 'username': 'Dave', 
            'name': 'Wachenschwanz, David', 'passwordAttempts': 0, 
            'locked': False, 'description': '', 'created': 'Thu Sep 28 19:35:00 2023', 
            'password_change_time': '2023-09-28 19:35:00.919105', 'email': 'dwachenschwanz@smartorg.com', 
            'phone1': ',', 'organisation': 'SmartOrg', 'email_verified': True, 
            'active_key': '', 'active_expire': '', 'admin': {'force_password_change': False}, 'isFirstLogin': False}
        """
             
        url = f"https://{self.server}/kirk/framework/user/detail"
        body = {}
        
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("GET", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None


    # Save (update) user profile for current user
    def saveUserProfile(self, username:str, name: str, email: str, phone1: str, organisation:str):
        """Save (update) user profile for current user
        
        Args:
            username (str):
                string with username
            name (str):
                string with <last_name,first_name>
            email (str):
                string with email
            phone1 (str):
                string with phone number
            organisation (str):
                string with organisation name

        API:
            PUT:  framework/user/detail

        Returns:
            ???
        """
             
        url = f"https://{self.server}/kirk/framework/user/detail"
        body = {
            'username': username,
            'name': name,
            'phone1': phone1,
            'email': email,
            'organisation': organisation
        }
        
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("PUT", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None



    # Get action for a node
    def actionFor(self, 
                    actionID: str,
                    nodeID: str, 
                    packedReportOptions: str = "e30=",
                    packedExcludeFilterTags: str = "W10=",
                    ):
        """Get display name list for a node and its template
        
        Args:
            actionID (str): 
                string with name of action in action menu
            leafOrPlatform (str):
                string with either "leaf" or "platform"
            nodeID (str):
                string with nodeID of node
            packedReportOptions (str, optional):
                string with 64-bit encoded report options dict
                Default value:  "e30=",  decoded value:  {}
            packedExcludeFilterOptions (str, optional):
                string with 64-bit encoded report options dict
                Default value:  "W10=",  decoded value:  []
           

        
        API:
            POST:  template/actionMenu

        Returns:
            dictionary containing the following keys:  
            ['data'] -> with following sub-keys:
            ['inputScreenConfig', 'selectedInputKey', 'settings']
            where ['inputScreenConfig'] has the following sub-keys:
            ['main', 'sibling', 'user', 'nodeAttribute']
            where ['main'] contains the following sub-keys:
            ['nodeID', 'nodeName', 'templateID', 'targetDS', 'leafOrPlatform', 
            'inputs', 'invisibleInputs', 'savableInputs', 'impactMappingList', 
            'nColCanvasSwotData', 'colHeaders', 'radioOrCheckbox', 'npvSwing', 'issueConfig']

        """
             
        url = f"https://{self.server}/kirk/template/actionMenu/{actionID}/{nodeID}"
        body = {
            'packed_report_options': packedReportOptions,
            'packed_exclude_filter_tags': packedExcludeFilterTags
        }
        
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None


    # Save data inputs for a node
    def saveInputs(self, nodeID: str, inputs: List[dict], forceSync: bool=False):
        """Save data inputs for a node
        
        Args:
            nodeID (str):
                string with nodeID of node
            inputs List(dict):
                List of dicts for each input being updated.  Dicts are of format:
                {
                    "Val": [
                        10,
                        30,
                        40
                    ],
                    "Key": "asp",
                    "Comment": [
                        {
                            "SavedBy": "Dave",
                            "SavedOn": "Mon%20Jul%2022%2015%3A09%3A37%202024",
                            "lastVal": [
                                21,
                                30,
                                40
                            ],
                            "msg": ""
                        }
                    ]
                }
            forceSync (bool): default = False
                Recalculation flag
            
        
        API:
            POST:  template/input/save

        Returns:
            {}

        """
             
        url = f"https://{self.server}/kirk/template/input/save"
        body = {
            'nodeID': nodeID,
            'inputs': inputs,
            'recalc': forceSync
        }
        
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    
    # Get specified inputs for a node
    def inputsFor(self, nodeID: str, inputKeys: str):
        """Get specified inputs for a node
        
        Args:
            nodeID (str):
                string with nodeID of node
            inputKeys (str):
                a pipe-delimited list of input keys 
                e.g. "marketSize|marketShare|discountRate"
           

        
        API:
            GET:  template/inputs/{nodeID}/{urllib.parse.quote(inputKeys)}

        Returns:
            dictionary containing ???

        """
             
        url = f"https://{self.server}/kirk/template/inputs/{nodeID}/{urllib.parse.quote(inputKeys)}"
        body = {}
        
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("GET", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None

    # Get shared data (common data) for a node
    def sharedDataFor(self, nodeID: str):
        """Get shared data (common data) for a node
        
        Args:
            nodeID (str):
                string with nodeID of node
            
        
        API:
            POST:  template/share-data/{nodeID}

        Returns:
            dictionary containing the following keys: ['inputScreenConfig', 'selectedInputKey', 'settings', 'readOnly']

        """
             
        url = f"https://{self.server}/kirk/template/share-data/{nodeID}"
        body = {}
        
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
    

    # Save broadcast messages
    def saveMessages(self, messages: dict):
        """Save broadcast messages

        Description:
            Message documents are saved in the astro_messages collection of the mongoDB database
        
        Args:
            messages
                list of dictionaries with messages to save
                [
                    {
                        "_id": "",
                        "title": "API message saving",
                        "message": "I am trying to save this message using the API",
                        "everyoneCanSee": True,
                        "alwaysShowMessage": True,
                        "groups": []
                    }
                ]
           
        
        API:
            POST:  framework/admin/broadcast/messages/save

        Returns:
            [{'title': 'API message saving',
            'message': 'I am trying to save this message using the API',
            'everyoneCanSee': True,
            'alwaysShowMessage': True,
            'groups': [],
            'lastModifyUsername': 'Dave',
            'lastModifyTime': '2024-08-06 22:18:07 UTC',
            '_id': '66b2a11ffe1bccce3b871c8d'}]

        """
             
        url = f"https://{self.server}/kirk/framework/admin/broadcast/messages/save"
        body = messages
        
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None



    # Get list of broadcast messages
    def getMessages(self):
        """Get list of broadcast messages
        
        Args:
            none
           
        
        API:
            POST:  framework/admin/broadcast/messages/list

        Returns:
            dictionary containing ???

        """
             
        url = f"https://{self.server}/kirk/framework/admin/broadcast/messages/list"
        body = {}
        
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None


    # Delete all broadcast messages
    # def deleteAllMessages(self):
    #     """Delete all broadcast messages (NOT WORKING)

    #     Description:
    #         Message documents are saved in the astro_messages collection of the mongoDB database
        
    #     Args:
    #         none
                
        
    #     API:
    #         DELETE:  framework/admin/broadcast/messages/delete

    #     Returns:
          
    #     """
             
    #     url = f"https://{self.server}/kirk/framework/admin/broadcast/messages/delete"
    #     body = {}
        
    #     self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

    #     response = request_call("DELETE", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
    #     if response:
    #         data = response.json()["data"]
    #         self.token = response.json()["token"]
    #         return data
    #     return None



    # Delete list of broadcast messages
    def deleteListOfMessages(self, idList):
        """Delete list of broadcast messages

        Description:
            Message documents are saved in the astro_messages collection of the mongoDB database
        
        Args:
            idList
                list containing _id of all messages in astro_messages to delete
                
        
        API:
            POST:  framework/admin/broadcast/messages/delete

        Returns:
          
        """
             
        url = f"https://{self.server}/kirk/framework/admin/broadcast/messages/delete"
        body = idList
        
        self.headers['Authorization'] = f'jwttoken {self.token}'.encode('utf-8')

        response = request_call("POST", url, headers=self.headers, json=body, timeout=self.timeout, verify=self.verify)
        if response:
            data = response.json()["data"]
            self.token = response.json()["token"]
            return data
        return None
