from pymongo import MongoClient

# mongoDB helper class
class SmartMongoDB:
    def __init__(self):
        self.__client = MongoClient('mongodb://localhost:27017/')
        self.__db = self.__client['astro_db']
        self.__astro_nodes = self.__db['astro_nodes']
        self.__astro_data = self.__db['astro_data']
        self.__name_cache = {}

    def portfolio_exists(self,treeID):
        self.__treeID = treeID
        query = {"treeID": self.__treeID, "parent": None}
        document = self.__astro_nodes.find_one(query)
        
        if document:
            # Save list of entries in ProjectStatus category
            self.__projectStatusEntries = [cat for cat in document['categoriesConfig'] if cat['CategoryName'] =="ProjectStatus"][0]['CategoryEntries']
            return True
        else:
            return False

    @property
    def project_status_entries(self):
        return self.__projectStatusEntries

    def get_project_status(self, tags):
        project_status = next((item for item in tags if 'ProjectStatus' in item), None)
    
        if project_status:
            project_status_value = project_status.split(":", 1)[1]  # Split and get the second part
        else:
            project_status_value = None
            
        return project_status_value


    def list_of_excluded_projects(self, filter=[]):

        if filter:
            query = {
                'treeID': self.__treeID,
                'children':[],
                "tags": {"$in": [f'ProjectStatus:{entry}' for entry in filter]}
            }
    
            projection = {'_id':1, 'data':1, 'name':1, 'parent':1, 'path':1,  'children':1, 'tags':1}
            
            nodes = list(self.__astro_nodes.find(query,projection))

            for n in nodes:
                n['ProjectStatus'] = self.get_project_status(n['tags'])
            return nodes
        else:
            return []

    def get_node_names(self,nodeIDs=[]):
        names = []
        for n in nodeIDs:
            if n in self.__name_cache:
                names.append(self.__name_cache[n])
                # print('cached')
            else:
                query = {'_id':n}
                projection = {'_id': 0, 'name':1}
                res = self.__astro_nodes.find_one(query,projection)
                names.append(res['name'])
                self.__name_cache[n] = res['name']
                # print('queried')
        return names

    def delete_node(self,node):

        delete_lst = []

        delete_lst.append(node)
        parent = node['parent'][0]
    
        # print(node['name'],parent)
    
        query = {
                '_id': parent,
                'children': {'$size': 1}
            }
        projection = {'_id':1, 'data':1, 'name':1, 'parent':1, 'path':1,  'children':1, 'tags': 1 }
    
        pNode = self.__astro_nodes.find_one(query,projection)
        if pNode:
            while pNode:
                # print('\t',pNode['name'],pNode['_id'], len(pNode['children']))
                delete_lst.append(pNode)
                query = {
                    '_id': pNode['parent'][0],
                    'children': {'$size': 1}
                }
                lastNode = pNode
                pNode = self.__astro_nodes.find_one(query,projection)
            # print('\t','Delete: ', lastNode['name'],lastNode['_id'])
            # res = so.deleteNode(lastNode['_id'])
        # else:
        #     print('\t','Delete Leaf: ', node['name'], node['_id'])
            # res = so.deleteNode( row['_id'])

        return delete_lst
        