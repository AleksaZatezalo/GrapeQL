"""
GraphQL schema analysis and management

Author: Aleksa Zatezalo
Version: 3.0
"""

from typing import Dict, List, Optional, Any, Set


class SchemaAnalyzer:
    """
    Analyzes GraphQL schemas to extract useful information for security testing.
    """
    
    def __init__(self, client):
        """
        Initialize with an HTTP client.
        
        Args:
            client: GraphQLHTTPClient instance
        """
        self.client = client
        self.schema = None
        self.query_type = None
        self.mutation_type = None
        self.subscription_type = None
        self.types = {}
        self.query_fields = {}
        self.mutation_fields = {}
        self.subscription_fields = {}
    
    async def load_schema(self) -> bool:
        """
        Load the GraphQL schema via introspection.
        
        Returns:
            bool: True if schema was loaded successfully
        """
        # Get the schema
        result = await self.client.introspection_query()
        
        if not result.get("data", {}).get("__schema"):
            return False
            
        # Store the raw schema
        self.schema = result["data"]["__schema"]
        
        # Process schema information
        self._process_types()
        self._process_operation_fields()
        
        return True
    
    def _process_types(self) -> None:
        """Process and organize type information from the schema."""
        types = self.schema.get("types", [])
        
        for type_info in types:
            type_name = type_info.get("name")
            type_kind = type_info.get("kind")
            
            # Skip built-in types
            if type_name and type_name.startswith("__"):
                continue
                
            # Store type info
            self.types[type_name] = {
                "kind": type_kind,
                "fields": type_info.get("fields", [])
            }
            
            # Identify root operation types
            query_type = self.schema.get("queryType", {}).get("name")
            if type_name == query_type:
                self.query_type = type_name
                
            mutation_type = self.schema.get("mutationType", {}).get("name")
            if type_name == mutation_type:
                self.mutation_type = type_name
                
            subscription_type = self.schema.get("subscriptionType", {}).get("name")
            if type_name == subscription_type:
                self.subscription_type = type_name
    
    def _process_operation_fields(self) -> None:
        """Process fields for query, mutation, and subscription types."""
        # Process query fields
        if self.query_type and self.query_type in self.types:
            for field in self.types[self.query_type].get("fields", []):
                self.query_fields[field["name"]] = {
                    "args": field.get("args", []),
                    "type": field.get("type", {})
                }
                
        # Process mutation fields
        if self.mutation_type and self.mutation_type in self.types:
            for field in self.types[self.mutation_type].get("fields", []):
                self.mutation_fields[field["name"]] = {
                    "args": field.get("args", []),
                    "type": field.get("type", {})
                }
                
        # Process subscription fields
        if self.subscription_type and self.subscription_type in self.types:
            for field in self.types[self.subscription_type].get("fields", []):
                self.subscription_fields[field["name"]] = {
                    "args": field.get("args", []),
                    "type": field.get("type", {})
                }
    
    def get_type_name(self, type_info: Dict) -> Optional[str]:
        """
        Get the name of a type, handling non/nullable and list types.
        
        Args:
            type_info: Type information object
            
        Returns:
            Optional[str]: Type name or None
        """
        # Handle direct name
        if type_info.get("name"):
            return type_info["name"]
            
        # Handle ofType for NON_NULL and LIST types
        of_type = type_info.get("ofType")
        if of_type:
            return self.get_type_name(of_type)
            
        return None
    
    def get_string_fields(self, is_mutation: bool = False) -> Dict[str, List[str]]:
        """
        Get all fields that accept string inputs, useful for injection testing.
        
        Args:
            is_mutation: Whether to get mutation fields (True) or query fields (False)
            
        Returns:
            Dict[str, List[str]]: Dictionary mapping field names to string argument names
        """
        string_fields = {}
        fields_dict = self.mutation_fields if is_mutation else self.query_fields
        
        for field_name, field_info in fields_dict.items():
            string_args = []
            
            for arg in field_info.get("args", []):
                arg_type = self.get_type_name(arg.get("type", {}))
                
                if arg_type in ("String", "ID"):
                    string_args.append(arg["name"])
                    
            if string_args:
                string_fields[field_name] = string_args
                
        return string_fields
    
    def find_circular_references(self) -> List[Dict]:
        """
        Find circular references in the schema for DoS testing.
        
        Returns:
            List[Dict]: List of circular references
        """
        circular_refs = []
        
        for type_name, type_info in self.types.items():
            for field in type_info.get("fields", []):
                field_type = self.get_type_name(field.get("type", {}))
                
                # Check if field returns another object type
                if field_type in self.types:
                    # Look for fields in the target type that reference back
                    target_fields = self.types[field_type].get("fields", [])
                    for target_field in target_fields:
                        target_field_type = self.get_type_name(target_field.get("type", {}))
                        
                        if target_field_type == type_name:
                            circular_refs.append({
                                "source_type": type_name,
                                "source_field": field["name"],
                                "target_type": field_type,
                                "target_field": target_field["name"]
                            })
                    
        return circular_refs
    
    def generate_dos_query(self) -> str:
        """
        Generate a query that could potentially cause a DoS condition.
        
        Returns:
            str: The DoS query
        """
        # Find circular references
        circular_refs = self.find_circular_references()
        
        if not circular_refs:
            # No circular references, use a simple nested query on a field that returns an object
            for field_name, field_info in self.query_fields.items():
                field_type = self.get_type_name(field_info.get("type", {}))
                
                if field_type in self.types and field_type != self.query_type:
                    # Found a field that returns an object, generate nested query
                    nested_query = "id\nname\ndescription"
                    
                    # Add nesting
                    for _ in range(5):  # 5 levels of nesting
                        nested_query = f"""
                        {field_name} {{
                            {nested_query}
                        }}
                        """
                    
                    return f"query DoSTest {{\n{nested_query}\n}}"
            
            # No suitable fields found
            return "query { __typename }"
            
        else:
            # Use circular references to create a deeply nested query
            ref = circular_refs[0]
            source_type = ref["source_type"]
            source_field = ref["source_field"]
            target_type = ref["target_type"]
            target_field = ref["target_field"]
            
            # Start with a simple selection
            nested_query = "id\nname"
            
            # Add circular nesting
            for _ in range(5):  # 5 levels of nesting
                nested_query = f"""
                {source_field} {{
                    id
                    name
                    {target_field} {{
                        id
                        name
                        {nested_query}
                    }}
                }}
                """
            
            # Find a query field that returns the source type
            query_field = None
            for field_name, field_info in self.query_fields.items():
                field_type = self.get_type_name(field_info.get("type", {}))
                if field_type == source_type:
                    query_field = field_name
                    break
            
            if not query_field:
                # Fallback to __typename if no suitable field found
                return "query { __typename }"
            
            return f"query DoSTest {{\n{query_field} {{\n{nested_query}\n}}\n}}"
    
    def get_injectable_fields(self) -> Dict[str, List[Dict]]:
        """
        Get fields that might be vulnerable to injection attacks.
        
        Returns:
            Dict[str, List[Dict]]: Dictionary mapping operation types to injectable fields
        """
        injectable = {
            "query": [],
            "mutation": []
        }
        
        # Check query fields
        for field_name, field_info in self.query_fields.items():
            for arg in field_info.get("args", []):
                arg_type = self.get_type_name(arg.get("type", {}))
                if arg_type in ("String", "ID"):
                    injectable["query"].append({
                        "field": field_name,
                        "arg": arg["name"],
                        "type": arg_type
                    })
        
        # Check mutation fields
        for field_name, field_info in self.mutation_fields.items():
            for arg in field_info.get("args", []):
                arg_type = self.get_type_name(arg.get("type", {}))
                if arg_type in ("String", "ID"):
                    injectable["mutation"].append({
                        "field": field_name,
                        "arg": arg["name"],
                        "type": arg_type
                    })
        
        return injectable
    
    def is_server_secure(self) -> Dict:
        """
        Perform basic security checks based on schema analysis.
        
        Returns:
            Dict: Dictionary of potential security issues
        """
        issues = []
        
        # Check for sensitive field names in queries
        sensitive_names = ["password", "token", "secret", "key", "auth", "credential"]
        for field_name in self.query_fields:
            for sensitive in sensitive_names:
                if sensitive.lower() in field_name.lower():
                    issues.append({
                        "title": f"Potentially sensitive field in query: {field_name}",
                        "severity": "MEDIUM"
                    })
        
        # Check for unsecured mutation fields
        if self.mutation_fields:
            for field_name in self.mutation_fields:
                # Check for mutations that might alter data without auth args
                if any(action in field_name.lower() for action in ["create", "update", "delete", "remove"]):
                    mutation = self.mutation_fields[field_name]
                    has_auth_arg = False
                    
                    for arg in mutation.get("args", []):
                        arg_name = arg.get("name", "").lower()
                        if any(auth_term in arg_name for auth_term in ["token", "auth", "key", "api"]):
                            has_auth_arg = True
                            break
                    
                    if not has_auth_arg:
                        issues.append({
                            "title": f"Mutation {field_name} may lack authentication parameters",
                            "severity": "HIGH"
                        })
        
        return issues