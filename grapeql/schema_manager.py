"""
Author: Aleksa Zatezalo
Version: 1.0
Date: March 2025
Description: GraphQL schema management for testing tools
"""

from typing import Dict, List, Optional, Any, Set, Tuple
from .http_client import GraphQLClient

class SchemaManager:
    """
    Manages GraphQL schema information for testing tools.
    Parses and provides structured access to schema elements.
    """
    
    def __init__(self, client: GraphQLClient):
        """
        Initialize with a GraphQL client.
        
        Args:
            client: GraphQLClient instance for making requests
        """
        self.client = client
        self.schema: Optional[Dict] = None
        self.query_type: Optional[str] = None
        self.mutation_type: Optional[str] = None
        self.subscription_type: Optional[str] = None
        self.types: Dict[str, Dict] = {}
        self.query_fields: Dict[str, Dict] = {}
        self.mutation_fields: Dict[str, Dict] = {}
        self.subscription_fields: Dict[str, Dict] = {}
        self.directives: List[Dict] = []
    
    async def load_schema(self) -> bool:
        """
        Load the GraphQL schema via introspection.
        
        Returns:
            bool: True if schema was loaded successfully, False otherwise
        """
        # Get the schema via introspection
        result = await self.client.introspection_schema()
        
        if not result.get("data", {}).get("__schema"):
            return False
            
        # Store the raw schema
        self.schema = result["data"]["__schema"]
        
        # Extract type information
        self._process_types()
        
        # Extract query, mutation, and subscription fields
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
    
    def get_field_type_name(self, type_info: Dict) -> Optional[str]:
        """
        Get the name of a field type, handling non/nullable and list types.
        
        Args:
            type_info: Type information object from GraphQL schema
            
        Returns:
            Optional[str]: Type name or None if not found
        """
        # Handle direct name
        if type_info.get("name"):
            return type_info["name"]
            
        # Handle ofType for NON_NULL and LIST types
        of_type = type_info.get("ofType")
        if of_type:
            return self.get_field_type_name(of_type)
            
        return None
    
    def find_circular_references(self) -> List[Dict]:
        """
        Find circular references in the schema.
        
        Returns:
            List[Dict]: List of circular references
        """
        circular_refs = []
        
        for type_name, type_info in self.types.items():
            for field in type_info.get("fields", []):
                field_type_name = self.get_field_type_name(field.get("type", {}))
                
                # If field type is another object type
                if field_type_name in self.types:
                    circular_refs.append({
                        "type": type_name,
                        "field": field["name"],
                        "target": field_type_name
                    })
                    
        return circular_refs
    
    def get_scalar_fields(self, type_name: str) -> List[str]:
        """
        Get all scalar fields for a given type.
        
        Args:
            type_name: Type name to get scalar fields for
            
        Returns:
            List[str]: List of scalar field names
        """
        scalar_fields = []
        
        if type_name not in self.types:
            return scalar_fields
            
        for field in self.types[type_name].get("fields", []):
            field_type_name = self.get_field_type_name(field.get("type", {}))
            
            if field_type_name in ("String", "Int", "Float", "Boolean", "ID"):
                scalar_fields.append(field["name"])
                
        return scalar_fields
    
    def get_object_fields(self, type_name: str) -> List[Dict]:
        """
        Get all fields that return object types for a given type.
        
        Args:
            type_name: Type name to get object fields for
            
        Returns:
            List[Dict]: List of object field information
        """
        object_fields = []
        
        if type_name not in self.types:
            return object_fields
            
        for field in self.types[type_name].get("fields", []):
            field_type_name = self.get_field_type_name(field.get("type", {}))
            
            if field_type_name in self.types:
                object_fields.append({
                    "name": field["name"],
                    "type": field_type_name
                })
                
        return object_fields
    
    def get_string_input_fields(self, is_mutation: bool = False) -> Dict[str, List[str]]:
        """
        Get all fields that accept string inputs.
        
        Args:
            is_mutation: Whether to check mutation fields (True) or query fields (False)
            
        Returns:
            Dict[str, List[str]]: Dictionary mapping field names to argument names
        """
        string_inputs = {}
        fields_dict = self.mutation_fields if is_mutation else self.query_fields
        
        for field_name, field_info in fields_dict.items():
            string_args = []
            
            for arg in field_info.get("args", []):
                arg_type_name = self.get_field_type_name(arg.get("type", {}))
                
                if arg_type_name in ("String", "ID"):
                    string_args.append(arg["name"])
                    
            if string_args:
                string_inputs[field_name] = string_args
                
        return string_inputs