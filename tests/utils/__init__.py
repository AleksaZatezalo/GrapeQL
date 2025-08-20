"""
Test utilities package for GrapeQL testing

This package provides helper functions, mock data generators, schema builders,
and other testing utilities to support comprehensive GraphQL security testing.
"""

from .test_helpers import (
    # Mock classes
    MockGraphQLResponse,
    GraphQLTestCase,
    PerformanceTimer,
    # Helper functions
    create_mock_session,
    create_mock_client,
    simulate_network_delay,
    # Query generators
    generate_deep_query,
    generate_alias_query,
    generate_circular_query,
    # Injection payloads
    create_injection_payloads,
    # Query analysis
    validate_graphql_query,
    extract_query_fields,
    calculate_query_depth,
    measure_query_complexity,
    # Test data
    create_test_findings,
    create_test_report_data,
    # Constants
    TEST_ENDPOINTS,
    INVALID_ENDPOINTS,
    COMMON_GRAPHQL_PATHS,
)

from .test_schemas import (
    # Schema builders
    SchemaBuilder,
    TypeBuilder,
    FieldBuilder,
    # Pre-built schemas
    VulnerableSchemaGenerator,
    SecureSchemaGenerator,
    # Engine-specific schemas
    ApolloSchemaPatterns,
    HasuraSchemaPatterns,
    GrapheneSchemaPatterns,
    YogaSchemaPatterns,
    # Schema utilities
    add_circular_references,
    add_deep_nesting,
    add_sensitive_fields,
    remove_introspection,
    # Test schema instances
    BASIC_VULNERABLE_SCHEMA,
    BASIC_SECURE_SCHEMA,
    COMPLEX_SCHEMA_WITH_CYCLES,
    MINIMAL_SCHEMA,
    FEDERATION_SCHEMA,
    RELAY_SCHEMA,
)

# Version info
__version__ = "1.0.0"
__author__ = "GrapeQL Testing Suite"


# Utility functions for common test operations
def create_test_environment():
    """Create a complete test environment with all necessary components."""
    return {
        "client": create_mock_client(),
        "session": create_mock_session(),
        "timer": PerformanceTimer(),
        "payloads": create_injection_payloads(),
    }


def get_all_test_schemas():
    """Get all available test schemas for comprehensive testing."""
    return {
        "basic_vulnerable": BASIC_VULNERABLE_SCHEMA,
        "basic_secure": BASIC_SECURE_SCHEMA,
        "complex_cycles": COMPLEX_SCHEMA_WITH_CYCLES,
        "minimal": MINIMAL_SCHEMA,
        "federation": FEDERATION_SCHEMA,
        "relay": RELAY_SCHEMA,
    }


# Export all public components
__all__ = [
    # Mock classes
    "MockGraphQLResponse",
    "GraphQLTestCase",
    "PerformanceTimer",
    # Helper functions
    "create_mock_session",
    "create_mock_client",
    "simulate_network_delay",
    "create_test_environment",
    # Query generators
    "generate_deep_query",
    "generate_alias_query",
    "generate_circular_query",
    # Injection payloads
    "create_injection_payloads",
    # Query analysis
    "validate_graphql_query",
    "extract_query_fields",
    "calculate_query_depth",
    "measure_query_complexity",
    # Test data
    "create_test_findings",
    "create_test_report_data",
    # Schema builders
    "SchemaBuilder",
    "TypeBuilder",
    "FieldBuilder",
    # Schema generators
    "VulnerableSchemaGenerator",
    "SecureSchemaGenerator",
    # Engine patterns
    "ApolloSchemaPatterns",
    "HasuraSchemaPatterns",
    "GrapheneSchemaPatterns",
    "YogaSchemaPatterns",
    # Schema utilities
    "add_circular_references",
    "add_deep_nesting",
    "add_sensitive_fields",
    "remove_introspection",
    "get_all_test_schemas",
    # Pre-built schemas
    "BASIC_VULNERABLE_SCHEMA",
    "BASIC_SECURE_SCHEMA",
    "COMPLEX_SCHEMA_WITH_CYCLES",
    "MINIMAL_SCHEMA",
    "FEDERATION_SCHEMA",
    "RELAY_SCHEMA",
    # Constants
    "TEST_ENDPOINTS",
    "INVALID_ENDPOINTS",
    "COMMON_GRAPHQL_PATHS",
]


# test/utils/test_schemas.py
"""
GraphQL test schemas and schema building utilities

This module provides a comprehensive collection of GraphQL schemas for testing
various security scenarios, engine types, and vulnerability patterns.
"""

from typing import Dict, List, Any, Optional, Union
import copy


class TypeBuilder:
    """Builder for GraphQL type definitions."""

    def __init__(self, name: str, kind: str = "OBJECT"):
        self.type_def = {
            "name": name,
            "kind": kind,
            "description": None,
            "fields": [],
            "interfaces": [],
            "possibleTypes": None,
            "enumValues": None,
            "inputFields": None,
        }

    def description(self, desc: str) -> "TypeBuilder":
        """Add description to the type."""
        self.type_def["description"] = desc
        return self

    def field(
        self,
        name: str,
        type_name: str,
        description: str = None,
        args: List[Dict] = None,
        deprecated: bool = False,
    ) -> "TypeBuilder":
        """Add a field to the type."""
        field_def = {
            "name": name,
            "description": description,
            "type": {"kind": "SCALAR", "name": type_name},
            "args": args or [],
            "isDeprecated": deprecated,
            "deprecationReason": None,
        }
        self.type_def["fields"].append(field_def)
        return self

    def object_field(
        self,
        name: str,
        type_name: str,
        description: str = None,
        args: List[Dict] = None,
        is_list: bool = False,
    ) -> "TypeBuilder":
        """Add an object field to the type."""
        if is_list:
            field_type = {
                "kind": "LIST",
                "name": None,
                "ofType": {"kind": "OBJECT", "name": type_name},
            }
        else:
            field_type = {"kind": "OBJECT", "name": type_name}

        field_def = {
            "name": name,
            "description": description,
            "type": field_type,
            "args": args or [],
            "isDeprecated": False,
            "deprecationReason": None,
        }
        self.type_def["fields"].append(field_def)
        return self

    def build(self) -> Dict:
        """Build and return the type definition."""
        return copy.deepcopy(self.type_def)


class FieldBuilder:
    """Builder for GraphQL field definitions."""

    def __init__(self, name: str, type_name: str):
        self.field_def = {
            "name": name,
            "description": None,
            "type": {"kind": "SCALAR", "name": type_name},
            "args": [],
            "isDeprecated": False,
            "deprecationReason": None,
        }

    def description(self, desc: str) -> "FieldBuilder":
        """Add description to the field."""
        self.field_def["description"] = desc
        return self

    def argument(
        self,
        name: str,
        type_name: str,
        description: str = None,
        default_value: Any = None,
    ) -> "FieldBuilder":
        """Add an argument to the field."""
        arg_def = {
            "name": name,
            "description": description,
            "type": {"kind": "SCALAR", "name": type_name},
            "defaultValue": default_value,
        }
        self.field_def["args"].append(arg_def)
        return self

    def deprecated(self, reason: str = "This field is deprecated") -> "FieldBuilder":
        """Mark field as deprecated."""
        self.field_def["isDeprecated"] = True
        self.field_def["deprecationReason"] = reason
        return self

    def build(self) -> Dict:
        """Build and return the field definition."""
        return copy.deepcopy(self.field_def)


class SchemaBuilder:
    """Builder for complete GraphQL schemas."""

    def __init__(self):
        self.schema = {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"},
                    "subscriptionType": None,
                    "types": [],
                    "directives": [],
                }
            }
        }

    def add_type(self, type_def: Dict) -> "SchemaBuilder":
        """Add a type definition to the schema."""
        self.schema["data"]["__schema"]["types"].append(type_def)
        return self

    def add_mutation_type(self, name: str = "Mutation") -> "SchemaBuilder":
        """Set the mutation type."""
        self.schema["data"]["__schema"]["mutationType"] = {"name": name}
        return self

    def add_subscription_type(self, name: str = "Subscription") -> "SchemaBuilder":
        """Set the subscription type."""
        self.schema["data"]["__schema"]["subscriptionType"] = {"name": name}
        return self

    def build(self) -> Dict:
        """Build and return the complete schema."""
        return copy.deepcopy(self.schema)


class VulnerableSchemaGenerator:
    """Generator for schemas with various security vulnerabilities."""

    @staticmethod
    def with_circular_references() -> Dict:
        """Generate a schema with circular reference vulnerabilities."""
        builder = SchemaBuilder()

        # User type with circular friends reference
        user_type = (
            TypeBuilder("User")
            .description("User with circular friend references")
            .field("id", "ID", "User identifier")
            .field("username", "String", "Username")
            .field("email", "String", "Email address")
            .object_field("friends", "User", "User's friends", is_list=True)
            .object_field("posts", "Post", "User's posts", is_list=True)
            .build()
        )

        # Post type with circular references through comments
        post_type = (
            TypeBuilder("Post")
            .description("Post with circular comment references")
            .field("id", "ID", "Post identifier")
            .field("title", "String", "Post title")
            .field("content", "String", "Post content")
            .object_field("author", "User", "Post author")
            .object_field("comments", "Comment", "Post comments", is_list=True)
            .build()
        )

        # Comment type with deep nesting potential
        comment_type = (
            TypeBuilder("Comment")
            .description("Comment with deep nesting potential")
            .field("id", "ID", "Comment identifier")
            .field("content", "String", "Comment content")
            .object_field("author", "User", "Comment author")
            .object_field("post", "Post", "Parent post")
            .object_field("replies", "Comment", "Comment replies", is_list=True)
            .object_field("parent", "Comment", "Parent comment")
            .build()
        )

        # Query type
        query_type = (
            TypeBuilder("Query")
            .description("Root query type")
            .object_field("user", "User", "Get user by ID")
            .object_field("users", "User", "Get all users", is_list=True)
            .object_field("post", "Post", "Get post by ID")
            .object_field("posts", "Post", "Get all posts", is_list=True)
            .build()
        )

        return (
            builder.add_type(query_type)
            .add_type(user_type)
            .add_type(post_type)
            .add_type(comment_type)
            .build()
        )

    @staticmethod
    def with_sensitive_fields() -> Dict:
        """Generate a schema with sensitive field exposure."""
        builder = SchemaBuilder()

        # User type with sensitive fields
        user_type = (
            TypeBuilder("User")
            .description("User with sensitive fields")
            .field("id", "ID", "User identifier")
            .field("username", "String", "Username")
            .field("email", "String", "Email address")
            .field("password", "String", "User password (SENSITIVE)")
            .field("ssn", "String", "Social Security Number (SENSITIVE)")
            .field("creditCard", "String", "Credit card number (SENSITIVE)")
            .field("apiKey", "String", "API key (SENSITIVE)")
            .field("internalId", "String", "Internal system ID")
            .field("debugInfo", "String", "Debug information")
            .build()
        )

        # Admin type with privileged operations
        admin_type = (
            TypeBuilder("Admin")
            .description("Admin user with privileged access")
            .field("id", "ID", "Admin identifier")
            .field("username", "String", "Admin username")
            .field("permissions", "String", "Admin permissions", is_list=True)
            .field("systemAccess", "Boolean", "System access flag")
            .object_field("users", "User", "All users (admin only)", is_list=True)
            .build()
        )

        # Query type
        query_type = (
            TypeBuilder("Query")
            .description("Root query with sensitive operations")
            .object_field("user", "User", "Get user by ID")
            .object_field("users", "User", "Get all users", is_list=True)
            .object_field("admin", "Admin", "Get admin user")
            .field("systemInfo", "String", "System information")
            .field("databaseInfo", "String", "Database connection info")
            .build()
        )

        return (
            builder.add_type(query_type)
            .add_type(user_type)
            .add_type(admin_type)
            .build()
        )

    @staticmethod
    def with_injection_points() -> Dict:
        """Generate a schema with potential injection points."""
        builder = SchemaBuilder()

        # Search type with injection-prone fields
        search_type = (
            TypeBuilder("Search")
            .description("Search functionality with injection risks")
            .field("query", "String", "Search query")
            .field("filter", "String", "Search filter")
            .field("sort", "String", "Sort criteria")
            .field("limit", "Int", "Result limit")
            .build()
        )

        # Query type with injection-prone arguments
        query_type = (
            TypeBuilder("Query").description("Root query with injection points").build()
        )

        # Manually add fields with arguments for injection testing
        query_type["fields"] = [
            {
                "name": "searchUsers",
                "description": "Search users with custom query",
                "type": {"kind": "LIST", "ofType": {"kind": "OBJECT", "name": "User"}},
                "args": [
                    {
                        "name": "query",
                        "description": "SQL-like search query",
                        "type": {"kind": "SCALAR", "name": "String"},
                    },
                    {
                        "name": "filter",
                        "description": "Custom filter expression",
                        "type": {"kind": "SCALAR", "name": "String"},
                    },
                ],
                "isDeprecated": False,
            },
            {
                "name": "executeCommand",
                "description": "Execute system command",
                "type": {"kind": "SCALAR", "name": "String"},
                "args": [
                    {
                        "name": "command",
                        "description": "Command to execute",
                        "type": {"kind": "SCALAR", "name": "String"},
                    }
                ],
                "isDeprecated": False,
            },
            {
                "name": "queryDatabase",
                "description": "Direct database query",
                "type": {"kind": "SCALAR", "name": "String"},
                "args": [
                    {
                        "name": "sql",
                        "description": "SQL query to execute",
                        "type": {"kind": "SCALAR", "name": "String"},
                    }
                ],
                "isDeprecated": False,
            },
        ]

        user_type = (
            TypeBuilder("User")
            .field("id", "ID", "User ID")
            .field("username", "String", "Username")
            .build()
        )

        return (
            builder.add_type(query_type)
            .add_type(user_type)
            .add_type(search_type)
            .build()
        )


class SecureSchemaGenerator:
    """Generator for secure, well-designed schemas."""

    @staticmethod
    def basic_secure() -> Dict:
        """Generate a basic secure schema."""
        builder = SchemaBuilder()

        # User type with safe fields only
        user_type = (
            TypeBuilder("User")
            .description("Secure user type")
            .field("id", "ID", "User identifier")
            .field("username", "String", "Public username")
            .field("displayName", "String", "Display name")
            .field("createdAt", "String", "Creation timestamp")
            .build()
        )

        # Post type with safe references
        post_type = (
            TypeBuilder("Post")
            .description("Secure post type")
            .field("id", "ID", "Post identifier")
            .field("title", "String", "Post title")
            .field("excerpt", "String", "Post excerpt")
            .field("publishedAt", "String", "Publication timestamp")
            .object_field("author", "User", "Post author")
            .build()
        )

        # Query type with limited depth
        query_type = (
            TypeBuilder("Query")
            .description("Secure root query")
            .object_field("user", "User", "Get user by ID")
            .object_field("posts", "Post", "Get published posts", is_list=True)
            .build()
        )

        return (
            builder.add_type(query_type).add_type(user_type).add_type(post_type).build()
        )

    @staticmethod
    def with_pagination() -> Dict:
        """Generate a secure schema with proper pagination."""
        builder = SchemaBuilder()

        # Connection types for Relay-style pagination
        page_info_type = (
            TypeBuilder("PageInfo")
            .description("Pagination information")
            .field("hasNextPage", "Boolean", "Has next page")
            .field("hasPreviousPage", "Boolean", "Has previous page")
            .field("startCursor", "String", "Start cursor")
            .field("endCursor", "String", "End cursor")
            .build()
        )

        user_edge_type = (
            TypeBuilder("UserEdge")
            .description("User edge")
            .field("cursor", "String", "Cursor")
            .object_field("node", "User", "User node")
            .build()
        )

        user_connection_type = (
            TypeBuilder("UserConnection")
            .description("User connection")
            .object_field("edges", "UserEdge", "User edges", is_list=True)
            .object_field("pageInfo", "PageInfo", "Page information")
            .field("totalCount", "Int", "Total count")
            .build()
        )

        user_type = (
            TypeBuilder("User")
            .field("id", "ID", "User ID")
            .field("username", "String", "Username")
            .build()
        )

        query_type = (
            TypeBuilder("Query")
            .description("Paginated query")
            .object_field("users", "UserConnection", "Get users with pagination")
            .build()
        )

        return (
            builder.add_type(query_type)
            .add_type(user_type)
            .add_type(page_info_type)
            .add_type(user_edge_type)
            .add_type(user_connection_type)
            .build()
        )


class ApolloSchemaPatterns:
    """Apollo Server specific schema patterns."""

    @staticmethod
    def with_federation() -> Dict:
        """Generate schema with Apollo Federation patterns."""
        builder = SchemaBuilder()

        # Federation service types
        service_type = (
            TypeBuilder("_Service")
            .description("Apollo Federation service")
            .field("sdl", "String", "Service SDL")
            .build()
        )

        entity_type = (
            TypeBuilder("_Entity")
            .description("Apollo Federation entity")
            .field("__typename", "String", "Entity typename")
            .build()
        )

        # User type with federation directives
        user_type = (
            TypeBuilder("User")
            .description("Federated user type")
            .field("id", "ID", "User ID")
            .field("username", "String", "Username")
            .field("email", "String", "Email")
            .build()
        )

        query_type = (
            TypeBuilder("Query")
            .description("Federated query")
            .object_field("_service", "_Service", "Federation service info")
            .object_field("_entities", "_Entity", "Federation entities", is_list=True)
            .object_field("user", "User", "Get user")
            .build()
        )

        return (
            builder.add_type(query_type)
            .add_type(user_type)
            .add_type(service_type)
            .add_type(entity_type)
            .build()
        )

    @staticmethod
    def with_subscriptions() -> Dict:
        """Generate schema with Apollo subscription patterns."""
        builder = SchemaBuilder()

        user_type = (
            TypeBuilder("User")
            .field("id", "ID", "User ID")
            .field("username", "String", "Username")
            .build()
        )

        message_type = (
            TypeBuilder("Message")
            .field("id", "ID", "Message ID")
            .field("content", "String", "Message content")
            .object_field("user", "User", "Message author")
            .build()
        )

        query_type = (
            TypeBuilder("Query")
            .object_field("messages", "Message", "Get messages", is_list=True)
            .build()
        )

        subscription_type = (
            TypeBuilder("Subscription")
            .description("Real-time subscriptions")
            .object_field("messageAdded", "Message", "New message added")
            .object_field("userOnline", "User", "User came online")
            .build()
        )

        return (
            builder.add_type(query_type)
            .add_type(user_type)
            .add_type(message_type)
            .add_type(subscription_type)
            .add_subscription_type("Subscription")
            .build()
        )


class HasuraSchemaPatterns:
    """Hasura specific schema patterns."""

    @staticmethod
    def auto_generated() -> Dict:
        """Generate schema with Hasura auto-generated patterns."""
        builder = SchemaBuilder()

        # Hasura metadata types
        metadata_type = (
            TypeBuilder("hasura_metadata")
            .description("Hasura metadata")
            .field("version", "String", "Hasura version")
            .field("sources", "String", "Data sources")
            .build()
        )

        # Auto-generated query root
        query_root_type = (
            TypeBuilder("query_root")
            .description("Hasura query root")
            .object_field("users", "users", "Auto-generated users query", is_list=True)
            .object_field("users_by_pk", "users", "Get user by primary key")
            .build()
        )

        # Auto-generated mutation root
        mutation_root_type = (
            TypeBuilder("mutation_root")
            .description("Hasura mutation root")
            .object_field("insert_users", "users_mutation_response", "Insert users")
            .object_field("update_users", "users_mutation_response", "Update users")
            .object_field("delete_users", "users_mutation_response", "Delete users")
            .build()
        )

        # Table types
        users_type = (
            TypeBuilder("users")
            .description("Auto-generated users table")
            .field("id", "uuid", "Primary key")
            .field("name", "String", "User name")
            .field("email", "String", "User email")
            .field("created_at", "timestamptz", "Creation timestamp")
            .build()
        )

        return (
            builder.add_type(query_root_type)
            .add_type(mutation_root_type)
            .add_type(users_type)
            .add_type(metadata_type)
            .add_mutation_type("mutation_root")
            .build()
        )


class GrapheneSchemaPatterns:
    """Graphene (Python) specific schema patterns."""

    @staticmethod
    def django_integration() -> Dict:
        """Generate schema with Graphene-Django patterns."""
        builder = SchemaBuilder()

        # Django model-based types
        user_type = (
            TypeBuilder("UserType")
            .description("Django User model")
            .field("id", "ID", "Django model ID")
            .field("username", "String", "Django username field")
            .field("email", "String", "Django email field")
            .field("isActive", "Boolean", "Django is_active field")
            .field("dateJoined", "DateTime", "Django date_joined field")
            .build()
        )

        # Relay-style node interface
        node_interface = (
            TypeBuilder("Node", kind="INTERFACE")
            .description("Relay Node interface")
            .field("id", "ID", "Global ID")
            .build()
        )

        query_type = (
            TypeBuilder("Query")
            .description("Graphene query")
            .object_field("allUsers", "UserType", "All users", is_list=True)
            .object_field("user", "UserType", "Single user")
            .object_field("node", "Node", "Relay node")
            .build()
        )

        return (
            builder.add_type(query_type)
            .add_type(user_type)
            .add_type(node_interface)
            .build()
        )


class YogaSchemaPatterns:
    """GraphQL Yoga specific schema patterns."""

    @staticmethod
    def with_middleware() -> Dict:
        """Generate schema typical of GraphQL Yoga setup."""
        builder = SchemaBuilder()

        user_type = (
            TypeBuilder("User")
            .field("id", "ID", "User ID")
            .field("name", "String", "User name")
            .field("email", "String", "User email")
            .build()
        )

        auth_payload_type = (
            TypeBuilder("AuthPayload")
            .description("Authentication payload")
            .field("token", "String", "JWT token")
            .object_field("user", "User", "Authenticated user")
            .build()
        )

        query_type = (
            TypeBuilder("Query")
            .object_field("me", "User", "Current user")
            .object_field("users", "User", "All users", is_list=True)
            .build()
        )

        mutation_type = (
            TypeBuilder("Mutation")
            .description("Yoga mutations")
            .object_field("signup", "AuthPayload", "User signup")
            .object_field("login", "AuthPayload", "User login")
            .build()
        )

        return (
            builder.add_type(query_type)
            .add_type(mutation_type)
            .add_type(user_type)
            .add_type(auth_payload_type)
            .add_mutation_type("Mutation")
            .build()
        )


# Schema modification utilities
def add_circular_references(schema: Dict, type_name: str, field_name: str) -> Dict:
    """Add circular references to an existing schema."""
    modified_schema = copy.deepcopy(schema)

    # Find the type and add self-reference
    for type_def in modified_schema["data"]["__schema"]["types"]:
        if type_def["name"] == type_name:
            circular_field = {
                "name": field_name,
                "description": f"Circular reference to {type_name}",
                "type": {
                    "kind": "LIST",
                    "ofType": {"kind": "OBJECT", "name": type_name},
                },
                "args": [],
                "isDeprecated": False,
            }
            type_def["fields"].append(circular_field)
            break

    return modified_schema


def add_deep_nesting(schema: Dict, max_depth: int = 10) -> Dict:
    """Add deep nesting potential to schema."""
    modified_schema = copy.deepcopy(schema)

    # Create nested structure
    for i in range(max_depth):
        nested_type = (
            TypeBuilder(f"Level{i}")
            .field("id", "ID", f"Level {i} ID")
            .field("value", "String", f"Level {i} value")
            .build()
        )

        if i < max_depth - 1:
            nested_type["fields"].append(
                {
                    "name": "child",
                    "type": {"kind": "OBJECT", "name": f"Level{i+1}"},
                    "args": [],
                    "isDeprecated": False,
                }
            )

        modified_schema["data"]["__schema"]["types"].append(nested_type)

    return modified_schema


def add_sensitive_fields(schema: Dict, type_name: str) -> Dict:
    """Add sensitive fields to a specific type."""
    modified_schema = copy.deepcopy(schema)

    sensitive_fields = [
        {
            "name": "password",
            "type": {"name": "String"},
            "description": "Password hash",
        },
        {"name": "apiKey", "type": {"name": "String"}, "description": "API key"},
        {
            "name": "secretToken",
            "type": {"name": "String"},
            "description": "Secret token",
        },
        {
            "name": "internalId",
            "type": {"name": "String"},
            "description": "Internal ID",
        },
        {
            "name": "debugInfo",
            "type": {"name": "String"},
            "description": "Debug information",
        },
    ]

    for type_def in modified_schema["data"]["__schema"]["types"]:
        if type_def["name"] == type_name:
            for field in sensitive_fields:
                field_def = {
                    "name": field["name"],
                    "description": field["description"],
                    "type": field["type"],
                    "args": [],
                    "isDeprecated": False,
                }
                type_def["fields"].append(field_def)
            break

    return modified_schema
