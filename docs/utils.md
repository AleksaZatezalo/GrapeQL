# Utils Module Documentation

The `utils.py` module provides utility classes and helper functions used throughout the GrapeQL library. The primary component is the `GrapePrinter` class, which handles formatted output and logging for the GraphQL client operations.

## Table of Contents

- [Overview](#overview)
- [GrapePrinter Class](#grapeprinter-class)
- [Status Types](#status-types)
- [Color Schemes](#color-schemes)
- [Usage Examples](#usage-examples)
- [Configuration](#configuration)
- [Integration](#integration)

## Overview

The utils module is designed to provide consistent, colored output for the GrapeQL library, making it easier to track operations, debug issues, and understand the flow of GraphQL requests and responses.

### Key Features

- ✅ **Colored Output** - Status-based color coding for better visibility
- ✅ **Consistent Formatting** - Standardized message format across the library
- ✅ **Silent Mode** - Option to disable output for production environments
- ✅ **Extensible** - Easy to add new status types and colors
- ✅ **Thread-Safe** - Safe for concurrent operations

## GrapePrinter Class

The `GrapePrinter` class is the main utility for formatted output in GrapeQL.

```python
class GrapePrinter:
    """
    Utility class for consistent, colored printing throughout GrapeQL.
    Provides status-based color coding and formatting for better UX.
    """
```

### Initialization

```python
from grapeql.utils import GrapePrinter

# Create printer instance
printer = GrapePrinter()

# Create with custom configuration
printer = GrapePrinter(silent=True)  # Disable output
```

### Core Method

#### `print_msg(message: str, status: str = "info") -> None`

Print a formatted message with color coding based on status.

```python
printer.print_msg("Connection established", status="success")
printer.print_msg("Warning: Rate limit approaching", status="warning")
printer.print_msg("Request failed", status="error")
printer.print_msg("Processing request...", status="info")
```

**Parameters:**
- `message` (str): The message to display
- `status` (str): Status type determining color and formatting

## Status Types

The `GrapePrinter` supports various status types, each with distinct visual styling:

### Standard Status Types

| Status | Color | Use Case | Example |
|--------|-------|----------|---------|
| `success` | 🟢 Green | Successful operations | "GraphQL schema loaded" |
| `error` | 🔴 Red | Errors and failures | "Connection timeout" |
| `warning` | 🟡 Yellow | Warnings and cautions | "Deprecated field used" |
| `info` | 🔵 Blue | General information | "Sending GraphQL query" |
| `debug` | 🟣 Purple | Debug information | "Request payload: {...}" |
| `failed` | 🔴 Red (alternative) | Failed operations | "Authentication failed" |

### Usage Examples

```python
from grapeql.utils import GrapePrinter

printer = GrapePrinter()

# Success messages
printer.print_msg("✅ Connected to GraphQL endpoint", "success")
printer.print_msg("✅ Schema introspection completed", "success")
printer.print_msg("✅ Query executed successfully", "success")

# Error messages
printer.print_msg("❌ Network connection failed", "error")
printer.print_msg("❌ Invalid GraphQL query syntax", "error")
printer.print_msg("❌ Authentication token expired", "error")

# Warning messages
printer.print_msg("⚠️  Using deprecated GraphQL field", "warning")
printer.print_msg("⚠️  Rate limit at 80% capacity", "warning")
printer.print_msg("⚠️  Large response size detected", "warning")

# Info messages
printer.print_msg("ℹ️  Connecting to https://api.example.com/graphql", "info")
printer.print_msg("ℹ️  Loading cached schema", "info")
printer.print_msg("ℹ️  Retrying request (attempt 2/3)", "info")

# Debug messages
printer.print_msg("🔍 Request headers: {'Authorization': 'Bearer ***'}", "debug")
printer.print_msg("🔍 Response time: 245ms", "debug")
printer.print_msg("🔍 Cache hit for query fingerprint", "debug")
```

## Color Schemes

### Terminal Color Support

The `GrapePrinter` automatically detects terminal capabilities and applies appropriate styling:

#### ANSI Color Codes
```python
# Internal color mapping (implementation detail)
COLORS = {
    'success': '\033[92m',  # Bright Green
    'error': '\033[91m',    # Bright Red
    'warning': '\033[93m',  # Bright Yellow
    'info': '\033[94m',     # Bright Blue
    'debug': '\033[95m',    # Bright Magenta
    'failed': '\033[91m',   # Bright Red
    'reset': '\033[0m'      # Reset to default
}
```

#### Fallback for Non-Color Terminals
When color support is not available, the printer falls back to prefix-based formatting:

```
[SUCCESS] GraphQL schema loaded
[ERROR] Connection timeout
[WARNING] Deprecated field used
[INFO] Processing request
[DEBUG] Request payload: {...}
```

## Configuration

### Silent Mode

Disable all output for production environments:

```python
# Silent printer - no output
silent_printer = GrapePrinter(silent=True)
silent_printer.print_msg("This won't be displayed", "info")

# Toggle silence at runtime
printer = GrapePrinter()
printer.silent = True  # Disable output
printer.silent = False # Re-enable output
```

### Custom Formatting

Extend the `GrapePrinter` for custom formatting:

```python
class CustomGrapePrinter(GrapePrinter):
    def print_msg(self, message: str, status: str = "info") -> None:
        # Add timestamp
        import datetime
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}"
        
        # Call parent method
        super().print_msg(formatted_message, status)

# Usage
custom_printer = CustomGrapePrinter()
custom_printer.print_msg("Operation completed", "success")
# Output: [14:30:45] Operation completed
```

## Integration

### GraphQLClient Integration

The `GrapePrinter` is automatically integrated into the `GraphQLClient`:

```python
from grapeql.client import GraphQLClient

client = GraphQLClient()
# The client.printer is automatically configured

# All client operations use the printer
client.set_endpoint("https://api.example.com/graphql")
# Output: "Endpoint set: https://api.example.com/graphql"

await client.introspection_query()
# Output: "Introspection successful" or "Introspection failed"
```

### Custom Printer Integration

Replace the default printer with a custom one:

```python
from grapeql.client import GraphQLClient
from grapeql.utils import GrapePrinter

# Create client with silent printer for production
client = GraphQLClient()
client.printer = GrapePrinter(silent=True)

# Or with custom printer
class ProductionPrinter(GrapePrinter):
    def print_msg(self, message: str, status: str = "info") -> None:
        if status in ["error", "warning"]:
            # Only log errors and warnings in production
            import logging
            logger = logging.getLogger("grapeql")
            if status == "error":
                logger.error(message)
            else:
                logger.warning(message)

client.printer = ProductionPrinter()
```

## Advanced Usage

### Logging Integration

Integrate with Python's logging system:

```python
import logging
from grapeql.utils import GrapePrinter

class LoggingGrapePrinter(GrapePrinter):
    def __init__(self, logger_name="grapeql", silent=False):
        super().__init__(silent=silent)
        self.logger = logging.getLogger(logger_name)
    
    def print_msg(self, message: str, status: str = "info") -> None:
        # Print to console
        if not self.silent:
            super().print_msg(message, status)
        
        # Also log to file
        if status == "error":
            self.logger.error(message)
        elif status == "warning":
            self.logger.warning(message)
        elif status == "success":
            self.logger.info(f"SUCCESS: {message}")
        else:
            self.logger.debug(message)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('grapeql.log'),
        logging.StreamHandler()
    ]
)

# Use logging printer
printer = LoggingGrapePrinter()
```

### Metrics Collection

Extend for metrics collection:

```python
from collections import defaultdict
from grapeql.utils import GrapePrinter

class MetricsGrapePrinter(GrapePrinter):
    def __init__(self, silent=False):
        super().__init__(silent=silent)
        self.metrics = defaultdict(int)
    
    def print_msg(self, message: str, status: str = "info") -> None:
        # Count status occurrences
        self.metrics[status] += 1
        
        # Print as normal
        super().print_msg(message, status)
    
    def get_metrics(self) -> dict:
        """Get metrics summary."""
        return dict(self.metrics)
    
    def reset_metrics(self) -> None:
        """Reset metrics counters."""
        self.metrics.clear()

# Usage
metrics_printer = MetricsGrapePrinter()

# After operations
print(metrics_printer.get_metrics())
# Output: {'success': 5, 'error': 2, 'warning': 1, 'info': 10}
```

### Context-Aware Printing

Add context information to messages:

```python
import threading
from grapeql.utils import GrapePrinter

class ContextGrapePrinter(GrapePrinter):
    def __init__(self, silent=False):
        super().__init__(silent=silent)
        self.context = threading.local()
    
    def set_context(self, **kwargs):
        """Set context information for this thread."""
        for key, value in kwargs.items():
            setattr(self.context, key, value)
    
    def print_msg(self, message: str, status: str = "info") -> None:
        # Add context to message
        context_parts = []
        
        if hasattr(self.context, 'request_id'):
            context_parts.append(f"req:{self.context.request_id}")
        
        if hasattr(self.context, 'operation'):
            context_parts.append(f"op:{self.context.operation}")
        
        if context_parts:
            context_str = f"[{','.join(context_parts)}] "
            message = context_str + message
        
        super().print_msg(message, status)

# Usage
context_printer = ContextGrapePrinter()
context_printer.set_context(request_id="req-123", operation="user_query")
context_printer.print_msg("Executing GraphQL query", "info")
# Output: [req:req-123,op:user_query] Executing GraphQL query
```

## Testing and Mocking

### Mock Printer for Tests

Create a mock printer for unit tests:

```python
from unittest.mock import Mock
from grapeql.utils import GrapePrinter

class MockGrapePrinter(GrapePrinter):
    def __init__(self):
        super().__init__(silent=True)
        self.messages = []
    
    def print_msg(self, message: str, status: str = "info") -> None:
        self.messages.append((message, status))
    
    def get_messages(self, status=None):
        """Get messages, optionally filtered by status."""
        if status:
            return [msg for msg, s in self.messages if s == status]
        return [msg for msg, s in self.messages]
    
    def has_message(self, message: str, status: str = None) -> bool:
        """Check if a specific message was printed."""
        for msg, s in self.messages:
            if message in msg and (status is None or s == status):
                return True
        return False
    
    def clear(self):
        """Clear message history."""
        self.messages.clear()

# Test usage
def test_graphql_client():
    from grapeql.client import GraphQLClient
    
    client = GraphQLClient()
    mock_printer = MockGrapePrinter()
    client.printer = mock_printer
    
    # Perform operations
    client.set_endpoint("https://api.example.com/graphql")
    
    # Verify messages
    assert mock_printer.has_message("Endpoint set", "success")
    assert len(mock_printer.get_messages("success")) == 1
```

### Capture Output for Analysis

Capture printer output for debugging:

```python
import io
import sys
from contextlib import redirect_stdout
from grapeql.utils import GrapePrinter

class CapturingGrapePrinter(GrapePrinter):
    def __init__(self, silent=False):
        super().__init__(silent=silent)
        self.captured_output = io.StringIO()
    
    def print_msg(self, message: str, status: str = "info") -> None:
        # Capture output
        with redirect_stdout(self.captured_output):
            super().print_msg(message, status)
    
    def get_output(self) -> str:
        """Get captured output."""
        return self.captured_output.getvalue()
    
    def clear_output(self):
        """Clear captured output."""
        self.captured_output = io.StringIO()

# Usage
capturing_printer = CapturingGrapePrinter()
capturing_printer.print_msg("Test message", "info")
output = capturing_printer.get_output()
print(f"Captured: {output}")
```

## Error Handling

### Robust Error Handling

Handle printing errors gracefully:

```python
from grapeql.utils import GrapePrinter

class RobustGrapePrinter(GrapePrinter):
    def print_msg(self, message: str, status: str = "info") -> None:
        try:
            super().print_msg(message, status)
        except Exception as e:
            # Fallback to basic print if styling fails
            try:
                print(f"[{status.upper()}] {message}")
            except Exception:
                # Last resort - silent failure
                pass

# Handle encoding issues
class SafeGrapePrinter(GrapePrinter):
    def print_msg(self, message: str, status: str = "info") -> None:
        # Ensure message is safely encodable
        try:
            safe_message = message.encode('utf-8', errors='replace').decode('utf-8')
            super().print_msg(safe_message, status)
        except Exception:
            # Fallback for any encoding issues
            super().print_msg(repr(message), status)
```

## Performance Considerations

### Lazy String Formatting

Optimize for performance when output is disabled:

```python
from grapeql.utils import GrapePrinter

class LazyGrapePrinter(GrapePrinter):
    def print_msg(self, message_func, status: str = "info") -> None:
        if self.silent:
            return  # Skip expensive string operations
        
        # Only evaluate message if we're actually printing
        if callable(message_func):
            message = message_func()
        else:
            message = str(message_func)
        
        super().print_msg(message, status)

# Usage
lazy_printer = LazyGrapePrinter()

# Expensive operation only runs if not silent
lazy_printer.print_msg(
    lambda: f"Response data: {expensive_json_formatting(data)}", 
    "debug"
)
```

### Batch Printing

Batch multiple messages for better performance:

```python
from grapeql.utils import GrapePrinter

class BatchGrapePrinter(GrapePrinter):
    def __init__(self, silent=False, batch_size=10):
        super().__init__(silent=silent)
        self.batch_size = batch_size
        self.message_buffer = []
    
    def print_msg(self, message: str, status: str = "info") -> None:
        if self.silent:
            return
        
        self.message_buffer.append((message, status))
        
        if len(self.message_buffer) >= self.batch_size:
            self.flush()
    
    def flush(self):
        """Print all buffered messages."""
        for message, status in self.message_buffer:
            super().print_msg(message, status)
        self.message_buffer.clear()
    
    def __del__(self):
        """Ensure remaining messages are printed."""
        if hasattr(self, 'message_buffer') and self.message_buffer:
            self.flush()

# Usage
batch_printer = BatchGrapePrinter(batch_size=5)
for i in range(12):
    batch_printer.print_msg(f"Message {i}", "info")
# Messages 0-4 printed after 5th message
# Messages 5-9 printed after 10th message
# Messages 10-11 printed when batch_printer is destroyed
```

## Best Practices

### 1. Consistent Status Usage

```python
# ✅ Good - Consistent status types
printer.print_msg("Connected successfully", "success")
printer.print_msg("Connection failed", "error")
printer.print_msg("Slow response detected", "warning")

# ❌ Avoid - Inconsistent or custom status types
printer.print_msg("Connected successfully", "good")  # Non-standard
printer.print_msg("Connection failed", "bad")        # Non-standard
```

### 2. Informative Messages

```python
# ✅ Good - Descriptive and actionable
printer.print_msg("GraphQL endpoint set: https://api.example.com/graphql", "success")
printer.print_msg("Request timeout after 10s - consider increasing timeout", "error")

# ❌ Avoid - Vague or unhelpful
printer.print_msg("Done", "success")
printer.print_msg("Error", "error")
```

### 3. Production Considerations

```python
# Production setup
import os

# Use environment variable to control output
is_production = os.getenv("ENV") == "production"
printer = GrapePrinter(silent=is_production)

# Or use different printer for production
if is_production:
    printer = LoggingGrapePrinter(silent=True)  # Log to file only
else:
    printer = GrapePrinter()  # Console output for development
```

### 4. Integration with GraphQL Client

```python
# Custom client with enhanced printing
from grapeql.client import GraphQLClient
from grapeql.utils import GrapePrinter

class VerboseGraphQLClient(GraphQLClient):
    def __init__(self, verbose=False):
        super().__init__()
        if verbose:
            self.printer = ContextGrapePrinter()
        else:
            self.printer = GrapePrinter(silent=True)

# Usage
client = VerboseGraphQLClient(verbose=True)
client.printer.set_context(session_id="sess-123")
```

## API Reference Summary

### GrapePrinter Class

```python
class GrapePrinter:
    def __init__(self, silent: bool = False):
        """
        Initialize the printer.
        
        Args:
            silent: If True, suppress all output
        """
    
    def print_msg(self, message: str, status: str = "info") -> None:
        """
        Print a formatted message with color coding.
        
        Args:
            message: The message to display
            status: Status type for color coding
        """
```

### Status Types

- `success` - Green, for successful operations
- `error` - Red, for errors and failures  
- `warning` - Yellow, for warnings and cautions
- `info` - Blue, for general information
- `debug` - Purple, for debug information
- `failed` - Red, alternative for failed operations

### Common Patterns

```python
# Standard usage
printer = GrapePrinter()
printer.print_msg("Operation completed", "success")

# Silent mode
printer = GrapePrinter(silent=True)

# Custom printer
class MyPrinter(GrapePrinter):
    def print_msg(self, message: str, status: str = "info") -> None:
        # Custom implementation
        pass
```