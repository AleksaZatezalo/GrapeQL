"""
Date: March 2025
Author: Aleksa Zatezalo
Description: Generates formatted reports containing vulnerabilities found by GrapeQL
"""

import json
import datetime
from typing import Dict, List, Any


def generate_report(filename: str, results: List[Dict]) -> None:
    """
    Generate a report file with findings from GrapeQL tests.
    
    Args:
        filename: Output filename for the report
        results: List of results from security tests
    """
    if not filename:
        return
        
    # Add file extension if not provided
    if not filename.endswith(('.md', '.json', '.txt')):
        filename += '.md'
    
    if filename.endswith('.json'):
        _generate_json_report(filename, results)
    else:
        _generate_markdown_report(filename, results)


def _generate_json_report(filename: str, results: List[Dict]) -> None:
    """Generate a JSON report."""
    with open(filename, 'w') as f:
        json.dump({
            'generated_at': datetime.datetime.now().isoformat(),
            'results': results
        }, f, indent=2)


def _generate_markdown_report(filename: str, results: List[Dict]) -> None:
    """Generate a Markdown report."""
    with open(filename, 'w') as f:
        f.write(f"# GrapeQL Security Report\n\n")
        f.write(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        for entry in results:
            endpoint = entry.get('endpoint', 'Unknown endpoint')
            f.write(f"## Endpoint: {endpoint}\n\n")
            
            # Engine information
            engine_info = entry.get('results', {}).get('engine', {})
            if engine_info:
                f.write("### GraphQL Engine\n\n")
                engine_name = engine_info.get('name', 'Unknown')
                f.write(f"- **Implementation**: {engine_name}\n")
                
                if 'technology' in engine_info:
                    technologies = ', '.join(engine_info.get('technology', ['Unknown']))
                    f.write(f"- **Technology Stack**: {technologies}\n")
                    
                if 'url' in engine_info and engine_info['url']:
                    f.write(f"- **Reference**: {engine_info['url']}\n")
                
                f.write("\n")
            
            # Basic vulnerabilities
            basic_vulns = entry.get('results', {}).get('basic_vulnerabilities', [])
            if basic_vulns:
                f.write("### Basic Vulnerabilities\n\n")
                for vuln in basic_vulns:
                    title = vuln.get('title', 'Unknown vulnerability')
                    severity = vuln.get('severity', 'UNKNOWN')
                    description = vuln.get('description', 'No description available')
                    impact = vuln.get('impact', 'Unknown impact')
                    curl = vuln.get('curl_verify', '')
                    
                    f.write(f"#### {title} ({severity})\n\n")
                    f.write(f"**Description**: {description}\n\n")
                    f.write(f"**Impact**: {impact}\n\n")
                    
                    if curl:
                        f.write("**Verification Command**:\n")
                        f.write(f"```bash\n{curl}\n```\n\n")
            
            # Injection vulnerabilities
            injection_vulns = entry.get('results', {}).get('injection_vulnerabilities', [])
            if injection_vulns:
                f.write("### Injection Vulnerabilities\n\n")
                for vuln in injection_vulns:
                    if isinstance(vuln, str):
                        f.write(f"- {vuln}\n\n")
                    else:
                        title = vuln.get('title', 'Unknown vulnerability')
                        payload = vuln.get('payload', 'Unknown payload')
                        f.write(f"#### {title}\n\n")
                        f.write(f"**Payload**: `{payload}`\n\n")
            
            f.write("---\n\n")
        
        # Add footer
        f.write("\n\n*This report was generated automatically by GrapeQL*\n")