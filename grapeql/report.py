"""
Report generation for GrapeQL security testing results

Author: Aleksa Zatezalo
Version: 3.0
"""

import json
import datetime
from typing import Dict, List


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
    if not filename.endswith(('.md', '.json', '.txt', '.html')):
        filename += '.md'
    
    if filename.endswith('.json'):
        _generate_json_report(filename, results)
    elif filename.endswith('.html'):
        _generate_html_report(filename, results)
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
        
        # Table of contents
        f.write("## Table of Contents\n\n")
        for i, entry in enumerate(results, 1):
            endpoint = entry.get('endpoint', 'Unknown endpoint')
            f.write(f"{i}. [Endpoint: {endpoint}](#endpoint-{i})\n")
        f.write("\n")
        
        # Process each endpoint
        for i, entry in enumerate(results, 1):
            endpoint = entry.get('endpoint', 'Unknown endpoint')
            f.write(f"<a name='endpoint-{i}'></a>\n")
            f.write(f"## {i}. Endpoint: {endpoint}\n\n")
            
            # Always show server information
            server_info = entry.get('results', {}).get('summary', {}).get('server_info', {})
            f.write("### Server Information\n\n")
            f.write(f"- Implementation: **{server_info.get('name', 'Unknown')}**\n")
            f.write(f"- Technology Stack: {', '.join(server_info.get('technology', ['Unknown']))}\n")
            if server_info.get('url'):
                f.write(f"- Reference URL: {server_info.get('url')}\n")
            f.write("\n")
            
            # Add response time statistics if available
            response_stats = entry.get('results', {}).get('summary', {}).get('response_stats', {})
            if response_stats and response_stats.get('count', 0) > 0:
                f.write("### Response Time Statistics\n\n")
                f.write(f"- Requests: {response_stats.get('count', 0)}\n")
                f.write(f"- Minimum: {response_stats.get('min', 0):.4f} seconds\n")
                f.write(f"- Maximum: {response_stats.get('max', 0):.4f} seconds\n")
                f.write(f"- Average: {response_stats.get('avg', 0):.4f} seconds\n\n")
            
            # Get test results
            test_results = entry.get('results', {}).get('tests', [])
            
            if not test_results:
                f.write("No test results available for this endpoint.\n\n")
                continue
            
            # Group by severity
            high_severity = []
            medium_severity = []
            low_severity = []
            
            for test in test_results:
                if test.get('vulnerable', False):
                    severity = test.get('severity', '').upper()
                    if severity == 'HIGH':
                        high_severity.append(test)
                    elif severity == 'MEDIUM':
                        medium_severity.append(test)
                    elif severity == 'LOW':
                        low_severity.append(test)
            
            # Write vulnerabilities by severity
            if high_severity:
                f.write("### High Severity Vulnerabilities\n\n")
                for j, vuln in enumerate(high_severity, 1):
                    _write_vulnerability_details(f, vuln, f"{i}.1.{j}")
            
            if medium_severity:
                f.write("### Medium Severity Vulnerabilities\n\n")
                for j, vuln in enumerate(medium_severity, 1):
                    _write_vulnerability_details(f, vuln, f"{i}.2.{j}")
            
            if low_severity:
                f.write("### Low Severity Vulnerabilities\n\n")
                for j, vuln in enumerate(low_severity, 1):
                    _write_vulnerability_details(f, vuln, f"{i}.3.{j}")
            
            if not high_severity and not medium_severity and not low_severity:
                f.write("### No Vulnerabilities Found\n\n")
                f.write("All security tests passed. No vulnerabilities were detected on this endpoint.\n\n")
            
            # Summary
            summary = entry.get('results', {}).get('summary', {})
            if summary:
                f.write("### Summary\n\n")
                f.write(f"- Total tests run: {summary.get('total', 0)}\n")
                f.write(f"- Vulnerabilities found: {summary.get('vulnerabilities', 0)}\n")
                f.write(f"  - High severity: {summary.get('high', 0)}\n")
                f.write(f"  - Medium severity: {summary.get('medium', 0)}\n")
                f.write(f"  - Low severity: {summary.get('low', 0)}\n\n")
            
            f.write("---\n\n")
        
        # Add footer
        f.write("\n\n*This report was generated automatically by GrapeQL*\n")


def _write_vulnerability_details(f, vuln: Dict, prefix: str = "") -> None:
    """Write details of a vulnerability to the report file."""
    name = vuln.get('name', 'Unknown vulnerability')
    description = vuln.get('description', 'No description provided')
    details = vuln.get('details', 'No details provided')
    
    if prefix:
        f.write(f"#### {prefix}. {name}\n\n")
    else:
        f.write(f"#### {name}\n\n")
        
    f.write(f"**Description**: {description}\n\n")
    f.write(f"**Details**: {details}\n\n")
    
    # Add response time for DoS tests
    if "response_time" in vuln and vuln["response_time"] is not None:
        f.write(f"**Response Time**: {vuln['response_time']:.4f} seconds\n\n")
    
    # Add curl command if available
    if "curl_command" in vuln and vuln["curl_command"]:
        f.write("**Sample curl command**:\n```bash\n")
        f.write(vuln["curl_command"])
        f.write("\n```\n\n")
    
    # Add multiple curl commands if available
    if "curl_commands" in vuln and vuln["curl_commands"]:
        f.write("**Sample curl commands**:\n\n")
        for i, cmd in enumerate(vuln["curl_commands"], 1):
            f.write(f"{i}. For field `{cmd.get('field', '')}` with payload `{cmd.get('payload', '')}`:\n")
            f.write("```bash\n")
            f.write(cmd.get('curl', ''))
            f.write("\n```\n\n")
    
    # Add vulnerable fields if available
    vulnerable_fields = vuln.get('vulnerable_fields', [])
    if vulnerable_fields:
        f.write("**Vulnerable Fields**:\n\n")
        for k, field in enumerate(vulnerable_fields, 1):
            operation = field.get('operation', '')
            field_name = field.get('field', '')
            arg_name = field.get('arg', '')
            payload = field.get('payload', '')
            
            f.write(f"{k}. `{operation}.{field_name}.{arg_name}` with payload: `{payload}`\n")
        
        f.write("\n")


def _generate_html_report(filename: str, results: List[Dict]) -> None:
    """Generate an HTML report."""
    html_start = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GrapeQL Security Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1000px;
            margin: 0 auto;
            padding: 20px;
        }
        h1 {
            color: #5a2d82;
            border-bottom: 2px solid #5a2d82;
            padding-bottom: 10px;
        }
        h2 {
            color: #5a2d82;
            margin-top: 30px;
        }
        h3 {
            margin-top: 25px;
            border-left: 4px solid #5a2d82;
            padding-left: 10px;
        }
        h4 {
            color: #333;
        }
        .high {
            color: #e60000;
        }
        .medium {
            color: #ff9900;
        }
        .low {
            color: #ffcc00;
        }
        .safe {
            color: #00cc66;
        }
        .info {
            color: #0066cc;
        }
        .summary {
            background-color: #f7f7f7;
            border-left: 4px solid #5a2d82;
            padding: 15px;
            margin: 20px 0;
        }
        .server-info {
            background-color: #f0f7ff;
            border-left: 4px solid #0066cc;
            padding: 15px;
            margin-bottom: 20px;
        }
        .stats-info {
            background-color: #f0fff7;
            border-left: 4px solid #00cc66;
            padding: 15px;
            margin-bottom: 20px;
        }
        .vuln-details {
            background-color: #f9f9f9;
            border-left: 4px solid #ddd;
            padding: 15px;
            margin-bottom: 20px;
        }
        .footer {
            text-align: center;
            margin-top: 50px;
            color: #777;
            font-size: 0.9em;
        }
        hr {
            border: none;
            height: 1px;
            background-color: #ddd;
            margin: 30px 0;
        }
        code {
            background-color: #f0f0f0;
            padding: 2px 5px;
            border-radius: 3px;
            font-family: monospace;
        }
        pre {
            background-color: #f0f0f0;
            padding: 10px;
            border-radius: 3px;
            overflow-x: auto;
            font-family: monospace;
            font-size: 0.9em;
        }
        .toc {
            background-color: #f9f9f9;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 30px;
        }
        .toc h2 {
            margin-top: 0;
        }
        .toc ol {
            padding-left: 20px;
        }
    </style>
</head>
<body>
    <h1>GrapeQL Security Report</h1>
    <p>Date: {date}</p>
"""
    
    html_end = """
    <div class="footer">
        <p>This report was generated automatically by GrapeQL</p>
    </div>
</body>
</html>
"""
    
    with open(filename, 'w') as f:
        # Write HTML header
        f.write(html_start.format(date=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        
        # Table of Contents
        f.write("<div class='toc'>\n")
        f.write("<h2>Table of Contents</h2>\n")
        f.write("<ol>\n")
        for i, entry in enumerate(results, 1):
            endpoint = entry.get('endpoint', 'Unknown endpoint')
            f.write(f"<li><a href='#endpoint-{i}'>Endpoint: {endpoint}</a></li>\n")
        f.write("</ol>\n")
        f.write("</div>\n")
        
        # Process each endpoint
        for i, entry in enumerate(results, 1):
            endpoint = entry.get('endpoint', 'Unknown endpoint')
            f.write(f"<h2 id='endpoint-{i}'>{i}. Endpoint: {endpoint}</h2>\n")
            
            # Always show server information
            server_info = entry.get('results', {}).get('summary', {}).get('server_info', {})
            f.write("<div class='server-info'>\n")
            f.write("<h3 class='info'>Server Information</h3>\n")
            f.write("<ul>\n")
            f.write(f"<li><strong>Implementation:</strong> {server_info.get('name', 'Unknown')}</li>\n")
            f.write(f"<li><strong>Technology Stack:</strong> {', '.join(server_info.get('technology', ['Unknown']))}</li>\n")
            if server_info.get('url'):
                f.write(f"<li><strong>Reference URL:</strong> <a href='{server_info.get('url')}' target='_blank'>{server_info.get('url')}</a></li>\n")
            f.write("</ul>\n")
            f.write("</div>\n")
            
            # Add response time statistics if available
            response_stats = entry.get('results', {}).get('summary', {}).get('response_stats', {})
            if response_stats and response_stats.get('count', 0) > 0:
                f.write("<div class='stats-info'>\n")
                f.write("<h3 class='info'>Response Time Statistics</h3>\n")
                f.write("<ul>\n")
                f.write(f"<li><strong>Requests:</strong> {response_stats.get('count', 0)}</li>\n")
                f.write(f"<li><strong>Minimum:</strong> {response_stats.get('min', 0):.4f} seconds</li>\n")
                f.write(f"<li><strong>Maximum:</strong> {response_stats.get('max', 0):.4f} seconds</li>\n")
                f.write(f"<li><strong>Average:</strong> {response_stats.get('avg', 0):.4f} seconds</li>\n")
                f.write("</ul>\n")
                f.write("</div>\n")
            
            # Get test results
            test_results = entry.get('results', {}).get('tests', [])
            
            if not test_results:
                f.write("<p>No test results available for this endpoint.</p>\n")
                continue
            
            # Group by severity
            high_severity = []
            medium_severity = []
            low_severity = []
            
            for test in test_results:
                if test.get('vulnerable', False):
                    severity = test.get('severity', '').upper()
                    if severity == 'HIGH':
                        high_severity.append(test)
                    elif severity == 'MEDIUM':
                        medium_severity.append(test)
                    elif severity == 'LOW':
                        low_severity.append(test)
            
            # Write vulnerabilities by severity
            if high_severity:
                f.write("<h3 class='high'>High Severity Vulnerabilities</h3>\n")
                for j, vuln in enumerate(high_severity, 1):
                    _write_html_vulnerability(f, vuln, f"{i}.1.{j}")
            
            if medium_severity:
                f.write("<h3 class='medium'>Medium Severity Vulnerabilities</h3>\n")
                for j, vuln in enumerate(medium_severity, 1):
                    _write_html_vulnerability(f, vuln, f"{i}.2.{j}")
            
            if low_severity:
                f.write("<h3 class='low'>Low Severity Vulnerabilities</h3>\n")
                for j, vuln in enumerate(low_severity, 1):
                    _write_html_vulnerability(f, vuln, f"{i}.3.{j}")
            
            if not high_severity and not medium_severity and not low_severity:
                f.write("<h3 class='safe'>No Vulnerabilities Found</h3>\n")
                f.write("<p>All security tests passed. No vulnerabilities were detected on this endpoint.</p>\n")
            
            # Summary
            summary = entry.get('results', {}).get('summary', {})
            if summary:
                f.write("<div class='summary'>\n")
                f.write("<h3>Summary</h3>\n")
                f.write("<ul>\n")
                f.write(f"<li>Total tests run: {summary.get('total', 0)}</li>\n")
                f.write(f"<li>Vulnerabilities found: {summary.get('vulnerabilities', 0)}</li>\n")
                f.write("<ul>\n")
                f.write(f"<li>High severity: {summary.get('high', 0)}</li>\n")
                f.write(f"<li>Medium severity: {summary.get('medium', 0)}</li>\n")
                f.write(f"<li>Low severity: {summary.get('low', 0)}</li>\n")
                f.write("</ul>\n")
                f.write("</ul>\n")
                f.write("</div>\n")
            
            f.write("<hr>\n")
        
        # Write HTML footer
        f.write(html_end)


def _write_html_vulnerability(f, vuln: Dict, prefix: str = "") -> None:
    """Write HTML details of a vulnerability to the report file."""
    name = vuln.get('name', 'Unknown vulnerability')
    description = vuln.get('description', 'No description provided')
    details = vuln.get('details', 'No details provided')
    
    f.write("<div class='vuln-details'>\n")
    
    if prefix:
        f.write(f"<h4>{prefix}. {name}</h4>\n")
    else:
        f.write(f"<h4>{name}</h4>\n")
        
    f.write(f"<p><strong>Description</strong>: {description}</p>\n")
    f.write(f"<p><strong>Details</strong>: {details}</p>\n")
    
    # Add response time for DoS tests
    if "response_time" in vuln and vuln["response_time"] is not None:
        f.write(f"<p><strong>Response Time</strong>: {vuln['response_time']:.4f} seconds</p>\n")
    
    # Add curl command if available
    if "curl_command" in vuln and vuln["curl_command"]:
        f.write("<p><strong>Sample curl command</strong>:</p>\n")
        f.write("<pre><code>")
        f.write(vuln["curl_command"].replace("<", "&lt;").replace(">", "&gt;"))
        f.write("</code></pre>\n")
    
    # Add multiple curl commands if available
    if "curl_commands" in vuln and vuln["curl_commands"]:
        f.write("<p><strong>Sample curl commands</strong>:</p>\n")
        f.write("<ol>\n")
        for cmd in vuln["curl_commands"]:
            f.write(f"<li>For field <code>{cmd.get('field', '')}</code> with payload <code>{cmd.get('payload', '')}</code>:\n")
            f.write("<pre><code>")
            f.write(cmd.get('curl', '').replace("<", "&lt;").replace(">", "&gt;"))
            f.write("</code></pre></li>\n")
        f.write("</ol>\n")
    
    # Add vulnerable fields if available
    vulnerable_fields = vuln.get('vulnerable_fields', [])
    if vulnerable_fields:
        f.write("<p><strong>Vulnerable Fields</strong>:</p>\n")
        f.write("<ol>\n")
        for field in vulnerable_fields:
            operation = field.get('operation', '')
            field_name = field.get('field', '')
            arg_name = field.get('arg', '')
            payload = field.get('payload', '')
            
            f.write(f"<li><code>{operation}.{field_name}.{arg_name}</code> with payload: <code>{payload}</code></li>\n")
        
        f.write("</ol>\n")
    
    f.write("</div>\n")