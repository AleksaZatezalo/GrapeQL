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
        
        for entry in results:
            endpoint = entry.get('endpoint', 'Unknown endpoint')
            f.write(f"## Endpoint: {endpoint}\n\n")
            
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
                f.write("###  High Severity Vulnerabilities\n\n")
                for vuln in high_severity:
                    _write_vulnerability_details(f, vuln)
            
            if medium_severity:
                f.write("###  Medium Severity Vulnerabilities\n\n")
                for vuln in medium_severity:
                    _write_vulnerability_details(f, vuln)
            
            if low_severity:
                f.write("###  Low Severity Vulnerabilities\n\n")
                for vuln in low_severity:
                    _write_vulnerability_details(f, vuln)
            
            if not high_severity and not medium_severity and not low_severity:
                f.write("###  No Vulnerabilities Found\n\n")
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


def _write_vulnerability_details(f, vuln: Dict) -> None:
    """Write details of a vulnerability to the report file."""
    name = vuln.get('name', 'Unknown vulnerability')
    description = vuln.get('description', 'No description provided')
    details = vuln.get('details', 'No details provided')
    
    f.write(f"#### {name}\n\n")
    f.write(f"**Description**: {description}\n\n")
    f.write(f"**Details**: {details}\n\n")
    
    # Add vulnerable fields if available
    vulnerable_fields = vuln.get('vulnerable_fields', [])
    if vulnerable_fields:
        f.write("**Vulnerable Fields**:\n\n")
        for field in vulnerable_fields:
            operation = field.get('operation', '')
            field_name = field.get('field', '')
            arg_name = field.get('arg', '')
            payload = field.get('payload', '')
            
            f.write(f"- `{operation}.{field_name}.{arg_name}` with payload: `{payload}`\n")
        
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
        .summary {
            background-color: #f7f7f7;
            border-left: 4px solid #5a2d82;
            padding: 15px;
            margin: 20px 0;
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
        
        # Process each endpoint
        for entry in results:
            endpoint = entry.get('endpoint', 'Unknown endpoint')
            f.write(f"<h2>Endpoint: {endpoint}</h2>\n")
            
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
                f.write("<h3 class='high'> High Severity Vulnerabilities</h3>\n")
                for vuln in high_severity:
                    _write_html_vulnerability(f, vuln)
            
            if medium_severity:
                f.write("<h3 class='medium'> Medium Severity Vulnerabilities</h3>\n")
                for vuln in medium_severity:
                    _write_html_vulnerability(f, vuln)
            
            if low_severity:
                f.write("<h3 class='low'> Low Severity Vulnerabilities</h3>\n")
                for vuln in low_severity:
                    _write_html_vulnerability(f, vuln)
            
            if not high_severity and not medium_severity and not low_severity:
                f.write("<h3 class='safe'> No Vulnerabilities Found</h3>\n")
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


def _write_html_vulnerability(f, vuln: Dict) -> None:
    """Write HTML details of a vulnerability to the report file."""
    name = vuln.get('name', 'Unknown vulnerability')
    description = vuln.get('description', 'No description provided')
    details = vuln.get('details', 'No details provided')
    
    f.write("<div class='vuln-details'>\n")
    f.write(f"<h4>{name}</h4>\n")
    f.write(f"<p><strong>Description</strong>: {description}</p>\n")
    f.write(f"<p><strong>Details</strong>: {details}</p>\n")
    
    # Add vulnerable fields if available
    vulnerable_fields = vuln.get('vulnerable_fields', [])
    if vulnerable_fields:
        f.write("<p><strong>Vulnerable Fields</strong>:</p>\n")
        f.write("<ul>\n")
        for field in vulnerable_fields:
            operation = field.get('operation', '')
            field_name = field.get('field', '')
            arg_name = field.get('arg', '')
            payload = field.get('payload', '')
            
            f.write(f"<li><code>{operation}.{field_name}.{arg_name}</code> with payload: <code>{payload}</code></li>\n")
        
        f.write("</ul>\n")
    
    f.write("</div>\n")