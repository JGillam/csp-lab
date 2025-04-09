"""
Utility functions for parsing CSP headers and analyzing their effectiveness.
"""
from typing import Dict, List, Optional, Tuple, Set
import re


def parse_csp_header(header: str) -> Dict[str, List[str]]:
    """
    Parse a Content Security Policy header into a structured dictionary.
    
    Args:
        header: The raw CSP header string
        
    Returns:
        Dictionary mapping directives to their values
    """
    if not header:
        return {}
    
    # Split the header into directive-value pairs
    directives = {}
    
    # Remove any leading/trailing whitespace and split by semicolons
    parts = [part.strip() for part in header.split(';') if part.strip()]
    
    for part in parts:
        # Split the directive from its values
        if not part:
            continue
            
        components = part.split(None, 1)
        directive = components[0].lower()
        
        if len(components) > 1:
            # Multiple values separated by spaces
            values = [v.strip() for v in components[1].split() if v.strip()]
        else:
            # No values for this directive
            values = []
        
        directives[directive] = values
    
    return directives


def analyze_csp_effectiveness(directives: Dict[str, List[str]]) -> str:
    """
    Analyze CSP directives and categorize the policy's effectiveness.
    
    Args:
        directives: Parsed CSP directives
        
    Returns:
        Category of effectiveness: "none", "minimal", "moderate", or "strong"
    """
    if not directives:
        return "none"
    
    # Check for unsafe directives
    unsafe_directives = {
        "unsafe-inline", 
        "unsafe-eval", 
        "unsafe-hashes",
        "data:", 
        "*"
    }
    
    # Count how many critical directives use unsafe values
    unsafe_count = 0
    critical_directives = {
        "script-src", 
        "style-src", 
        "default-src"
    }
    
    # Check if fallback to default-src is needed
    for directive in critical_directives:
        if directive not in directives and "default-src" in directives:
            # This directive falls back to default-src
            values = directives["default-src"]
        else:
            values = directives.get(directive, [])
            
        if any(unsafe in values for unsafe in unsafe_directives):
            unsafe_count += 1
    
    # Check for advanced directives
    has_nonce = any("'nonce-" in str(v) for d in directives.values() for v in d)
    has_hash = any("'sha" in str(v) for d in directives.values() for v in d)
    has_strict_dynamic = any("'strict-dynamic'" in str(v) for v in directives.values())
    has_trusted_types = "trusted-types" in directives
    
    # Determine effectiveness
    if has_trusted_types or (has_strict_dynamic and (has_nonce or has_hash)):
        return "strong"
    elif (has_nonce or has_hash) and unsafe_count <= 1:
        return "moderate"
    elif unsafe_count < len(critical_directives):
        return "minimal"
    else:
        return "none"


def detect_csp_misconfigurations(directives: Dict[str, List[str]]) -> List[str]:
    """
    Detect common CSP misconfigurations.
    
    Args:
        directives: Parsed CSP directives
        
    Returns:
        List of detected misconfigurations
    """
    issues = []
    
    # Check for missing critical directives when default-src is not set
    if "default-src" not in directives:
        for directive in ["script-src", "style-src", "connect-src"]:
            if directive not in directives:
                issues.append(f"Missing {directive} directive without default-src fallback")
    
    # Check for overly permissive directives
    for directive, values in directives.items():
        if "*" in values:
            issues.append(f"Overly permissive wildcard in {directive}")
    
    # Check for 'self' without protocol specification
    for directive, values in directives.items():
        if "'self'" in values and not any(v.startswith(("https:", "http:")) for v in values):
            issues.append(f"{directive} uses 'self' without protocol specification")
    
    # Check for report-uri without report-to (report-uri is deprecated)
    if "report-uri" in directives and "report-to" not in directives:
        issues.append("Using deprecated report-uri without report-to")
    
    # Check for mixed content
    if any("http:" in v for d, values in directives.items() for v in values):
        issues.append("Policy allows mixed content (http:)")
    
    return issues


def parse_sri_attributes(html_content: str) -> Tuple[int, int, int, int]:
    """
    Parse HTML content to count script and link tags with SRI attributes.
    
    Args:
        html_content: HTML content as a string
        
    Returns:
        Tuple containing:
            - Total number of script tags
            - Number of script tags with integrity attribute
            - Total number of link tags
            - Number of link tags with integrity attribute
    """
    # Count script tags
    script_tags_total = len(re.findall(r'<script[^>]*>', html_content, re.IGNORECASE))
    script_tags_with_integrity = len(re.findall(r'<script[^>]*integrity=["\'][^"\']*["\'][^>]*>', html_content, re.IGNORECASE))
    
    # Count link tags
    link_tags_total = len(re.findall(r'<link[^>]*>', html_content, re.IGNORECASE))
    link_tags_with_integrity = len(re.findall(r'<link[^>]*integrity=["\'][^"\']*["\'][^>]*>', html_content, re.IGNORECASE))
    
    return (script_tags_total, script_tags_with_integrity, link_tags_total, link_tags_with_integrity)
