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


def analyze_csp_script_execution(directives: Dict[str, List[str]]) -> int:
    """
    Analyze script execution control level in CSP directives.
    
    Args:
        directives: Parsed CSP directives
        
    Returns:
        Score from 1-5 representing the strength of script execution control
    """
    if not directives:
        return 1  # Ineffective
    
    # Check script-src or fallback to default-src
    if "script-src" in directives:
        script_values = directives["script-src"]
    elif "default-src" in directives:
        script_values = directives["default-src"]
    else:
        return 1  # Missing script-src with no restrictive default-src
    
    # Convert to lowercase strings for easier matching
    script_values = [str(v).lower() for v in script_values]
    
    # Check for nonce/hash techniques
    has_nonce = any("'nonce-" in v for v in script_values)
    has_hash = any(("'sha256-" in v or "'sha384-" in v or "'sha512-" in v) for v in script_values)
    has_strict_dynamic = "'strict-dynamic'" in script_values
    
    # Check for unsafe directives (considering browser behavior)
    has_literal_unsafe_inline = "'unsafe-inline'" in script_values
    # If nonce or hash is present, unsafe-inline is ignored by modern browsers
    has_effective_unsafe_inline = has_literal_unsafe_inline and not (has_nonce or has_hash)
    
    has_unsafe_eval = "'unsafe-eval'" in script_values
    has_wildcard = "*" in script_values
    has_permissive_scheme = any(v in ["https:", "http:"] for v in script_values)
    has_dangerous_scheme = any(v in ["data:", "blob:", "filesystem:"] for v in script_values)
    has_trusted_types = "trusted-types" in directives
    
    # Level 5: Exceptional (Trusted Types, strict-dynamic, no effective unsafe directives)
    if has_trusted_types and has_strict_dynamic and (has_nonce or has_hash) and not has_effective_unsafe_inline and not has_unsafe_eval:
        return 5
    
    # Level 4: Strong (strict-dynamic with nonce/hash, may have safer eval alternatives)
    if has_strict_dynamic and (has_nonce or has_hash) and (not has_unsafe_eval or "'wasm-unsafe-eval'" in script_values):
        return 4
    
    # Level 3: Moderate (proper nonce/hash usage, no wildcards or dangerous schemes)
    if (has_nonce or has_hash) and not has_effective_unsafe_inline and not has_wildcard and not has_permissive_scheme and not has_dangerous_scheme:
        return 3
    
    # Level 2: Basic (specific domains, may have literal unsafe-inline with nonce/hash)
    if (len(script_values) > 0 and not has_wildcard) or (has_literal_unsafe_inline and (has_nonce or has_hash)):
        return 2
    
    # Level 1: Ineffective
    return 1


def analyze_csp_style_injection(directives: Dict[str, List[str]]) -> int:
    """
    Analyze style injection control level in CSP directives.
    
    Args:
        directives: Parsed CSP directives
        
    Returns:
        Score from 1-5 representing the strength of style injection control
    """
    if not directives:
        return 1  # Ineffective
    
    # Check style-src or fallback to default-src
    if "style-src" in directives:
        style_values = directives["style-src"]
    elif "default-src" in directives:
        style_values = directives["default-src"]
    else:
        return 1  # Missing style-src with no restrictive default-src
    
    # Convert to lowercase strings for easier matching
    style_values = [str(v).lower() for v in style_values]
    
    # Check style protection features
    has_nonce = any("'nonce-" in v for v in style_values)
    has_hash = any(("'sha256-" in v or "'sha384-" in v or "'sha512-" in v) for v in style_values)
    has_unsafe_inline = "'unsafe-inline'" in style_values
    has_wildcard = "*" in style_values
    
    # Level 5: Exceptional (nonce/hash for all inline styles, no unsafe-inline)
    if (has_nonce or has_hash) and not has_unsafe_inline and not has_wildcard:
        return 5
    
    # Level 3: Moderate (specific domains, may use nonces/hashes)
    if (has_nonce or has_hash or len(style_values) > 0) and not has_wildcard:
        return 3
    
    # Level 1: Ineffective
    return 1


def analyze_csp_object_media(directives: Dict[str, List[str]]) -> int:
    """
    Analyze object/media control level in CSP directives.
    
    Args:
        directives: Parsed CSP directives
        
    Returns:
        Score from 1-5 representing the strength of object/media control
    """
    if not directives:
        return 1  # Ineffective
    
    # Check object-src or fallback to default-src
    if "object-src" in directives:
        object_values = directives["object-src"]
    elif "default-src" in directives:
        object_values = directives["default-src"]
    else:
        return 1  # Missing object-src with no restrictive default-src
    
    # Convert to lowercase strings for easier matching
    object_values = [str(v).lower() for v in object_values]
    
    # Level 5: Exceptional (object-src: 'none')
    if "'none'" in object_values:
        return 5
    
    # Level 3: Moderate (specific restrictions, no wildcards)
    if len(object_values) > 0 and "*" not in object_values:
        return 3
    
    # Level 1: Ineffective
    return 1


def analyze_csp_frame_control(directives: Dict[str, List[str]]) -> int:
    """
    Analyze frame control level in CSP directives.
    
    Args:
        directives: Parsed CSP directives
        
    Returns:
        Score from 1-5 representing the strength of frame control
    """
    if not directives or "frame-ancestors" not in directives:
        return 1  # Missing frame-ancestors directive
    
    frame_values = [str(v).lower() for v in directives["frame-ancestors"]]
    
    # Level 5: Exceptional (restricted to 'self' or 'none')
    if "'none'" in frame_values or ("'self'" in frame_values and len(frame_values) == 1):
        return 5
    
    # Level 3: Moderate (specific domains, no wildcards)
    if "*" not in frame_values and len(frame_values) > 0:
        return 3
    
    # Level 1: Ineffective
    return 1


def analyze_csp_form_action(directives: Dict[str, List[str]]) -> int:
    """
    Analyze form action control level in CSP directives.
    
    Args:
        directives: Parsed CSP directives
        
    Returns:
        Score from 1-5 representing the strength of form action control
    """
    if not directives or "form-action" not in directives:
        return 1  # Missing form-action directive
    
    form_values = [str(v).lower() for v in directives["form-action"]]
    
    # Level 5: Exceptional (restricted to 'self' with limited external targets)
    if "'self'" in form_values and len(form_values) <= 2:
        return 5
    
    # Level 3: Moderate (specific domains, no wildcards)
    if "*" not in form_values and len(form_values) > 0:
        return 3
    
    # Level 1: Ineffective
    return 1


def analyze_csp_base_uri(directives: Dict[str, List[str]]) -> int:
    """
    Analyze base URI control level in CSP directives.
    
    Args:
        directives: Parsed CSP directives
        
    Returns:
        Score from 1-5 representing the strength of base URI control
    """
    if not directives or "base-uri" not in directives:
        return 1  # Missing base-uri directive
    
    base_values = [str(v).lower() for v in directives["base-uri"]]
    
    # Level 5: Exceptional (restricted to 'self' or 'none')
    if "'none'" in base_values or ("'self'" in base_values and len(base_values) == 1):
        return 5
    
    # Level 3: Moderate (specific domains, no wildcards)
    if "*" not in base_values and len(base_values) > 0:
        return 3
    
    # Level 1: Ineffective
    return 1


def analyze_csp_components(directives: Dict[str, List[str]]) -> Dict[str, int]:
    """
    Perform component-based CSP classification according to the framework.
    
    Args:
        directives: Parsed CSP directives
        
    Returns:
        Dictionary with scores for each component:
        - script_execution_score
        - style_injection_score
        - object_media_score
        - frame_control_score
        - form_action_score
        - base_uri_score
    """
    return {
        "script_execution_score": analyze_csp_script_execution(directives),
        "style_injection_score": analyze_csp_style_injection(directives),
        "object_media_score": analyze_csp_object_media(directives),
        "frame_control_score": analyze_csp_frame_control(directives),
        "form_action_score": analyze_csp_form_action(directives),
        "base_uri_score": analyze_csp_base_uri(directives)
    }


def analyze_csp_effectiveness(directives: Dict[str, List[str]]) -> str:
    """
    Analyze CSP directives and categorize the policy's effectiveness.
    
    This is maintained for backward compatibility with existing code.
    Newer code should use analyze_csp_components instead.
    
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
