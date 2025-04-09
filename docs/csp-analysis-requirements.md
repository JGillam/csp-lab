# Content Security Policy Analysis Project
## Project Overview

This document outlines the requirements for a project to analyze Content Security Policy (CSP) implementation across popular websites. The project aims to gather data about CSP adoption and effectiveness to support a presentation at an upcoming information security conference.

## Objectives

1. Collect CSP and Subresource Integrity (SRI) data from a large sample of popular websites
2. Store the collected data in a structured format for further analysis
3. Analyze the data to determine statistics on CSP implementation patterns
4. Generate insights on the effectiveness and adoption of various CSP directives

## Technical Requirements

### Data Collection Tool

The tool should:

1. Accept an input list of target websites (approximately 10,000 sites)
2. For each website:
   - Retrieve the full HTTP response headers
   - Extract and store the Content-Security-Policy header (if present)
   - Extract and store any Content-Security-Policy-Report-Only headers (if present)
   - Scan the HTML response for Subresource Integrity (SRI) attributes in `<script>` and `<link>` tags
   - Record the presence/absence of CSP and SRI
   - Handle connection failures gracefully (retry logic, timeout handling)
   - Maintain a log of failed attempts
3. Process multiple sites concurrently to improve performance
4. Include rate limiting to avoid triggering security controls
5. Store all collected data in a structured JSON format

### Data Storage Format

The JSON output should capture:

```json
{
  "metadata": {
    "date_collected": "ISO-8601 timestamp",
    "total_sites_attempted": 10000,
    "total_sites_succeeded": 9850,
    "tool_version": "1.0.0"
  },
  "sites": [
    {
      "url": "https://example.com",
      "timestamp": "ISO-8601 timestamp",
      "status_code": 200,
      "headers": {
        "content-security-policy": "policy string here",
        "content-security-policy-report-only": "policy string here (if present)"
      },
      "sri_usage": {
        "script_tags_total": 15,
        "script_tags_with_integrity": 8,
        "link_tags_total": 12,
        "link_tags_with_integrity": 3
      },
      "error": null
    },
    {
      "url": "https://example.org",
      "timestamp": "ISO-8601 timestamp",
      "status_code": null,
      "headers": null,
      "sri_usage": null,
      "error": "Connection timeout after 30s"
    }
  ]
}
```

### Analysis Tool Requirements

Develop one or more analysis scripts to process the collected JSON data and extract meaningful statistics, including:

1. Basic adoption statistics:
   - Percentage of sites with no CSP
   - Percentage of sites with CSP
   - Percentage of sites with CSP-Report-Only
   - Percentage of sites with both CSP and CSP-Report-Only

2. CSP effectiveness analysis:
   - Identify sites with "checkbox" CSPs (containing unsafe-inline, unsafe-eval, etc.)
   - Categorize CSP implementations by effectiveness (none, minimal, moderate, strong)
   - Identify most common CSP directives and their configurations
   - Detect common CSP misconfigurations

3. SRI adoption:
   - Percentage of sites using SRI
   - Correlation between SRI usage and CSP strength
   - Average percentage of script tags protected by SRI per site
   - Average percentage of link tags protected by SRI per site

4. Advanced directives analysis:
   - Adoption of newer CSP directives (trusted-types, require-trusted-types-for)
   - Usage of nonce-based CSP
   - Usage of hash-based CSP
   - Implementation of strict-dynamic

## Technical Constraints

### Language and Libraries

- The tools should be developed in Python for maximum portability and ease of maintenance
- Use standard libraries where possible (requests, BeautifulSoup, etc.)
- Include proper error handling and logging
- Provide clear documentation for setup and usage
- Implement using a Python virtual environment for dependency isolation and reproducibility

### Performance Requirements

- The collection tool should be able to process at least 10 sites per minute on average
- The tool should support resuming interrupted scans
- Memory usage should be optimized to handle the complete dataset

### Usability Requirements

- Command-line interface with configurable parameters (target list, output file, concurrency level, etc.)
- Progress indicators during long-running operations
- Clear logging of errors and warnings
- Simple setup process with minimal dependencies

## Deliverables

1. Data Collection Tool:
   - Source code with documentation
   - Requirements file (requirements.txt) listing all dependencies
   - Usage instructions
   - Script for setting up and activating the virtual environment

2. Analysis Tools:
   - Source code with documentation
   - Requirements file (can share the same requirements.txt)
   - Usage instructions

3. Sample Data:
   - A small sample dataset for testing

4. Environment Setup:
   - Instructions for creating and activating the virtual environment
   - Clearly documented Python version requirements (recommend Python 3.8+)

## Timeline

- Initial prototype: 2 weeks
- Final delivery: 1 month
- Support period: 2 weeks after delivery for bug fixes and adjustments

## Extensions (Optional)

If time permits, consider implementing:

1. Visualization components for the analysis results
2. Historical tracking to detect CSP changes over time
3. Comparison against industry best practices or standards
4. Detection of CSP bypasses or weaknesses
5. A web interface for exploring the collected data

## Contact Information

[Your contact information]

## References

- [Content Security Policy Level 3 Specification](https://www.w3.org/TR/CSP3/)
- [Subresource Integrity Specification](https://www.w3.org/TR/SRI/)
- [OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
