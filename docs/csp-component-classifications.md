# CSP Component-Based Classification Framework

This framework evaluates Content Security Policies by independently classifying the protection level for each critical security area, using concrete criteria that can be programmatically assessed across large datasets.

## 1. Script Execution Control

| Level | Classification | Criteria |
|-------|---------------|----------|
| **1** | **Ineffective** | • Missing `script-src` with no restrictive `default-src`<br>• Includes `'unsafe-inline'` without nonce/hash mitigation<br>• Uses wildcard (`*`) as source<br>• Uses overly permissive schemes (`https:`, `http:`) |
| **2** | **Basic** | • Defines `script-src` with specific domains<br>• May include `'unsafe-inline'` but with nonce/hash present<br>• May include `'unsafe-eval'`<br>• Limits scripts to specific domains but allows many external sources |
| **3** | **Moderate** | • No wildcards or overly permissive schemes<br>• Properly uses nonces or hashes<br>• Prohibits dangerous schemes (`data:`, etc.) |
| **4** | **Strong** | • Uses both nonces/hashes and `'strict-dynamic'`<br>• Avoids `'unsafe-eval'` or restricts it with alternatives like `'wasm-unsafe-eval'` |
| **5** | **Exceptional** | • Implements Trusted Types API protections<br>• No presence of `'unsafe-inline'` or `'unsafe-eval'`<br>• Uses nonce/hash with `'strict-dynamic'` and appropriate fallbacks |

## 2. Style Injection Control

| Level | Classification | Criteria |
|-------|---------------|----------|
| **1** | **Ineffective** | • Missing `style-src` with no restrictive `default-src`<br>• Includes `'unsafe-inline'` without mitigation<br>• Uses wildcard (`*`) as source |
| **3** | **Moderate** | • Defines `style-src` with specific domains<br>• May use nonces/hashes for inline styles<br>• No wildcards |
| **5** | **Exceptional** | • Uses nonces or hashes for all inline styles<br>• No `'unsafe-inline'` or properly mitigated<br>• Specific external style sources only |

## 3. Object/Media Control

| Level | Classification | Criteria |
|-------|---------------|----------|
| **1** | **Ineffective** | • Missing `object-src` with no restrictive `default-src`<br>• Uses wildcard (`*`) for plugin content |
| **3** | **Moderate** | • Defines `object-src` with specific restrictions<br>• No wildcards in sources |
| **5** | **Exceptional** | • Sets `object-src: 'none'`<br>• No plugin execution permitted |

## 4. Frame Control

| Level | Classification | Criteria |
|-------|---------------|----------|
| **1** | **Ineffective** | • Missing `frame-ancestors` directive<br>• `frame-ancestors` set to wildcard (`*`) |
| **3** | **Moderate** | • Includes `frame-ancestors` with specific domains<br>• No wildcards |
| **5** | **Exceptional** | • `frame-ancestors` restricted to 'self' or 'none'<br>• No third-party framing allowed or very strictly limited |

## 5. Form Action Control

| Level | Classification | Criteria |
|-------|---------------|----------|
| **1** | **Ineffective** | • Missing `form-action` directive<br>• `form-action` includes wildcard (`*`) |
| **3** | **Moderate** | • Includes `form-action` with specific domains<br>• No wildcards |
| **5** | **Exceptional** | • `form-action` restricted to 'self'<br>• Very limited external form submission targets |

## 6. Base URI Control

| Level | Classification | Criteria |
|-------|---------------|----------|
| **1** | **Ineffective** | • Missing `base-uri` directive<br>• `base-uri` includes wildcard (`*`) |
| **3** | **Moderate** | • Includes `base-uri` with specific domains<br>• No wildcards |
| **5** | **Exceptional** | • `base-uri` restricted to 'self' or 'none'<br>• Prevents manipulation of base URL for relative paths |

## Example Composite Analysis Approaches

Instead of a single composite score, consider these analysis approaches:

1. **Protection Profile**: Express as a vector [Script, Style, Object, Frame, Form, Base]
   * Example: [4, 3, 5, 1, 3, 5]
   * Provides complete pattern information without reduction

2. **Area-Specific Analysis**: Analyze each security area independently across the dataset
   * Identify common patterns and weaknesses
   * Track improvement areas across the web ecosystem

3. **Threshold Approach**: Classify sites based on minimum protection levels
   * "Comprehensively Protected": All areas at level 3 or higher
   * "Substantially Protected": At least four areas at level 3 or higher
   * "Partially Protected": At least three areas at level 3 or higher
   * "Minimally Protected": At least one area at level 3 or higher
   * "Ineffective": All areas below level 3

This framework can be implemented programmatically to analyze and classify CSP policies across the 750,000+ website dataset with clearly defined, objective criteria.

## Features Not Currently Classified

While the above classification framework covers the most critical aspects of CSP, the following features are intentionally excluded from the current classification scheme, though they may be considered for future enhancements:

1. **Upgrade-Insecure-Requests**: Directive that upgrades HTTP resources to HTTPS
2. **Navigate-To Controls**: Restrictions on where a document can navigate
3. **Report-To Configuration**: Whether appropriate reporting is configured
4. **Worker-src Protection**: Controls for web worker script sources
5. **Manifest-src**: Restrictions on PWA manifest loading
6. **Connect-src**: Network connection restrictions
7. **Feature/Permission Policy Integration**: Restrictions on browser features
8. **Fallback Strategies**: Provisions for older browsers without modern CSP support
