# XSSHunter - Reflected XSS Vulnerability Scanner

## Overview

XSSHunter is a specialized security scanning tool designed to detect reflected Cross-Site Scripting (XSS) vulnerabilities in web applications. It focuses on URL parameters and detects if payloads are reflected in the response content.

## Features

- **Parameter Testing**: Tests all GET parameters simultaneously with proven payloads
- **Reflection Detection**: Checks for payload reflection in response content
- **Extensive Payload Library**: Supports **911+ customizable XSS payloads** via database configuration
- **Automatic Parameter Extraction**: Automatically extracts and tests all URL parameters
- **Proven Approach**: Uses the proven method of replacing all parameters at once
- **Database-Backed Config**: Manage payloads through web UI or YAML files

## How It Works

1. **URL Collection**: Collects URLs from subdomains or a provided URL list
2. **Parameter Extraction**: Automatically extracts all GET parameters from each URL
3. **Payload Injection**: Replaces all parameters simultaneously with XSS payloads
4. **Reflection Detection**: Checks if the payload is reflected in the response content
5. **Finding Storage**: Stores confirmed XSS vulnerabilities in the database

## Usage

### Basic Usage

**Scan a single domain:**
```bash
python3 BugHunterArsenal.py -d example.com --tool xsshunter
```

**Scan multiple domains from a file:**
```bash
python3 BugHunterArsenal.py -f domains.txt --tool xsshunter
```

**Scan URLs directly** (skip subdomain enumeration):
```bash
python3 BugHunterArsenal.py -l urls.txt --tool xsshunter
```

**Disable subdomain enumeration:**
```bash
python3 BugHunterArsenal.py -d example.com --tool xsshunter --no-subs
```

### Advanced Options

**Add authentication cookie:**
```bash
python3 BugHunterArsenal.py -d example.com --cookie "session=abc123" --tool xsshunter
```

**Add custom header:**
```bash
python3 BugHunterArsenal.py -d example.com --x-request-for "HackerOne" --tool xsshunter
```

**Use custom output directory:**
```bash
python3 BugHunterArsenal.py -d example.com -o my_results --tool xsshunter
```

**Force restart:**
```bash
python3 BugHunterArsenal.py -d example.com --restart --tool xsshunter
```

**Enable verbose output:**
```bash
python3 BugHunterArsenal.py -d example.com -v --tool xsshunter
```

## Configuration

### XSS Payloads

XSSHunter uses a comprehensive library of XSS payloads stored in the database. Payloads can be managed through:

1. **Web UI**: Settings page → XSS Payloads tab
2. **YAML File**: `config/xss_payloads.yaml` (auto-synced to database)

**Default Payload:**
The tool uses a proven payload as the default: `"><img src=x onerror=prompt(String.fromCharCode(79,80,69,76,66,85,71,66,79,85,78,84,89))>`

**Example Payloads:**
```yaml
xss_payloads:
  default: '"><img src=x onerror=prompt(String.fromCharCode(79,80,69,76,66,85,71,66,79,85,78,84,89))>'
  payloads:
    - <script>alert("XSS")</script>
    - <img src="x" onerror="alert('XSS')">
    - <body onload="alert('XSS')">
    - <svg onload="alert('XSS')">
    # ... 911+ more payloads
```

### Excluded Extensions

Configure file extensions to exclude from scanning (same as KeyHunter).

## How Reflection Detection Works

1. **URL Modification**: All GET parameters are replaced with the XSS payload
2. **HTTP Request**: The modified URL is fetched using `httpx`
3. **Content Check**: The response content is checked for payload presence
4. **Confirmation**: If payload is found, it's marked as a confirmed XSS vulnerability

## Output

Results are stored in SQLite databases:

- **Main Database**: `output/bughunter.db` (default)
- **Per-Domain Database**: `output/bughunter_{domain}.db` (optional)

**Database Tables:**
- `xss_findings` - Detected XSS vulnerabilities (url_id, payload, parameter, severity, notes)
- `urls` - Scanned URLs with status codes and content types
- `subdomains` - Discovered subdomains

**Accessing Results:**
- **Web Dashboard**: View findings at http://127.0.0.1:5000
- **SQLite**: `sqlite3 output/bughunter.db` → `SELECT * FROM xss_findings;`

## Examples

### Example 1: Scan a Domain
```bash
python3 BugHunterArsenal.py -d example.com --tool xsshunter
```

### Example 2: Test Specific URLs
```bash
python3 BugHunterArsenal.py -l urls.txt --tool xsshunter --no-subs
```

### Example 3: Authenticated Scan
```bash
python3 BugHunterArsenal.py -d example.com \
  --cookie "session=abc123" \
  --x-request-for "YourName" \
  --tool xsshunter
```

## Best Practices

1. **Reuse URLs**: After scanning with KeyHunter, reuse URLs for XSS testing without re-crawling
2. **Custom Payloads**: Add domain-specific payloads if standard ones don't work
3. **Review Findings**: Manually verify XSS findings to ensure they're exploitable
4. **Parameter Coverage**: The tool tests all parameters at once, ensuring comprehensive coverage
5. **Combine with Other Tools**: Run XSSHunter alongside other tools for comprehensive vulnerability assessment

## Related Documentation

- [Main README](../README.md)
- [BugHunter Arsenal Documentation](../README.md#documentation)
