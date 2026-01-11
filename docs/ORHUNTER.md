# ORHunter - Open Redirect Vulnerability Scanner

## Overview

ORHunter is a specialized security scanning tool designed to detect open redirect vulnerabilities in web applications. It tests URL parameters for redirect behavior and validates if redirects can be abused.

## Features

- **Redirect Detection**: Tests URL parameters for open redirect vulnerabilities
- **Automatic Parameter Testing**: Automatically extracts and tests all GET parameters
- **Redirect Validation**: Validates redirect destinations for potential abuse
- **Simple Payload**: Uses a simple, effective redirect payload (`https://google.com`)
- **Useful for Chaining**: Great for SSRF chains and social engineering attacks

## How It Works

1. **URL Collection**: Collects URLs from subdomains or a provided URL list
2. **Parameter Extraction**: Automatically extracts all GET parameters from each URL
3. **Payload Injection**: Replaces all parameters with a redirect payload
4. **Redirect Detection**: Checks if the final URL after redirects starts with the payload
5. **Finding Storage**: Stores confirmed open redirect vulnerabilities in the database

## Usage

### Basic Usage

**Scan a single domain:**
```bash
python3 BugHunterArsenal.py -d example.com --tool orhunter
```

**Scan multiple domains from a file:**
```bash
python3 BugHunterArsenal.py -f domains.txt --tool orhunter
```

**Scan URLs directly:**
```bash
python3 BugHunterArsenal.py -l urls.txt --tool orhunter
```

**Disable subdomain enumeration:**
```bash
python3 BugHunterArsenal.py -d example.com --tool orhunter --no-subs
```

### Advanced Options

**Add authentication cookie:**
```bash
python3 BugHunterArsenal.py -d example.com --cookie "session=abc123" --tool orhunter
```

**Add custom header:**
```bash
python3 BugHunterArsenal.py -d example.com --x-request-for "HackerOne" --tool orhunter
```

**Use custom output directory:**
```bash
python3 BugHunterArsenal.py -d example.com -o my_results --tool orhunter
```

**Force restart:**
```bash
python3 BugHunterArsenal.py -d example.com --restart --tool orhunter
```

**Enable verbose output:**
```bash
python3 BugHunterArsenal.py -d example.com -v --tool orhunter
```

## Configuration

### Redirect Payload

ORHunter uses a simple redirect payload: `https://google.com`

This payload is effective because:
- Google.com is a well-known, safe destination
- It's unlikely to be whitelisted by applications
- It clearly demonstrates open redirect behavior

### Excluded Extensions

Configure file extensions to exclude from scanning (same as KeyHunter and XSSHunter).

## How Redirect Detection Works

1. **URL Modification**: All GET parameters are replaced with the redirect payload
2. **HTTP Request**: The modified URL is fetched using `httpx` (with redirect following enabled)
3. **Final URL Check**: The final URL after redirects is checked
4. **Confirmation**: If the final URL starts with the payload, it's marked as an open redirect vulnerability

## Use Cases

Open redirect vulnerabilities can be exploited for:

- **SSRF Chains**: Redirect internal requests to attacker-controlled domains
- **Social Engineering**: Create convincing phishing links that appear to be from trusted domains
- **Bypass Security Controls**: Redirect users past security warnings or filters
- **OAuth Abuse**: Redirect OAuth callbacks to attacker-controlled endpoints

## Output

Results are stored in SQLite databases:

- **Main Database**: `output/bughunter.db` (default)
- **Per-Domain Database**: `output/bughunter_{domain}.db` (optional)

**Database Tables:**
- `redirect_findings` - Detected open redirect vulnerabilities (url_id, parameter, redirect_url, severity, notes)
- `urls` - Scanned URLs with status codes and content types
- `subdomains` - Discovered subdomains

**Accessing Results:**
- **Web Dashboard**: View findings at http://127.0.0.1:5000
- **SQLite**: `sqlite3 output/bughunter.db` → `SELECT * FROM redirect_findings;`

## Examples

### Example 1: Scan a Domain
```bash
python3 BugHunterArsenal.py -d example.com --tool orhunter
```

### Example 2: Test Specific URLs
```bash
python3 BugHunterArsenal.py -l urls.txt --tool orhunter --no-subs
```

### Example 3: Authenticated Scan
```bash
python3 BugHunterArsenal.py -d example.com \
  --cookie "session=abc123" \
  --x-request-for "YourName" \
  --tool orhunter
```

## Best Practices

1. **Combine with Other Tools**: Run ORHunter alongside XSSHunter and KeyHunter for comprehensive testing
2. **Reuse URLs**: After scanning with KeyHunter, reuse URLs for redirect testing
3. **Manual Verification**: Test confirmed findings manually to verify exploitability
4. **Check Context**: Consider the context where redirects occur (login pages, OAuth, etc.)
5. **Document Exploitation**: Document how redirects can be chained with other vulnerabilities

## Related Documentation

- [Main README](../README.md)
- [BugHunter Arsenal Documentation](../README.md#documentation)
