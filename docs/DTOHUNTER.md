# DTOHunter - Subdomain Takeover Detection Scanner

## Overview

DTOHunter is a specialized security scanning tool designed to detect subdomain takeover vulnerabilities. It checks subdomains for potential takeover using fingerprinting from the [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) repository.

## Features

- **Fingerprint-Based Detection**: Uses proven fingerprints from can-i-take-over-xyz
- **Vulnerable-Only Scanning**: Only checks fingerprints marked as vulnerable
- **Automatic Updates**: Always checks online repository for updates and stores local copy
- **DNS Resolution**: Checks CNAME records and NXDOMAIN responses
- **HTTP Fingerprinting**: Validates fingerprints against actual response content
- **Deduplication**: Only scans unique subdomains to avoid redundant checks

## How It Works

1. **Fingerprint Loading**: Fetches fingerprints from online repository (with local cache fallback)
2. **Subdomain Collection**: Collects subdomains from `subfinder` or provided list
3. **DNS Checks**: Resolves CNAME records and checks for NXDOMAIN
4. **Fingerprint Matching**: Validates fingerprints against HTTP response content
5. **Finding Storage**: Stores confirmed takeover vulnerabilities in the database

## Supported Services

DTOHunter checks for takeover vulnerabilities in services such as:

- GitHub Pages
- Heroku
- Shopify
- Fastly
- AWS S3
- Microsoft Azure
- Vercel
- And many more (see [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz))

Only services marked as **vulnerable** in the fingerprints are checked.

## Usage

### Basic Usage

**Scan a single domain:**
```bash
python3 BugHunterArsenal.py -d example.com --tool dtohunter
```

**Scan multiple domains from a file:**
```bash
python3 BugHunterArsenal.py -f domains.txt --tool dtohunter
```

**Note**: DTOHunter only works with domains, not URL lists. It focuses on subdomain takeover, so it needs domain/subdomain enumeration.

### Advanced Options

**Add authentication cookie:**
```bash
python3 BugHunterArsenal.py -d example.com --cookie "session=abc123" --tool dtohunter
```

**Add custom header:**
```bash
python3 BugHunterArsenal.py -d example.com --x-request-for "HackerOne" --tool dtohunter
```

**Use custom output directory:**
```bash
python3 BugHunterArsenal.py -d example.com -o my_results --tool dtohunter
```

**Force restart:**
```bash
python3 BugHunterArsenal.py -d example.com --restart --tool dtohunter
```

**Enable verbose output:**
```bash
python3 BugHunterArsenal.py -d example.com -v --tool dtohunter
```

## Configuration

### Fingerprints

DTOHunter uses fingerprints from the [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) repository:

- **Online Source**: `https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/refs/heads/master/fingerprints.json`
- **Local Cache**: `config/takeover_fingerprints.json` (automatically updated)

The tool:
1. Always attempts to fetch the latest fingerprints from the online repository
2. Stores them locally for backup if the repository becomes unavailable
3. Filters for only `vulnerable: true` fingerprints

**Example Fingerprint:**
```json
{
  "service": "github",
  "cname": ["github.io", "github.map.fastly.net"],
  "nxdomain": true,
  "vulnerable": true,
  "fingerprint": "There isn't a GitHub Pages site here."
}
```

## How Takeover Detection Works

1. **CNAME Resolution**: Resolves CNAME records for the subdomain
2. **NXDOMAIN Check**: Checks if the subdomain returns NXDOMAIN
3. **HTTP Check**: Fetches the HTTP response from the subdomain
4. **Fingerprint Matching**: Compares response content against fingerprint text
5. **Confirmation**: If all conditions match, marks as a takeover vulnerability

## Prerequisites

DTOHunter requires `dnspython` for DNS resolution:

```bash
pip install dnspython
```

## Output

Results are stored in SQLite databases:

- **Main Database**: `output/bughunter.db` (default)
- **Per-Domain Database**: `output/bughunter_{domain}.db` (optional)

**Database Tables:**
- `takeover_findings` - Detected subdomain takeover vulnerabilities (subdomain_id, service, fingerprint, cname, severity, notes)
- `subdomains` - Discovered subdomains
- `urls` - Collected URLs (if URL collection was performed)

**Accessing Results:**
- **Web Dashboard**: View findings at http://127.0.0.1:5000
- **SQLite**: `sqlite3 output/bughunter.db` → `SELECT * FROM takeover_findings;`

## Examples

### Example 1: Scan a Domain
```bash
python3 BugHunterArsenal.py -d example.com --tool dtohunter
```

### Example 2: Scan Multiple Domains
```bash
python3 BugHunterArsenal.py -f domains.txt --tool dtohunter
```

### Example 3: Authenticated Scan
```bash
python3 BugHunterArsenal.py -d example.com \
  --cookie "session=abc123" \
  --x-request-for "YourName" \
  --tool dtohunter
```

## Best Practices

1. **Domain Focus**: DTOHunter only works with domains/subdomains, not URLs
2. **Subdomain Enumeration**: Ensure subdomain enumeration is enabled for best results
3. **Verify Findings**: Manually verify takeover vulnerabilities before reporting
4. **Combine with Recon**: Use alongside other tools for comprehensive subdomain assessment
5. **Monitor Updates**: The tool automatically updates fingerprints, but monitor the can-i-take-over-xyz repository for new services

## Related Documentation

- [Main README](../README.md)
- [BugHunter Arsenal Documentation](../README.md#documentation)
