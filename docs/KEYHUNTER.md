# KeyHunter - API Key Detection & Validation Tool

## Overview

KeyHunter is a specialized security scanning tool designed to detect and validate exposed API keys and secrets from web applications. It scans domains, subdomains, and URLs to identify potential API key leaks using customizable regex patterns.

## Features

- **Wide Provider Coverage**: Detects API keys from **50+ providers** using customizable regex patterns
- **Real-time Validation**: Validates discovered keys using the [keyhacks](https://github.com/streaak/keyhacks) repository
- **Automatic Categorization**: Categorizes findings as Valid ✓, Invalid ✗, or Manual Review ?
- **Subdomain Enumeration**: Optional subdomain discovery using `subfinder`
- **URL Collection**: Combines Wayback Machine archives and active crawling with `katana`
- **Custom Patterns**: Easy addition of new provider patterns via database configuration

## Supported Providers

KeyHunter detects and validates API keys from the following providers (33+ with automatic validation):

**Cloud & Infrastructure:**
- AWS Access Keys ✓
- Amazon MWS Token ✓
- Alibaba Cloud ✓
- Microsoft Azure ✓
- Heroku ✓
- Vercel ✓

**Version Control & CI/CD:**
- GitHub Token ✓
- GitLab PAT ✓
- GitLab CI/CD ✓

**Communication & Collaboration:**
- Slack Token ✓
- Slack Webhook ✓
- Discord Webhook ✓
- Telegram ✓

**Payment & E-commerce:**
- Stripe ✓
- Square Token ✓
- Square Secret ✓
- PayPal Braintree ✓
- Shopify ✓

**Email & Marketing:**
- SendGrid ✓
- Mailgun ✓
- MailChimp ✓

**Other Services:**
- Twilio ✓
- NPM Token ✓
- Dropbox ✓
- Mapbox ✓
- Postman ✓
- Cloudinary ✓
- Facebook Token ✓
- Facebook OAuth ✓
- OpenAI ✓
- Grafana API ✓
- Grafana Service Account Token ✓
- Instagram ✓
- Picatic ✓

**Manual Validation Required:**
- Cloudinary (URL-based)
- Firebase (URL, Bucket, Database)
- PGP Private Key
- Generic API Key
- Generic Secret
- Google OAuth
- OAuth2 Bearer
- Laravel ENV
- React App ENV
- URL Password
- JWT

## Usage

### Basic Usage

**Scan a single domain:**
```bash
python3 BugHunterArsenal.py -d example.com --tool keyhunter
```

**Scan multiple domains from a file:**
```bash
python3 BugHunterArsenal.py -f domains.txt --tool keyhunter
```

**Scan URLs directly** (skip subdomain enumeration):
```bash
python3 BugHunterArsenal.py -l urls.txt --tool keyhunter
```

**Disable subdomain enumeration:**
```bash
python3 BugHunterArsenal.py -d example.com --tool keyhunter --no-subs
```

### Advanced Options

**Add authentication cookie:**
```bash
python3 BugHunterArsenal.py -d example.com --cookie "session=abc123" --tool keyhunter
```

**Add custom header** (for bug bounty programs):
```bash
python3 BugHunterArsenal.py -d example.com --x-request-for "HackerOne" --tool keyhunter
```

**Use custom output directory:**
```bash
python3 BugHunterArsenal.py -d example.com -o my_results --tool keyhunter
```

**Force restart** (delete existing scan and start fresh):
```bash
python3 BugHunterArsenal.py -d example.com --restart --tool keyhunter
```

**Enable verbose output:**
```bash
python3 BugHunterArsenal.py -d example.com -v --tool keyhunter
```

## Configuration

### API Patterns

KeyHunter uses regex patterns stored in the database to detect API keys. Patterns can be managed through:

1. **Web UI**: Settings page → API Patterns tab
2. **YAML File**: `config/api_patterns.yaml` (auto-synced to database)

**Example Pattern:**
```yaml
api_keys:
  aws:
    - "AKIA[0-9A-Z]{16}"
  github:
    - "ghp_[a-zA-Z0-9]{36}"
    - "github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}"
```

### Excluded Extensions

Configure file extensions to exclude from scanning via Settings page or `config/excluded_extensions.yaml`.

**Example:**
```yaml
excluded_extensions:
  - .jpg
  - .png
  - .css
  - .js
  - .svg
  - .woff
```

## Validation Status

Each API key finding includes a `validation_status` field:

- **`valid`**: The API key is active and functional (automatically verified)
- **`invalid`**: The API key is inactive or incorrect (automatically verified)
- **`manual`**: Requires manual validation (provider not supported or requires additional context)

Validation is performed in real-time using API endpoints from the [keyhacks](https://github.com/streaak/keyhacks) repository.

## Output

Results are stored in SQLite databases:

- **Main Database**: `output/bughunter.db` (default)
- **Per-Domain Database**: `output/bughunter_{domain}.db` (optional, for large targets)

**Database Tables:**
- `api_keys` - Detected API keys with metadata (provider, key, validation_status, severity, notes)
- `urls` - Scanned URLs with status codes and content types
- `subdomains` - Discovered subdomains

**Accessing Results:**
- **Web Dashboard**: View findings at http://127.0.0.1:5000
- **SQLite**: `sqlite3 output/bughunter.db` → `SELECT * FROM api_keys WHERE provider = 'aws';`

## Examples

### Example 1: Scan a Domain
```bash
python3 BugHunterArsenal.py -d example.com --tool keyhunter
```

### Example 2: Authenticated Scan
```bash
python3 BugHunterArsenal.py -d example.com \
  --cookie "session=abc123" \
  --x-request-for "YourName" \
  --tool keyhunter
```

### Example 3: Scan Specific URLs
```bash
python3 BugHunterArsenal.py -l urls.txt --tool keyhunter --no-subs
```

## Best Practices

1. **Start with Subdomain Enumeration**: Let KeyHunter discover subdomains first for maximum coverage
2. **Custom Patterns**: Add provider-specific patterns for services you commonly encounter
3. **Review Validation Status**: Focus on `valid` findings, but don't ignore `manual` ones
4. **False Positive Flagging**: Use the dashboard to mark false positives for better organization
5. **Rescan Capabilities**: Reuse collected URLs for other tools without re-crawling

## Related Documentation

- [Main README](../README.md)
- [BugHunter Arsenal Documentation](../README.md#documentation)
