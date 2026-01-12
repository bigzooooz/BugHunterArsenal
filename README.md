<a href="https://paypal.me/b4zb0z"><img src="https://shields.io/badge/paypal-Support_on_Paypal-blue?logo=paypal&style=for-the-badge" /></a> 
<a href="https://ko-fi.com/s/cb4c85e80b"><img src="https://shields.io/badge/KoFi-Buy_Me_a_coffee-blue?logo=ko-fi&style=for-the-badge" /></a>

---

<div align="center">
  <img src="web/logo.png" alt="BugHunter Arsenal Logo" width="200">
  <h1>BugHunter Arsenal</h1>
  <p><strong>Multi-Tool Security Scanning Platform for Bug Bounty Hunters</strong></p>
  <p>Current Version: <strong>v1.2.0</strong> · <a href="docs/CHANGELOG.md">Changelog</a></p>
</div>

---

## 📖 Overview

**BugHunter Arsenal** is a comprehensive, unified security scanning platform designed for bug bounty hunters and security researchers. It provides a single interface to run multiple specialized security tools simultaneously, making vulnerability discovery more efficient and organized.

Unlike standalone security tools, BugHunter Arsenal orchestrates multiple scanners through a unified web dashboard and command-line interface, allowing you to discover vulnerabilities across different attack vectors in parallel.

---

## 🛠️ Available Tools

BugHunter Arsenal currently includes four specialized security scanning tools:

### 🔑 [KeyHunter](docs/KEYHUNTER.md)
**API Key Detection & Validation** - Scans domains, subdomains, and URLs for exposed API keys and secrets from 50+ providers with real-time validation. Automatically categorizes findings as Valid ✓, Invalid ✗, or Manual Review ?.

### 🎯 [XSSHunter](docs/XSSHUNTER.md)
**Reflected Cross-Site Scripting (XSS) Vulnerability Scanner** - Detects XSS vulnerabilities in URL parameters by testing all GET parameters simultaneously with 911+ customizable payloads. Checks for payload reflection in response content.

### 🔄 [ORHunter](docs/ORHUNTER.md)
**Open Redirect Vulnerability Scanner** - Identifies open redirect vulnerabilities in web applications by testing URL parameters for redirect behavior. Useful for SSRF chains and social engineering attacks.

### 🎯 [DTOHunter](docs/DTOHUNTER.md)
**Subdomain Takeover Detection Scanner** - Detects vulnerable subdomains that can be taken over using fingerprinting from can-i-take-over-xyz. Checks CNAME records, NXDOMAIN responses, and service fingerprints.


---

## ✨ Key Features

### 🎛️ Unified Web Dashboard
- **Interactive GUI**: Manage all scans from a single web interface
- **Real-time Monitoring**: Live scan output streaming with Server-Sent Events (SSE)
- **Findings Management**: Full CRUD operations for organizing vulnerabilities
- **Multi-Tool Support**: Run multiple tools simultaneously on the same targets
- **Rescan Capabilities**: Reuse collected URLs with new parameters (rescan, recrawl, rediscover)

### 🗄️ Database-Backed Storage
- **SQLite Database**: All scan results stored in organized databases
- **Per-Domain Databases**: Separate database files for each target (optional)
- **Findings Tracking**: Severity levels, verification status, false positive flagging
- **Scan History**: Complete audit trail of all scanning activities
- **Checkpoint System**: Resume interrupted scans from the last checkpoint

### ⚙️ Advanced Configuration
- **Database-Backed Configs**: Manage API patterns, excluded extensions, and payloads through the web UI
- **Settings Management**: Add, edit, delete, and restore configuration items
- **YAML Sync**: Automatic synchronization from YAML config files to database
- **Soft Deletes**: Preserve user customizations when syncing from YAML
- **Custom Patterns**: Easy addition of new detection patterns and payloads

### 🔄 Flexible Scanning Options
- **Resume Support**: Automatically resumes incomplete scans by default
- **Force Restart**: Option to start fresh scans when needed
- **URL Reuse**: Reuse collected URLs for different tool scans without re-crawling
- **Subdomain Enumeration**: Optional subdomain discovery using `subfinder`
- **Multiple Input Formats**: Scan domains, files of domains, or direct URL lists

### 🔐 Authentication & Headers
- **Cookie Support**: Authenticate with protected endpoints
- **Custom Headers**: Add X-Request-For and other custom headers for bug bounty programs
- **Random User-Agents**: Automatically rotates user agents to avoid detection

---

## 📦 Installation

### Prerequisites

- **Python 3.7+**
- **Go** (for installing external tools)
- External tools: `subfinder`, `waybackurls`, `katana`, `httpx`

### Step-by-Step Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/bigzooooz/BugHunterArsenal.git
   cd BugHunterArsenal
   ```

2. **Install Python Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Install External Tools**:
   
   **Option A: Automatic Installation** (recommended, requires sudo):
   ```bash
   sudo python3 BugHunterArsenal.py --install
   ```
   
   **Option B: Manual Installation**:
   ```bash
   go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
   go install github.com/tomnomnom/waybackurls@latest
   go install github.com/projectdiscovery/httpx/cmd/httpx@latest
   go install github.com/projectdiscovery/katana/cmd/katana@latest
   ```
   
   Make sure the Go binaries are in your PATH.

4. **Verify Installation**:
   ```bash
   python3 BugHunterArsenal.py --version
   ```

---

## 🚀 Usage

### Command Line Interface

#### Basic Scanning

**Scan a single domain with KeyHunter** (default tool):
```bash
python3 BugHunterArsenal.py -d example.com
```

**Scan with a specific tool**:
```bash
python3 BugHunterArsenal.py -d example.com --tool xsshunter
```

**Scan multiple domains from a file**:
```bash
python3 BugHunterArsenal.py -f domains.txt --tool keyhunter
```

**Scan URLs directly** (skip subdomain enumeration):
```bash
python3 BugHunterArsenal.py -l urls.txt --tool xsshunter
```

**Run multiple tools simultaneously**:
```bash
python3 BugHunterArsenal.py -d example.com --tool keyhunter,xsshunter,orhunter
```

#### Advanced Options

**Disable subdomain enumeration**:
```bash
python3 BugHunterArsenal.py -d example.com --no-subs --tool keyhunter
```

**Use custom output directory**:
```bash
python3 BugHunterArsenal.py -d example.com -o my_results --tool xsshunter
```

**Add authentication cookie**:
```bash
python3 BugHunterArsenal.py -d example.com --cookie "session=abc123" --tool keyhunter
```

**Add custom header** (for bug bounty programs):
```bash
python3 BugHunterArsenal.py -d example.com --x-request-for "HackerOne" --tool xsshunter
```

**Force restart** (delete existing scan and start fresh):
```bash
python3 BugHunterArsenal.py -d example.com --restart --tool keyhunter
```

**Enable verbose output**:
```bash
python3 BugHunterArsenal.py -d example.com -v --tool keyhunter
```

### Web GUI Dashboard

**Start the web dashboard**:
```bash
python3 BugHunterArsenal.py --gui
```

Then open **http://127.0.0.1:5000** in your browser.

#### Dashboard Features

- **Target Management**: Add, view, and manage scanning targets
- **Scan Wizard**: Interactive interface for configuring and starting scans
- **Live Monitoring**: Real-time output from running scans
- **Findings Management**: View, edit, verify, and organize discovered vulnerabilities
- **Settings Page**: Manage API patterns, excluded extensions, and XSS payloads
- **Statistics Dashboard**: Overview of scans, findings, and subdomains
- **Export Functionality**: Export findings in various formats

#### Rescan Options

From the target details page, you can:

- **🔍 Re-scan URLs**: Reuse existing URLs with new tool parameters (skip subdomain enum and URL collection)
- **🕷️ Re-crawl URLs**: Keep subdomains, re-collect URLs from existing subdomains
- **🌐 Re-discover**: Fresh start with same parameters (re-enumerate subdomains and crawl)

---

## 📖 Documentation

Detailed documentation for each tool is available in the [docs/](docs/) directory:

- **[KeyHunter Documentation](docs/KEYHUNTER.md)** - API key detection and validation guide
- **[XSSHunter Documentation](docs/XSSHUNTER.md)** - XSS vulnerability scanning guide
- **[ORHunter Documentation](docs/ORHUNTER.md)** - Open redirect scanning guide
- **[DTOHunter Documentation](docs/DTOHUNTER.md)** - Subdomain takeover detection guide

For tool-specific features, usage examples, configuration options, and best practices, see the individual tool documentation files.

---

## 🛠️ Command-Line Options

### Tool Selection
- `--tool TOOL_NAME` - Specify tool(s) to run (comma-separated). Options: `keyhunter`, `xsshunter`, `xss`, `orhunter`, `openredirect`, `redirect`, `dtohunter`, `takeover`. Default: `keyhunter`

### Scanning Options
- `-d, --domain DOMAIN` - Target domain to scan
- `-f, --file FILE` - File containing list of domains to scan
- `-l, --urls-file FILE` - File containing list of URLs to scan directly (skips subdomain enumeration)
- `-ns, --no-subs` - Disable subdomain enumeration
- `-o, --output DIR` - Custom output directory name (default: `output`)

### Authentication & Headers
- `--cookie COOKIE` - Cookie string for authenticated requests
- `--x-request-for HEADER` - Custom X-Request-For header value

### Scan Control
- `--restart` - Force restart: delete existing scan and start fresh (default: resumes from checkpoint)
- `-v, --verbose` - Enable verbose output

### System Options
- `--gui` - Start the web dashboard GUI server
- `--install, --setup` - Install missing dependencies automatically (requires sudo)
- `--update` - Update BugHunter Arsenal to the latest version
- `--version` - Display version information

---

## ⚙️ Configuration

### Settings Management (Web UI)

Access the Settings page from the dashboard to manage:

1. **API Patterns**: Add, edit, or delete API key detection patterns
2. **Excluded Extensions**: Manage file extensions to exclude from scanning
3. **XSS Payloads**: Manage XSS payloads, set default payload, add custom payloads

All configurations are stored in the database and automatically synced from YAML files on startup.

### YAML Configuration Files

Configuration files in `config/` are automatically synced to the database:

- **`config/api_patterns.yaml`**: API key detection patterns
- **`config/excluded_extensions.yaml`**: File extensions to exclude
- **`config/xss_payloads.yaml`**: XSS payloads (911+ payloads included)

### Database Structure

Results are stored in SQLite databases:

- **Main Database**: `output/bughunter.db` (default)
- **Per-Domain Databases**: `output/bughunter_{domain}.db` (optional, for large targets)

**Database Tables**:
- `scans` - Scan metadata and checkpoints
- `subdomains` - Discovered subdomains
- `urls` - Collected URLs with status codes
- `api_keys` - API key findings (KeyHunter)
- `xss_findings` - XSS vulnerability findings (XSSHunter)
- `redirect_findings` - Open redirect findings (ORHunter)
- `takeover_findings` - Subdomain takeover findings (DTOHunter)
- `config_api_patterns` - API pattern configurations
- `config_excluded_extensions` - Excluded extension configurations
- `config_xss_payloads` - XSS payload configurations

---

## 📁 Project Structure

```
BugHunterArsenal/
├── BugHunterArsenal.py      # Main entry point
├── requirements.txt         # Python dependencies
├── version.txt             # Version information
│
├── tools/                   # Security scanning tools
│   ├── keyhunter/          # API key detection tool
│   ├── xsshunter/          # XSS vulnerability scanner
│   ├── orhunter/           # Open redirect scanner
│   └── dtohunter/          # Subdomain takeover scanner
│
├── bughunter/              # Core platform modules
│   ├── server.py           # Flask web server
│   ├── database.py         # Database operations
│   ├── config_migration.py # Config sync to database
│   ├── recon.py            # Reconnaissance utilities
│   └── http_client.py      # HTTP client utilities
│
├── web/                    # Web dashboard
│   ├── dashboard.html      # Main dashboard UI
│   └── logo.png            # Logo image
│
├── config/                 # Configuration files
│   ├── api_patterns.yaml
│   ├── excluded_extensions.yaml
│   ├── xss_payloads.yaml
│   └── takeover_fingerprints.json
│
├── output/                 # Scan results (databases)
├── docs/                   # Documentation
│   ├── CHANGELOG.md        # Version history
│   ├── KEYHUNTER.md        # KeyHunter detailed guide
│   ├── XSSHUNTER.md        # XSSHunter detailed guide
│   ├── ORHUNTER.md         # ORHunter detailed guide
│   └── DTOHUNTER.md        # DTOHunter detailed guide
└── README.md               # This file
```

---

## 📊 Quick Start Examples

### Basic Scanning
```bash
# Scan a domain with KeyHunter (default tool)
python3 BugHunterArsenal.py -d example.com

# Run multiple tools simultaneously
python3 BugHunterArsenal.py -d example.com --tool keyhunter,xsshunter,orhunter,dtohunter

# Test specific URLs (skip subdomain enumeration)
python3 BugHunterArsenal.py -l urls.txt --tool xsshunter --no-subs
```

### Authenticated Scanning
```bash
# Scan with authentication
python3 BugHunterArsenal.py -d example.com \
  --cookie "session=abc123" \
  --x-request-for "YourName" \
  --tool keyhunter,xsshunter
```

---

## 🔍 Accessing Results

### Via Web Dashboard
- Navigate to http://127.0.0.1:5000
- View findings in the "Findings Management" section
- Filter by tool, severity, verification status, or domain
- Export findings as JSON, CSV, or text

### Via SQLite
```bash
sqlite3 output/bughunter.db

# View findings by type
SELECT * FROM api_keys WHERE provider = 'aws';
SELECT * FROM xss_findings;
SELECT * FROM redirect_findings;
SELECT * FROM takeover_findings;
```

---

## 🐛 Troubleshooting

### External Tools Not Found
```bash
# Install missing tools
sudo python3 BugHunterArsenal.py --install

# Or manually add Go binaries to PATH
export PATH=$PATH:$(go env GOPATH)/bin
```

### Database Locked Errors
- Ensure no other instances are accessing the database
- Close the web dashboard if accessing via SQLite directly
- Wait for current scan operations to complete

### Scan Not Resuming
- Check if checkpoint exists in the database
- Use `--restart` flag to force a fresh start if needed

---

## 🤝 Contributing

Contributions are welcome! Whether it's:

- Adding new security scanning tools
- Improving existing tools
- Enhancing the web dashboard
- Adding new detection patterns
- Improving documentation
- Bug fixes and optimizations

Please feel free to submit issues or pull requests!

---

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## 💖 Support

If you find BugHunter Arsenal useful, consider:

1. ⭐ **Starring the repository** on GitHub
2. ☕ **Buying me a coffee** on [Ko-fi](https://ko-fi.com/s/cb4c85e80b)
3. 💸 **Supporting via PayPal** at [paypal.me/b4zb0z](https://paypal.me/b4zb0z)
4. 📢 **Sharing** with other bug bounty hunters and security researchers
5. 💡 **Providing feedback** and feature requests

---

## ⚠️ Disclaimer

**This tool is intended for educational and authorized security testing purposes only.**

- Only use on systems you own or have explicit permission to test
- Unauthorized access to computer systems is illegal
- The authors are not responsible for any misuse or damage caused by this tool
- Always comply with applicable laws and regulations
- Respect bug bounty program rules and scope limitations

---

## 🎯 Happy Hunting!

<div align="center">
  <p><strong>Good luck finding bugs! 🐛</strong></p>
  <p>Stay ethical, stay legal, and happy hunting! 🎯</p>
</div>
