# Changelog

All notable changes to BugHunter Arsenal will be documented in this file.

## [1.0.0] - 2025-01-11

### Initial Release

**BugHunter Arsenal** - A comprehensive, unified security scanning platform that wraps around multiple specialized security tools.

#### Available Tools
- **KeyHunter**: API key detection and validation from 50+ providers
- **XSSHunter**: Reflected XSS vulnerability scanner with 911+ payloads
- **ORHunter**: Open redirect vulnerability scanner
- **DTOHunter**: Subdomain takeover detection scanner

#### Platform Features
- Unified web dashboard for managing all scans
- Database-backed storage with SQLite
- Multi-tool support - run multiple tools simultaneously
- Rescan capabilities (rescan, recrawl, rediscover)
- Configuration management via web UI
- Real-time scan monitoring
- Checkpoint system for resuming scans
- Per-domain database support for large targets

---

## [2.0.0] - PREVIOUS (Removed - Reset to v1.0.0)

### Major Changes
- **Complete project reorganization**: Restructured codebase into logical directories
  - `keyhunter/` - Main source code module
  - `web/` - Web GUI files (dashboard, logo)
  - `config/` - Configuration files (API patterns, excluded extensions)
  - `docs/` - Documentation files
  - Entry point script (`KeyHunter.py`) in root for easy execution
- **Improved code organization**: Better separation of concerns and maintainability
- **Module-based architecture**: Code now organized as a proper Python package
- **Enhanced Web GUI**: Comprehensive dashboard with real-time monitoring, scan management, and configuration

### Added
- **Web Dashboard Features**:
  - Standalone HTML dashboard (`dashboard.html`) with full scan management
  - Currently running scans card on dashboard with duration tracking and stop buttons
  - Clickable running scans to view real-time output in modal
  - Loading spinner indicators for active scans
  - Stop button confirmation dialogs for safety
  - Rerun functionality for errored or failed scans
  - Individual and bulk scan deletion with confirmation
  - Scan history with checkboxes for bulk operations
  - Targets page showing all domains, subdomains, URLs, and findings in hierarchical view
  - Export functionality (CSV, JSON, TXT) with scope selection (all targets, selected target, selected subdomain)
  - Settings page for editing YAML configuration files
  - About page with tool information, developer details, and support links
  - Compact Quick Filters in sidebar (icon buttons)
  - Highlighted "New Scan" button in navigation
  - Local timezone display for all timestamps
  - Real-time scan output streaming with Server-Sent Events (SSE)
  - Persistent scan sessions (scans continue after page reload)
- **Backend Improvements**:
  - SQLite WAL (Write-Ahead Logging) mode for better concurrency
  - Database retry logic with exponential backoff for handling locks
  - API endpoints for targets and export functionality
  - API endpoints for config file management (read/write with YAML validation)
  - Automatic backup creation before config file saves
  - Improved timestamp handling with UTC storage and local timezone display
  - Better error handling for scan output reading
- **Configuration Management**:
  - Form-based editor for excluded extensions (tag interface)
  - YAML text editor for API patterns (direct editing)
  - YAML syntax validation before saving
  - Reset functionality to revert unsaved changes
- `-o` / `--output` flag to specify custom output directory name
- Interactive dashboard with copy-to-clipboard functionality for API keys
- Statistics dashboard showing URLs scanned, keys found, and providers detected across all scans
- Responsive design optimized for desktop and mobile viewing
- Organized folder structure for output files
- Automatic Go installation if not present (via apt-get)
- Automatic binary management: moves Go binaries from `~/go/bin/` to `/usr/bin/` after installation
- Support for custom binary path via `KEYHUNTER_BIN_PATH` environment variable

### Changed
- Enhanced output organization with custom directory support
- Improved dependency installation: all tools now installed via Go (removed apt-get fallback for tools)
- Only Go itself is installed via apt-get; all security tools use Go installation
- Enhanced installation process with better error handling and feedback
- Removed HTML generation from Python code; now uses standalone dashboard file
- Updated all path references to work with new project structure
- Improved import structure for better code organization
- Currently running scans card automatically hidden when no scans are active
- Quick Filters made more compact to save sidebar space
- Navigation reorganized (About moved to header, New Scan highlighted)

### Fixed
- Fixed database schema initialization (scans, urls, api_keys tables)
- Fixed scan execution path (KeyHunter.py → Keyhunter.py)
- Fixed timezone display issues (now shows local timezone correctly)
- Fixed scan status detection (no longer marks completed scans as error)
- Fixed spinner animation glitches during polling
- Fixed database locking issues with WAL mode and retry logic
- Fixed YAML parsing for nested API patterns (Laravel Environment Variables)
- Fixed quote handling in config form (no more truncation)

## [1.2.0] - Previous

### Added
- Added katana integration for enhanced URL crawling with JavaScript crawling support
- Added `--install` / `--setup` flag for automatic dependency installation (requires sudo)
- Added `-l` / `--urls-file` flag to scan URLs directly from a file (skips domain enumeration)
- Improved httpx error handling with comprehensive error diagnostics
- Enhanced verbose mode to show actual httpx commands and full error output
- URL validation improvements to catch malformed URLs early

### Changed
- Improved dependency checking to only announce missing tools
- Enhanced error messages for better debugging

### Fixed
- Fixed httpx integration issue where errors were not being captured or displayed
- Fixed "Unknown error" messages by properly checking both stdout and stderr
- Fixed dependency installation flow to exit gracefully after successful installation

## [1.1.9] - Previous

### Changed
- Enhanced API key search functionality to eliminate duplicates
- Improved result output formatting

### Added
- Added new API key patterns for JWT and RSA Private Key
- Added React App environment variable pattern

### Fixed
- Refined Firebase and Generic API Key patterns for improved accuracy
- Removed Twitter access token patterns

## [1.1.8] - Previous

### Changed
- Refactored API key storage structure
- Updated result saving logic

## [1.1.7] - Previous

### Changed
- Improved URL fetching by streaming response content

### Added
- Added Shopify API tokens support

## Previous Versions

### Added
- Support for custom headers (X-Request-For)
- Cookie authentication support
- Random User-Agent rotation
- Multiple domain support from file
- Subdomain enumeration with subfinder
- Wayback Machine URL collection
- Asynchronous URL processing
- YAML-based API key pattern configuration

### Changed
- Update process now uses git reset instead of pull
- Improved API token pattern matching

