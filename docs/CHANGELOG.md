# Changelog

All notable changes to BugHunter Arsenal will be documented in this file.

## [1.2.2] - 2026-02-13

### Added
- Print dashboard URL when running with `--gui` so users know where to open the browser

### Changed
- Runtime directories (`output`, `logs`, `scans`, `uploads`) are now created on first run (GUI or tool) instead of during `--install`, so they are owned by the current user and avoid permission issues

### Fixed
- 500 Internal Server Error on first load when the database was created under a different user (e.g. after `sudo --install`); runtime dirs are now created before starting the server so the app can write to the database
- Sidebar is now a responsive drawer on smaller screens (≤1024px): hamburger toggle, overlay to close, and drawer closes when navigating

## [1.2.1] - 2026-01-18

### Added
- Scan pause and resume functionality with cooldown management to prevent rapid or concurrent resume attempts
- Locking mechanism to prevent concurrent resume operations and track last resume attempt per scan
- Ability to resume scans from paused, failed, or stopped states without creating a new scan
- New API endpoint to pause scans while preserving their state for later resumption
- Automatic cleanup of old resume-attempt records to prevent memory leaks
- New `.btn-warning` button style for warning-related actions in the dashboard
- Visual `.status-paused` indicator for paused targets
- Loading indicators for APIs, URLs, and subdomains sections to improve user experience
- Grouping of findings by key value and provider in the findings table
- Bulk deletion functionality for grouped findings

### Changed
- `list_scans` behavior updated to mark dead scans as paused instead of automatically resuming them
- Target details loading optimized to fetch summary data first for improved dashboard performance

### Fixed
- Improved scan lifecycle handling to avoid unintended auto-resume behavior
- Enhanced process and state management for better reliability and control

## [1.2.0] - 2026-01-12

### Added
- Server logs page in the web dashboard for viewing and managing application logs
- Export functionality to download targets data in JSON, CSV, or TXT formats
- Process status tracking for running scans with PID and status indicators
- Automatic scan resume when processes unexpectedly terminate
- Enhanced API key detection patterns for Slack, GitHub, OpenAI, and WakaTime services

### Fixed
- Excessive API requests causing timeouts and performance issues
- Scans showing as "running" when processes had actually stopped
- Export functionality not working properly in the web dashboard
- Request polling frequency optimized to prevent server overload

### Changed
- Improved scan monitoring with better process status visibility
- Enhanced request handling with caching and queuing for better performance
- Updated API key detection rules for improved accuracy

## [1.1.0] - 2026-01-12

### Added
- Real-time output streaming for GUI scans with Server-Sent Events (SSE)
- Process reconnection feature - GUI server can reconnect to running scans after restart
- Stop scan functionality with process termination support
- Support for both subprocess.Popen and psutil.Process in scan management
- Non-blocking output reading using select() for better performance
- Centralized version management - version is now read from `version.txt` file
- API endpoint `/api/version` for fetching version dynamically in web dashboard
- Dynamic version display in web dashboard (loads from API)

### Fixed
- Real-time output display in web GUI (previously showing blank)
- Output reading blocking issues using select() with timeout
- Process termination on stop button click
- Missing select module import causing NameError
- Timeout warnings removed for long-running scans
- KeyHunter tool banner updated to show only "KeyHunter" instead of "BugHunter Arsenal"
- `loadVersion` function definition error in dashboard HTML

### Changed
- Output writer thread starts automatically on server startup
- Improved output reading logic to prevent blocking
- Enhanced stop scan function to handle both regular and reconnected processes
- `bughunter.__version__` now reads from `version.txt` instead of hardcoded value
- Web dashboard version display now loads dynamically from `/api/version` endpoint
- DTOHunter optimization - domain content is fetched once per subdomain and compared with all fingerprints (reduces HTTP requests from N to 1-2 per subdomain)
- Updated requirements.txt to include `dnspython` dependency for DTOHunter

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

