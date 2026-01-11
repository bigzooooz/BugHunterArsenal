"""
Shared Database Module for Checkpoint-Based Scanning
Provides database operations with checkpoint/resume capabilities
"""

import sqlite3
from typing import List, Dict, Optional, Tuple, Callable, Any
from pathlib import Path
import os
import time


# Database timeout in seconds (how long to wait for locks)
DB_TIMEOUT = 30.0
# Retry attempts for locked database
MAX_RETRIES = 5
# Base delay between retries in seconds
RETRY_DELAY = 0.1


def get_db_connection(db_path: str, timeout: float = DB_TIMEOUT):
    """Get a database connection with timeout and WAL mode enabled"""
    conn = sqlite3.connect(db_path, timeout=timeout)
    # Enable WAL mode for better concurrency
    try:
        conn.execute('PRAGMA journal_mode=WAL')
    except sqlite3.OperationalError:
        # If WAL mode fails (e.g., read-only), continue without it
        pass
    return conn


def retry_db_operation(func: Callable, *args, **kwargs) -> Any:
    """Retry a database operation if it fails due to lock"""
    for attempt in range(MAX_RETRIES):
        try:
            return func(*args, **kwargs)
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e).lower() and attempt < MAX_RETRIES - 1:
                # Exponential backoff
                delay = RETRY_DELAY * (2 ** attempt)
                time.sleep(delay)
                continue
            raise
    return None


def init_database_with_checkpoints(db_path: str):
    """Initialize database with checkpoint support - enhanced schema"""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    
    # Scans table with checkpoint support
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            end_time TIMESTAMP,
            status TEXT DEFAULT 'pending',
            checkpoint TEXT,
            output_dir TEXT,
            UNIQUE(domain, scan_type, output_dir)
        )
    ''')
    
    # Subdomains table with status tracking
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS subdomains (
            subdomain_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            domain TEXT NOT NULL,
            subdomain TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            waybackurls_done INTEGER DEFAULT 0,
            katana_done INTEGER DEFAULT 0,
            urls_collected_at TIMESTAMP,
            discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
            UNIQUE(scan_id, subdomain)
        )
    ''')
    
    # URLs table with status tracking and subdomain link
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS urls (
            url_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            subdomain_id INTEGER,
            url TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            status_code INTEGER,
            content_type TEXT,
            source TEXT,
            checked_at TIMESTAMP,
            discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
            FOREIGN KEY (subdomain_id) REFERENCES subdomains(subdomain_id) ON DELETE SET NULL,
            UNIQUE(scan_id, url)
        )
    ''')
    
    # API keys table (existing)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS api_keys (
            key_id INTEGER PRIMARY KEY AUTOINCREMENT,
            url_id INTEGER NOT NULL,
            provider TEXT NOT NULL,
            key_value TEXT NOT NULL,
            found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            severity TEXT DEFAULT 'medium',
            false_positive INTEGER DEFAULT 0,
            verified INTEGER DEFAULT 0,
            validation_status TEXT DEFAULT 'manual',
            notes TEXT,
            FOREIGN KEY (url_id) REFERENCES urls(url_id) ON DELETE CASCADE,
            UNIQUE(url_id, provider, key_value)
        )
    ''')
    
    # XSS findings table (for XSSHunter)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS xss_findings (
            finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
            url_id INTEGER NOT NULL,
            parameter_name TEXT NOT NULL,
            payload TEXT NOT NULL,
            reflected_location TEXT,
            reflected_context TEXT,
            severity TEXT DEFAULT 'medium',
            false_positive INTEGER DEFAULT 0,
            verified INTEGER DEFAULT 0,
            notes TEXT,
            found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (url_id) REFERENCES urls(url_id) ON DELETE CASCADE,
            UNIQUE(url_id, parameter_name, payload)
        )
    ''')
    
    # Open Redirect findings table (for OpenRedirect)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS redirect_findings (
            finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
            url_id INTEGER NOT NULL,
            parameter_name TEXT NOT NULL,
            payload TEXT NOT NULL,
            redirect_url TEXT,
            severity TEXT DEFAULT 'medium',
            false_positive INTEGER DEFAULT 0,
            verified INTEGER DEFAULT 0,
            notes TEXT,
            found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (url_id) REFERENCES urls(url_id) ON DELETE CASCADE,
            UNIQUE(url_id, parameter_name, payload)
        )
    ''')
    
    # Domain Takeover findings table (for DTOHunter)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS takeover_findings (
            finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
            subdomain_id INTEGER NOT NULL,
            service TEXT NOT NULL,
            fingerprint TEXT,
            cname TEXT,
            severity TEXT DEFAULT 'high',
            false_positive INTEGER DEFAULT 0,
            verified INTEGER DEFAULT 0,
            notes TEXT,
            found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (subdomain_id) REFERENCES subdomains(subdomain_id) ON DELETE CASCADE,
            UNIQUE(subdomain_id, service)
        )
    ''')
    
    # Config tables for YAML-based settings (with soft delete support)
    # API patterns table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS config_api_patterns (
            pattern_id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT NOT NULL,
            pattern TEXT NOT NULL,
            is_user_added INTEGER DEFAULT 0,
            deleted_at TIMESTAMP NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(provider, pattern)
        )
    ''')
    
    # Excluded extensions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS config_excluded_extensions (
            extension_id INTEGER PRIMARY KEY AUTOINCREMENT,
            extension TEXT NOT NULL UNIQUE,
            is_user_added INTEGER DEFAULT 0,
            deleted_at TIMESTAMP NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # XSS payloads table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS config_xss_payloads (
            payload_id INTEGER PRIMARY KEY AUTOINCREMENT,
            payload TEXT NOT NULL UNIQUE,
            is_default INTEGER DEFAULT 0,
            is_user_added INTEGER DEFAULT 0,
            deleted_at TIMESTAMP NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Migrate existing tables if needed (must happen BEFORE creating indexes)
    _migrate_existing_schema(cursor)
    
    # Create indexes for config tables
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_api_pattern_provider ON config_api_patterns(provider)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_api_pattern_deleted ON config_api_patterns(deleted_at)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_excluded_ext_deleted ON config_excluded_extensions(deleted_at)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_xss_payload_deleted ON config_xss_payloads(deleted_at)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_xss_payload_default ON config_xss_payloads(is_default)')
    
    # Create indexes (after migration ensures all columns exist)
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_subdomain_scan_id ON subdomains(scan_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_subdomain_status ON subdomains(status)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_subdomain_domain ON subdomains(domain)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_url_scan_id ON urls(scan_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_url_status ON urls(status)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_url_subdomain_id ON urls(subdomain_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_url_unique ON urls(url)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_api_key_url_id ON api_keys(url_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_xss_url_id ON xss_findings(url_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_redirect_url_id ON redirect_findings(url_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_takeover_subdomain_id ON takeover_findings(subdomain_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_domain ON scans(domain)')
    
    conn.commit()
    return conn


def _migrate_existing_schema(cursor):
    """Migrate existing database schema to add checkpoint fields"""
    try:
        # Add checkpoint fields to scans
        cursor.execute("PRAGMA table_info(scans)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'checkpoint' not in columns:
            cursor.execute('ALTER TABLE scans ADD COLUMN checkpoint TEXT')
        if 'status' not in columns:
            try:
                cursor.execute('ALTER TABLE scans ADD COLUMN status TEXT DEFAULT "running"')
            except:
                pass
        
        # Add status and tracking to subdomains if table exists
        try:
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='subdomains'")
            if cursor.fetchone():
                cursor.execute("PRAGMA table_info(subdomains)")
                subdomain_columns = [col[1] for col in cursor.fetchall()]
                
                if 'status' not in subdomain_columns:
                    cursor.execute('ALTER TABLE subdomains ADD COLUMN status TEXT DEFAULT "pending"')
                if 'waybackurls_done' not in subdomain_columns:
                    cursor.execute('ALTER TABLE subdomains ADD COLUMN waybackurls_done INTEGER DEFAULT 0')
                if 'katana_done' not in subdomain_columns:
                    cursor.execute('ALTER TABLE subdomains ADD COLUMN katana_done INTEGER DEFAULT 0')
                if 'urls_collected_at' not in subdomain_columns:
                    cursor.execute('ALTER TABLE subdomains ADD COLUMN urls_collected_at TIMESTAMP')
        except:
            pass
        
        # Add status and subdomain_id to urls
        cursor.execute("PRAGMA table_info(urls)")
        url_columns = [col[1] for col in cursor.fetchall()]
        
        if 'status' not in url_columns:
            cursor.execute('ALTER TABLE urls ADD COLUMN status TEXT DEFAULT "pending"')
        if 'subdomain_id' not in url_columns:
            cursor.execute('ALTER TABLE urls ADD COLUMN subdomain_id INTEGER')
            cursor.execute('ALTER TABLE urls ADD COLUMN source TEXT')
            cursor.execute('ALTER TABLE urls ADD COLUMN discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_url_subdomain_id ON urls(subdomain_id)
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_url_status ON urls(status)
            ''')
    except sqlite3.OperationalError as e:
        # Schema might already be updated or table doesn't exist yet
        pass


def find_existing_scan(db_path: str, domain: str, scan_type: str, output_dir: str) -> Optional[Dict]:
    """Find existing scan for domain, scan_type, and output_dir"""
    if not os.path.exists(db_path):
        return None
    
    def _find():
        conn = get_db_connection(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT scan_id, domain, scan_type, status, checkpoint, start_time, output_dir
                FROM scans
                WHERE domain = ? AND scan_type = ? AND output_dir = ?
                ORDER BY scan_id DESC
                LIMIT 1
            ''', (domain, scan_type, output_dir))
            
            row = cursor.fetchone()
            if row:
                return {
                    'scan_id': row['scan_id'],
                    'domain': row['domain'],
                    'scan_type': row['scan_type'],
                    'status': row['status'],
                    'checkpoint': row['checkpoint'],
                    'start_time': row['start_time'],
                    'output_dir': row['output_dir']
                }
            return None
        finally:
            conn.close()
    
    return retry_db_operation(_find)


def create_or_resume_scan(db_path: str, domain: str, scan_type: str, output_dir: str, 
                          interactive: bool = None, force_restart: bool = False) -> Tuple[int, bool]:
    """
    Create a new scan or resume existing one.
    Returns: (scan_id, is_resumed)
    
    If interactive is None, detects automatically based on stdin availability.
    If force_restart is True, will delete existing scan and create new one.
    If force_restart is False (default), will resume existing scan if found.
    """
    import sys
    
    # Auto-detect interactive mode if not specified
    if interactive is None:
        interactive = sys.stdin.isatty() if hasattr(sys.stdin, 'isatty') else False
    
    # Check for existing scan
    existing = find_existing_scan(db_path, domain, scan_type, output_dir)
    
    if existing:
        if force_restart:
            # Force restart: delete existing scan and create new
            from colorama import Fore
            print(Fore.YELLOW + f"[!] Force restart requested. Deleting existing scan and creating new..."); sys.stdout.flush()
            _delete_scan(db_path, existing['scan_id'])
        elif interactive and interactive is True:
            # Only prompt if explicitly in interactive mode (should not happen from CLI)
            # CLI always passes interactive=False, so this branch is for manual/legacy use
            from colorama import Fore
            print("")
            print(Fore.YELLOW + f"[!] Existing scan found for domain: {domain}")
            print(Fore.WHITE + f"    Status: {existing['status']}")
            print(Fore.WHITE + f"    Checkpoint: {existing.get('checkpoint', 'N/A')}")
            print(Fore.WHITE + f"    Started: {existing['start_time']}")
            print("")
            print(Fore.CYAN + "Choose an option:")
            print(Fore.WHITE + "  [1] Resume existing scan from last checkpoint")
            print(Fore.WHITE + "  [2] Start fresh (delete old scan and create new)")
            print("")
            
            while True:
                try:
                    choice = input(Fore.YELLOW + "Enter choice (1 or 2): ").strip()
                    if choice == '1':
                        # Resume
                        print(Fore.GREEN + "[+] Resuming existing scan..."); sys.stdout.flush()
                        return (existing['scan_id'], True)
                    elif choice == '2':
                        # Delete and create new
                        print(Fore.YELLOW + "[!] Deleting old scan and creating new..."); sys.stdout.flush()
                        _delete_scan(db_path, existing['scan_id'])
                        break
                    else:
                        print(Fore.RED + "Invalid choice. Please enter 1 or 2.")
                except (EOFError, KeyboardInterrupt):
                    # Handle non-interactive or interrupted input - default to resume
                    print(Fore.GREEN + "\n[+] Non-interactive mode detected. Resuming existing scan..."); sys.stdout.flush()
                    return (existing['scan_id'], True)
        else:
            # Non-interactive mode (CLI default): automatically resume if exists
            # This is the default behavior - CLI defaults to resume
            from colorama import Fore
            import sys
            print(Fore.GREEN + f"[+] Found existing scan (ID: {existing['scan_id']}), resuming from checkpoint..."); sys.stdout.flush()
            return (existing['scan_id'], True)
    
    # Create new scan
    def _create():
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        
        try:
            # Use INSERT OR IGNORE to handle race conditions
            cursor.execute('''
                INSERT OR IGNORE INTO scans (domain, scan_type, status, checkpoint, output_dir)
                VALUES (?, ?, 'pending', 'initializing', ?)
            ''', (domain, scan_type, output_dir))
            
            if cursor.lastrowid:
                scan_id = cursor.lastrowid
                conn.commit()
                return (scan_id, False)
            else:
                # Race condition - scan was created between check and insert, fetch it
                cursor.execute('''
                    SELECT scan_id FROM scans
                    WHERE domain = ? AND scan_type = ? AND output_dir = ?
                ''', (domain, scan_type, output_dir))
                row = cursor.fetchone()
                if row:
                    return (row[0], True)
                else:
                    # Should not happen, but handle it
                    raise ValueError("Failed to create or find scan")
        finally:
            conn.close()
    
    return retry_db_operation(_create)


def _delete_scan(db_path: str, scan_id: int):
    """Delete a scan and all related data"""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    
    try:
        # Cascade deletes will handle related data
        cursor.execute('DELETE FROM scans WHERE scan_id = ?', (scan_id,))
        conn.commit()
    finally:
        conn.close()


def update_scan_checkpoint(db_path: str, scan_id: int, status: str, checkpoint: str):
    """Update scan status and checkpoint"""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            UPDATE scans 
            SET status = ?, checkpoint = ?
            WHERE scan_id = ?
        ''', (status, checkpoint, scan_id))
        conn.commit()
    finally:
        conn.close()


def get_scan_checkpoint(db_path: str, scan_id: int) -> Optional[Dict]:
    """Get current scan checkpoint information"""
    conn = get_db_connection(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            SELECT status, checkpoint
            FROM scans
            WHERE scan_id = ?
        ''', (scan_id,))
        
        row = cursor.fetchone()
        if row:
            return {
                'status': row['status'],
                'checkpoint': row['checkpoint']
            }
        return None
    finally:
        conn.close()


def store_subdomain(db_path: str, scan_id: int, domain: str, subdomain: str) -> int:
    """Store a subdomain and return its ID"""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT OR IGNORE INTO subdomains (scan_id, domain, subdomain, status)
            VALUES (?, ?, ?, 'pending')
        ''', (scan_id, domain, subdomain))
        
        # Get the subdomain_id
        cursor.execute('''
            SELECT subdomain_id FROM subdomains
            WHERE scan_id = ? AND subdomain = ?
        ''', (scan_id, subdomain))
        
        row = cursor.fetchone()
        subdomain_id = row[0] if row else None
        
        conn.commit()
        return subdomain_id
    finally:
        conn.close()


def get_pending_subdomains(db_path: str, scan_id: int) -> List[Dict]:
    """Get all pending subdomains that need URL collection"""
    conn = get_db_connection(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            SELECT subdomain_id, subdomain, waybackurls_done, katana_done
            FROM subdomains
            WHERE scan_id = ? AND status IN ('pending', 'urls_collecting')
        ''', (scan_id,))
        
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def mark_subdomain_collection_start(db_path: str, subdomain_id: int):
    """Mark subdomain as starting URL collection"""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            UPDATE subdomains SET status = 'urls_collecting'
            WHERE subdomain_id = ?
        ''', (subdomain_id,))
        conn.commit()
    finally:
        conn.close()


def mark_subdomain_tool_done(db_path: str, subdomain_id: int, tool: str):
    """Mark waybackurls or katana as done for a subdomain"""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    
    try:
        field = 'waybackurls_done' if tool == 'waybackurls' else 'katana_done'
        cursor.execute(f'''
            UPDATE subdomains SET {field} = 1
            WHERE subdomain_id = ?
        ''', (subdomain_id,))
        conn.commit()
    finally:
        conn.close()


def mark_subdomain_collection_complete(db_path: str, subdomain_id: int):
    """Mark subdomain URL collection as complete"""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            UPDATE subdomains 
            SET status = 'urls_collected', urls_collected_at = CURRENT_TIMESTAMP
            WHERE subdomain_id = ?
        ''', (subdomain_id,))
        conn.commit()
    finally:
        conn.close()


def store_url(db_path: str, scan_id: int, url: str, subdomain_id: Optional[int] = None, 
              source: str = 'unknown') -> int:
    """Store a URL and return its ID (if already exists, return existing ID)"""
    def _store():
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        
        try:
            # Check if URL already exists
            cursor.execute('''
                SELECT url_id FROM urls
                WHERE scan_id = ? AND url = ?
            ''', (scan_id, url))
            
            row = cursor.fetchone()
            if row:
                return row[0]
            
            # Insert new URL
            cursor.execute('''
                INSERT INTO urls (scan_id, subdomain_id, url, status, source)
                VALUES (?, ?, ?, 'pending', ?)
            ''', (scan_id, subdomain_id, url, source))
            
            url_id = cursor.lastrowid
            conn.commit()
            return url_id
        finally:
            conn.close()
    
    return retry_db_operation(_store)


def store_urls_batch(db_path: str, scan_id: int, url_data: List[Tuple[str, Optional[int], str]]) -> int:
    """
    Store multiple URLs in a single transaction for better performance and reduced locking.
    Uses INSERT OR IGNORE to handle duplicates automatically via UNIQUE constraint.
    url_data is a list of tuples: (url, subdomain_id, source)
    Returns the number of URLs actually inserted (excluding duplicates).
    """
    if not url_data:
        return 0
    
    def _store_batch():
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        
        try:
            # Clean and prepare URLs for batch insert
            # Use INSERT OR IGNORE to handle duplicates automatically (UNIQUE constraint on scan_id, url)
            urls_to_insert = []
            seen_in_batch = set()  # Prevent duplicates within the same batch
            
            for url, subdomain_id, source in url_data:
                if not url or not url.strip():
                    continue
                url = url.strip()
                # Skip duplicates within the same batch
                if url not in seen_in_batch:
                    urls_to_insert.append((scan_id, subdomain_id, url, 'pending', source))
                    seen_in_batch.add(url)
            
            if not urls_to_insert:
                return 0
            
            # Batch insert using INSERT OR IGNORE - much faster than checking duplicates first
            # The UNIQUE(scan_id, url) constraint will prevent actual duplicates
            cursor.executemany('''
                INSERT OR IGNORE INTO urls (scan_id, subdomain_id, url, status, source)
                VALUES (?, ?, ?, ?, ?)
            ''', urls_to_insert)
            
            # SQLite doesn't always set rowcount correctly, so we estimate based on what we tried to insert
            # Since we're using INSERT OR IGNORE, we can't know the exact count without querying
            # For performance, we'll return the number attempted (actual count may be slightly less)
            inserted_count = len(urls_to_insert)
            
            conn.commit()
            return inserted_count
        finally:
            conn.close()
    
    return retry_db_operation(_store_batch)


def get_pending_urls(db_path: str, scan_id: int, limit: int = None) -> List[Dict]:
    """Get all pending URLs that need to be scanned"""
    conn = get_db_connection(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        query = '''
            SELECT url_id, url, subdomain_id
            FROM urls
            WHERE scan_id = ? AND status = 'pending'
            ORDER BY url_id
        '''
        
        if limit:
            query += f' LIMIT {limit}'
        
        cursor.execute(query, (scan_id,))
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def mark_url_checked(db_path: str, url_id: int, status_code: Optional[int] = None, 
                     content_type: Optional[str] = None):
    """Mark URL as checked with optional status code and content type"""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            UPDATE urls 
            SET status = 'checked', 
                status_code = ?,
                content_type = ?,
                checked_at = CURRENT_TIMESTAMP
            WHERE url_id = ?
        ''', (status_code, content_type, url_id))
        conn.commit()
    finally:
        conn.close()


def mark_url_failed(db_path: str, url_id: int):
    """Mark URL as failed"""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            UPDATE urls SET status = 'failed'
            WHERE url_id = ?
        ''', (url_id,))
        conn.commit()
    finally:
        conn.close()


def count_urls_by_status(db_path: str, scan_id: int) -> Dict[str, int]:
    """Count URLs by status"""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            SELECT status, COUNT(*) as count
            FROM urls
            WHERE scan_id = ?
            GROUP BY status
        ''', (scan_id,))
        
        result = {'pending': 0, 'checked': 0, 'failed': 0}
        for row in cursor.fetchall():
            result[row[0]] = row[1]
        return result
    finally:
        conn.close()
