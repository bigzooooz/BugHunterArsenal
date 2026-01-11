#!/usr/bin/env python3

import os
import sys
import json
import time
import signal
import subprocess
import threading
import uuid
import sqlite3
import logging
import yaml
import shutil
import queue
import re
from datetime import datetime, timezone
from pathlib import Path
from flask import Flask, render_template_string, request, jsonify, Response, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename
from werkzeug.serving import WSGIRequestHandler

# Try to import psutil for system stats, but don't fail if it's not available
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

class QuietWSGIRequestHandler(WSGIRequestHandler):
    def log_request(self, code='-', size='-'):
        pass
    
    def log_message(self, format, *args):
        pass

logging.getLogger('werkzeug').setLevel(logging.CRITICAL)
logging.getLogger('werkzeug').disabled = True
log = logging.getLogger('werkzeug')
log.disabled = True

app = Flask(__name__)
app.logger.disabled = True
logging.getLogger('flask').setLevel(logging.CRITICAL)
logging.getLogger('flask').disabled = True
CORS(app)

SCANS_DIR = Path("scans")
SCANS_DIR.mkdir(exist_ok=True)

UPLOADS_DIR = Path("uploads")
UPLOADS_DIR.mkdir(exist_ok=True)

ALLOWED_EXTENSIONS = {'txt'}

active_scans = {}
scan_lock = threading.Lock()

# Output queue for batching database writes
output_queue = queue.Queue()
output_writer_running = False
output_writer_lock = threading.Lock()

def get_db_path():
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)
    return output_dir / "bughunter.db"

def get_db_connection(db_path=None, timeout=60.0):
    """Get a database connection with proper timeout and WAL mode."""
    if db_path is None:
        db_path = get_db_path()
    
    conn = sqlite3.connect(str(db_path), timeout=timeout, check_same_thread=False)
    # Enable WAL mode for better concurrency
    conn.execute('PRAGMA journal_mode=WAL')
    # Set busy timeout (in milliseconds)
    conn.execute(f'PRAGMA busy_timeout={int(timeout * 1000)}')
    # Optimize for concurrent access
    conn.execute('PRAGMA synchronous=NORMAL')
    conn.execute('PRAGMA cache_size=10000')
    conn.execute('PRAGMA temp_store=MEMORY')
    return conn

def execute_with_retry(func, max_retries=10, retry_delay=0.1):
    """Execute a database operation with retry logic for handling locks."""
    import time
    import random
    for attempt in range(max_retries):
        try:
            return func()
        except sqlite3.OperationalError as e:
            error_msg = str(e).lower()
            if ("database is locked" in error_msg or "database table is locked" in error_msg) and attempt < max_retries - 1:
                # Exponential backoff with jitter to prevent thundering herd
                sleep_time = retry_delay * (2 ** attempt) + random.uniform(0, 0.01)
                time.sleep(sleep_time)
                continue
            raise
        except Exception as e:
            # For non-OperationalError exceptions, check if it's a database lock issue
            error_msg = str(e).lower()
            if ("database is locked" in error_msg or "database table is locked" in error_msg) and attempt < max_retries - 1:
                sleep_time = retry_delay * (2 ** attempt) + random.uniform(0, 0.01)
                time.sleep(sleep_time)
                continue
            raise
    return None

def convert_timestamp_to_iso(timestamp_str):
    """Convert SQLite timestamp string to ISO 8601 format with timezone info.
    SQLite stores timestamps in UTC, so we need to ensure they're properly formatted."""
    if not timestamp_str:
        return None
    
    try:
        # Try parsing as SQLite datetime format (YYYY-MM-DD HH:MM:SS)
        if isinstance(timestamp_str, str) and ' ' in timestamp_str and 'T' not in timestamp_str:
            # SQLite format: YYYY-MM-DD HH:MM:SS (stored in UTC)
            try:
                dt = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                # Try with microseconds
                try:
                    dt = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S.%f')
                except ValueError:
                    return timestamp_str
            # Assume UTC if no timezone info (SQLite stores in UTC)
            dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        elif isinstance(timestamp_str, str) and 'T' in timestamp_str:
            # Already in ISO format, just ensure it has timezone
            if timestamp_str.endswith('Z'):
                return timestamp_str
            elif '+' in timestamp_str or (len(timestamp_str) > 5 and (timestamp_str[-6] == '-' or timestamp_str[-5] == '-')):
                return timestamp_str
            else:
                # No timezone, assume UTC - try to parse
                try:
                    # Remove 'Z' if present and parse
                    clean_str = timestamp_str.replace('Z', '')
                    if '.' in clean_str:
                        dt = datetime.strptime(clean_str, '%Y-%m-%dT%H:%M:%S.%f')
                    else:
                        dt = datetime.strptime(clean_str, '%Y-%m-%dT%H:%M:%S')
                    dt = dt.replace(tzinfo=timezone.utc)
                    return dt.isoformat()
                except (ValueError, AttributeError):
                    return timestamp_str
        else:
            # Try parsing as datetime object
            if isinstance(timestamp_str, datetime):
                if timestamp_str.tzinfo is None:
                    timestamp_str = timestamp_str.replace(tzinfo=timezone.utc)
                return timestamp_str.isoformat()
    except (ValueError, AttributeError, TypeError) as e:
        # If parsing fails, return as-is
        return timestamp_str
    
    return timestamp_str

def convert_row_to_dict(row):
    """Convert a database row to dict, converting timestamps to ISO format."""
    if not row:
        return None
    
    result = dict(row)
    # Convert timestamp fields to ISO format
    timestamp_fields = ['started_at', 'completed_at', 'stopped_at', 'timestamp', 
                       'start_time', 'end_time', 'checked_at', 'found_at']
    
    for field in timestamp_fields:
        if field in result and result[field]:
            result[field] = convert_timestamp_to_iso(result[field])
    
    return result

# Initialize database on first request
@app.before_request
def ensure_database_initialized():
    """Ensure database is initialized before handling requests"""
    if not hasattr(ensure_database_initialized, '_initialized'):
        init_database()
        ensure_database_initialized._initialized = True

def init_database():
    db_path = get_db_path()
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS web_scans (
            web_scan_id TEXT PRIMARY KEY,
            scan_type TEXT NOT NULL,
            target TEXT NOT NULL,
            options TEXT,
            status TEXT DEFAULT 'running',
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            stopped_at TIMESTAMP,
            return_code INTEGER,
            output_dir TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_output (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            web_scan_id TEXT NOT NULL,
            output_line TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (web_scan_id) REFERENCES web_scans(web_scan_id)
        )
    ''')
    
    # Create tables for scan results (scans, urls, api_keys)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            end_time TIMESTAMP,
            status TEXT DEFAULT 'running',
            checkpoint TEXT,
            output_dir TEXT
        )
    ''')
    
    # Add checkpoint column if it doesn't exist (for backward compatibility)
    cursor.execute("PRAGMA table_info(scans)")
    scan_columns = [col[1] for col in cursor.fetchall()]
    if 'checkpoint' not in scan_columns:
        try:
            cursor.execute('ALTER TABLE scans ADD COLUMN checkpoint TEXT')
        except sqlite3.OperationalError:
            pass
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS subdomains (
            subdomain_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            domain TEXT NOT NULL,
            subdomain TEXT NOT NULL,
            discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
            UNIQUE(scan_id, subdomain)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS urls (
            url_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            url TEXT NOT NULL,
            status_code INTEGER,
            content_type TEXT,
            checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
            UNIQUE(scan_id, url)
        )
    ''')
    
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
    
    # Create indexes
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_subdomain_scan_id ON subdomains(scan_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_subdomain_domain ON subdomains(domain)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_id ON urls(scan_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_url_id ON api_keys(url_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_url ON urls(url)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_severity ON api_keys(severity)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_false_positive ON api_keys(false_positive)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_verified ON api_keys(verified)')
    
    # Check and add missing columns to api_keys table (for backward compatibility)
    cursor.execute("PRAGMA table_info(api_keys)")
    columns = [col[1] for col in cursor.fetchall()]
    
    if 'severity' not in columns:
        try:
            cursor.execute('ALTER TABLE api_keys ADD COLUMN severity TEXT DEFAULT "medium"')
        except sqlite3.OperationalError:
            pass
    
    if 'false_positive' not in columns:
        try:
            cursor.execute('ALTER TABLE api_keys ADD COLUMN false_positive INTEGER DEFAULT 0')
        except sqlite3.OperationalError:
            pass
    
    if 'verified' not in columns:
        try:
            cursor.execute('ALTER TABLE api_keys ADD COLUMN verified INTEGER DEFAULT 0')
        except sqlite3.OperationalError:
            pass
    
    if 'notes' not in columns:
        try:
            cursor.execute('ALTER TABLE api_keys ADD COLUMN notes TEXT')
        except sqlite3.OperationalError:
            pass
    
    if 'validation_status' not in columns:
        try:
            cursor.execute('ALTER TABLE api_keys ADD COLUMN validation_status TEXT DEFAULT "manual"')
        except sqlite3.OperationalError:
            pass
    
    # Create configs/settings table for application-wide settings
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS app_config (
            config_id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL UNIQUE,
            value TEXT,
            value_type TEXT DEFAULT 'string',
            category TEXT DEFAULT 'general',
            description TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_by TEXT DEFAULT 'system'
        )
    ''')
    
    # Create settings table for user preferences
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS app_settings (
            setting_id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL UNIQUE,
            value TEXT,
            value_type TEXT DEFAULT 'string',
            category TEXT DEFAULT 'user',
            description TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_by TEXT DEFAULT 'system'
        )
    ''')
    
    # Create indexes for configs/settings
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_config_key ON app_config(key)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_config_category ON app_config(category)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_setting_key ON app_settings(key)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_setting_category ON app_settings(category)')
    
    conn.commit()
    conn.close()

# Helper functions for configs/settings (ready for future use)
def get_config(key: str, default=None):
    """Get a configuration value from app_config table"""
    def _get_config():
        db_path = get_db_path()
        conn = get_db_connection(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT value, value_type FROM app_config WHERE key = ?', (key,))
            row = cursor.fetchone()
            if row:
                value, value_type = row
                # Convert value based on type
                if value_type == 'int':
                    return int(value) if value else default
                elif value_type == 'float':
                    return float(value) if value else default
                elif value_type == 'bool':
                    return value.lower() in ('true', '1', 'yes') if value else default
                elif value_type == 'json':
                    import json
                    return json.loads(value) if value else default
                return value
            return default
        finally:
            conn.close()
    
    return execute_with_retry(_get_config) or default

def set_config(key: str, value, value_type='string', category='general', description=None):
    """Set a configuration value in app_config table"""
    def _set_config():
        db_path = get_db_path()
        conn = get_db_connection(db_path)
        try:
            cursor = conn.cursor()
            # Convert value to string for storage
            if value_type == 'json':
                import json
                value_str = json.dumps(value)
            else:
                value_str = str(value)
            
            cursor.execute('''
                INSERT OR REPLACE INTO app_config (key, value, value_type, category, description, updated_at)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (key, value_str, value_type, category, description))
            conn.commit()
        finally:
            conn.close()
    
    execute_with_retry(_set_config)

def get_setting(key: str, default=None):
    """Get a user setting value from app_settings table"""
    def _get_setting():
        db_path = get_db_path()
        conn = get_db_connection(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT value, value_type FROM app_settings WHERE key = ?', (key,))
            row = cursor.fetchone()
            if row:
                value, value_type = row
                # Convert value based on type
                if value_type == 'int':
                    return int(value) if value else default
                elif value_type == 'float':
                    return float(value) if value else default
                elif value_type == 'bool':
                    return value.lower() in ('true', '1', 'yes') if value else default
                elif value_type == 'json':
                    import json
                    return json.loads(value) if value else default
                return value
            return default
        finally:
            conn.close()
    
    return execute_with_retry(_get_setting) or default

def set_setting(key: str, value, value_type='string', category='user', description=None):
    """Set a user setting value in app_settings table"""
    def _set_setting():
        db_path = get_db_path()
        conn = get_db_connection(db_path)
        try:
            cursor = conn.cursor()
            # Convert value to string for storage
            if value_type == 'json':
                import json
                value_str = json.dumps(value)
            else:
                value_str = str(value)
            
            cursor.execute('''
                INSERT OR REPLACE INTO app_settings (key, value, value_type, category, description, updated_at)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (key, value_str, value_type, category, description))
            conn.commit()
        finally:
            conn.close()
    
    execute_with_retry(_set_setting)

def get_scan_from_db(web_scan_id):
    def _get_scan():
        db_path = get_db_path()
        conn = get_db_connection(db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM web_scans WHERE web_scan_id = ?', (web_scan_id,))
            row = cursor.fetchone()
            if row:
                return convert_row_to_dict(row)
            return None
        finally:
            conn.close()
    
    return execute_with_retry(_get_scan)

def save_scan_to_db(web_scan_id, scan_type, target, options, status='running', output_dir=None):
    def _save_scan():
        db_path = get_db_path()
        conn = get_db_connection(db_path)
        try:
            cursor = conn.cursor()
            options_json = json.dumps(options) if options else None
            
            cursor.execute('''
                INSERT OR REPLACE INTO web_scans 
                (web_scan_id, scan_type, target, options, status, output_dir, started_at)
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (web_scan_id, scan_type, target, options_json, status, output_dir))
            
            conn.commit()
        finally:
            conn.close()
    
    execute_with_retry(_save_scan)

def update_scan_status(web_scan_id, status, return_code=None):
    def _update_status():
        db_path = get_db_path()
        conn = get_db_connection(db_path)
        try:
            cursor = conn.cursor()
            
            if status == 'completed':
                cursor.execute('''
                    UPDATE web_scans 
                    SET status = ?, completed_at = CURRENT_TIMESTAMP, return_code = ?
                    WHERE web_scan_id = ?
                ''', (status, return_code, web_scan_id))
            elif status == 'stopped':
                cursor.execute('''
                    UPDATE web_scans 
                    SET status = ?, stopped_at = CURRENT_TIMESTAMP
                    WHERE web_scan_id = ?
                ''', (status, web_scan_id))
            else:
                cursor.execute('''
                    UPDATE web_scans SET status = ? WHERE web_scan_id = ?
                ''', (status, web_scan_id))
            
            conn.commit()
        finally:
            conn.close()
    
    execute_with_retry(_update_status)

def add_output_line(web_scan_id, line):
    """Add output line to queue for batched writing."""
    output_queue.put((web_scan_id, line))

def _batch_write_outputs():
    """Background thread that batches output writes to reduce database contention."""
    global output_writer_running, output_queue
    batch = []
    batch_size = 50
    batch_timeout = 0.5  # Write batch after 0.5 seconds even if not full
    
    last_write_time = time.time()
    
    while output_writer_running or not output_queue.empty():
        try:
            # Get item with timeout
            try:
                item = output_queue.get(timeout=0.1)
                batch.append(item)
            except queue.Empty:
                item = None
            
            current_time = time.time()
            should_flush = (
                len(batch) >= batch_size or
                (batch and (current_time - last_write_time) >= batch_timeout)
            )
            
            if should_flush and batch:
                _write_output_batch(batch)
                batch = []
                last_write_time = current_time
            
            if item:
                output_queue.task_done()
                
        except Exception as e:
            logging.error(f"Error in output writer thread: {e}", exc_info=True)
            time.sleep(0.1)
    
    # Write any remaining items
    if batch:
        _write_output_batch(batch)

def _write_output_batch(batch):
    """Write a batch of output lines to the database."""
    if not batch:
        return
    
    def _write_batch():
        db_path = get_db_path()
        conn = get_db_connection(db_path, timeout=60.0)
        try:
            cursor = conn.cursor()
            cursor.executemany('''
                INSERT INTO scan_output (web_scan_id, output_line)
                VALUES (?, ?)
            ''', batch)
            conn.commit()
        finally:
            conn.close()
    
    execute_with_retry(_write_batch, max_retries=20, retry_delay=0.1)

def sync_scan_data_to_main_db(web_scan_id):
    """Sync data from scan's database file to main database in real-time."""
    try:
        # Get scan info
        scan_data = get_scan_from_db(web_scan_id)
        if not scan_data:
            return
        
        target = scan_data['target']
        output_dir = scan_data.get('output_dir') or 'output'
        
        # Path to scan's database - try per-domain database first, then default
        import re
        safe_domain = re.sub(r'[^\w\-_\.]', '_', target)
        scan_db_path = Path(output_dir) / f"bughunter_{safe_domain}.db"
        if not scan_db_path.exists():
            scan_db_path = Path(output_dir) / "bughunter.db"
        if not scan_db_path.exists():
            return
        
        main_db_path = get_db_path()
        main_conn = get_db_connection(main_db_path, timeout=10.0)
        
        try:
            main_cursor = main_conn.cursor()
            
            # Get or create scan_id in main database
            main_cursor.execute('SELECT scan_id FROM scans WHERE domain = ? AND output_dir = ? ORDER BY scan_id DESC LIMIT 1', 
                              (target, output_dir))
            scan_row = main_cursor.fetchone()
            if scan_row:
                main_scan_id = scan_row[0]
            else:
                # Create new scan entry
                main_cursor.execute('''
                    INSERT INTO scans (domain, scan_type, status, output_dir)
                    VALUES (?, 'domain', 'running', ?)
                ''', (target, output_dir))
                main_scan_id = main_cursor.lastrowid
            
            # Connect to scan's database
            scan_conn = sqlite3.connect(str(scan_db_path), timeout=10.0)
            scan_conn.row_factory = sqlite3.Row
            scan_cursor = scan_conn.cursor()
            
            try:
                # Get scan_id and checkpoint from scan's database (should match domain)
                scan_cursor.execute('SELECT scan_id, status, checkpoint FROM scans WHERE domain = ? ORDER BY scan_id DESC LIMIT 1', (target,))
                scan_scan_row = scan_cursor.fetchone()
                if not scan_scan_row:
                    return  # No scan data yet
                scan_scan_id = scan_scan_row[0]
                scan_status = scan_scan_row[1] if len(scan_scan_row) > 1 else 'running'
                scan_checkpoint = scan_scan_row[2] if len(scan_scan_row) > 2 else None
                
                # Sync checkpoint and status to main database
                if scan_checkpoint:
                    main_cursor.execute('''
                        UPDATE scans 
                        SET status = ?, checkpoint = ?
                        WHERE scan_id = ?
                    ''', (scan_status, scan_checkpoint, main_scan_id))
                
                # Sync URLs
                scan_cursor.execute('SELECT url_id, url, status_code, content_type FROM urls WHERE scan_id = ?', (scan_scan_id,))
                scan_urls = scan_cursor.fetchall()
                
                for url_row in scan_urls:
                    try:
                        main_cursor.execute('''
                            INSERT OR IGNORE INTO urls (scan_id, url, status_code, content_type)
                            VALUES (?, ?, ?, ?)
                        ''', (main_scan_id, url_row['url'], url_row['status_code'] if url_row['status_code'] else None, url_row['content_type'] if url_row['content_type'] else None))
                    except sqlite3.Error:
                        pass
                
                # Sync API keys (need to map url_id from scan DB to main DB)
                scan_cursor.execute('''
                    SELECT ak.key_id, ak.url_id, ak.provider, ak.key_value, ak.validation_status, ak.severity,
                           ak.false_positive, ak.verified, ak.notes, u.url
                    FROM api_keys ak
                    JOIN urls u ON ak.url_id = u.url_id
                    WHERE u.scan_id = ?
                ''', (scan_scan_id,))
                scan_keys = scan_cursor.fetchall()
                
                for key_row in scan_keys:
                    # Find corresponding url_id in main DB
                    main_cursor.execute('SELECT url_id FROM urls WHERE scan_id = ? AND url = ?', 
                                      (main_scan_id, key_row['url']))
                    main_url_row = main_cursor.fetchone()
                    if main_url_row:
                        main_url_id = main_url_row[0]
                        try:
                            main_cursor.execute('''
                                INSERT OR IGNORE INTO api_keys 
                                (url_id, provider, key_value, validation_status, severity, false_positive, verified, notes)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                            ''', (main_url_id, key_row['provider'], key_row['key_value'], 
                                 key_row['validation_status'] if key_row['validation_status'] else 'manual', 
                                 key_row['severity'] if key_row['severity'] else 'medium',
                                 key_row['false_positive'] if key_row['false_positive'] is not None else 0, 
                                 key_row['verified'] if key_row['verified'] is not None else 0, 
                                 key_row['notes'] if key_row['notes'] else ''))
                        except sqlite3.Error:
                            pass
                
                main_conn.commit()
            finally:
                scan_conn.close()
        finally:
            main_conn.close()
    except Exception as e:
        # Don't log every sync error
        pass

def get_last_output_line(web_scan_id):
    """Get the last output line for a scan."""
    def _get_last_line():
        db_path = get_db_path()
        conn = get_db_connection(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT output_line FROM scan_output 
                WHERE web_scan_id = ? 
                ORDER BY id DESC 
                LIMIT 1
            ''', (web_scan_id,))
            row = cursor.fetchone()
            if row:
                return row[0].strip() if row[0] else None
            return None
        finally:
            conn.close()
    
    return execute_with_retry(_get_last_line)

def get_last_output_lines_batch(web_scan_ids):
    """Get the last output line for multiple scans in a single query."""
    if not web_scan_ids:
        return {}
    
    def _get_last_lines():
        db_path = get_db_path()
        conn = get_db_connection(db_path)
        try:
            cursor = conn.cursor()
            # Use a subquery with ROW_NUMBER to get the last output for each scan
            # This is more efficient than multiple queries
            placeholders = ','.join('?' * len(web_scan_ids))
            cursor.execute(f'''
                SELECT web_scan_id, output_line
                FROM (
                    SELECT web_scan_id, output_line,
                           ROW_NUMBER() OVER (PARTITION BY web_scan_id ORDER BY id DESC) as rn
                    FROM scan_output
                    WHERE web_scan_id IN ({placeholders})
                ) WHERE rn = 1
            ''', web_scan_ids)
            rows = cursor.fetchall()
            return {row[0]: row[1].strip() if row[1] else None for row in rows}
        finally:
            conn.close()
    
    return execute_with_retry(_get_last_lines) or {}

def get_output_lines(web_scan_id, since_id=0):
    def _get_lines():
        db_path = get_db_path()
        conn = get_db_connection(db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, output_line FROM scan_output 
                WHERE web_scan_id = ? AND id > ?
                ORDER BY id ASC
            ''', (web_scan_id, since_id))
            rows = cursor.fetchall()
            return [convert_row_to_dict(row) for row in rows]
        finally:
            conn.close()
    
    return execute_with_retry(_get_lines) or []

def list_all_scans():
    def _list_scans():
        db_path = get_db_path()
        conn = get_db_connection(db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT web_scan_id, scan_type, target, status, started_at, completed_at
                FROM web_scans
                ORDER BY started_at DESC
            ''')
            rows = cursor.fetchall()
            return [convert_row_to_dict(row) for row in rows]
        finally:
            conn.close()
    
    return execute_with_retry(_list_scans) or []

def get_dashboard_html():
    PROJECT_ROOT = Path(__file__).parent.parent
    dashboard_path = PROJECT_ROOT / "web" / "dashboard.html"
    if dashboard_path.exists():
        return dashboard_path.read_text(encoding='utf-8')
    return "<html><body>Dashboard not found</body></html>"

@app.route('/')
def index():
    return render_template_string(get_dashboard_html())

@app.route('/logo.png')
def serve_logo():
    PROJECT_ROOT = Path(__file__).parent.parent
    return send_from_directory(str(PROJECT_ROOT / "web"), 'logo.png')

@app.route('/logo-with-text.png')
def serve_logo_with_text():
    PROJECT_ROOT = Path(__file__).parent.parent
    return send_from_directory(str(PROJECT_ROOT / "web"), 'logo-with-text.png')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        timestamp = int(time.time())
        filename = f"{timestamp}_{filename}"
        file_path = UPLOADS_DIR / filename
        file.save(file_path)
        return jsonify({'file_path': str(file_path.absolute())}), 200
    
    return jsonify({'error': 'Invalid file type'}), 400

@app.route('/api/scans', methods=['POST'])
def start_scan():
    try:
        if not request.is_json:
            return jsonify({'error': 'Request must be JSON'}), 400
        
        data = request.json
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400
        
        scan_type = data.get('type')
        target = data.get('target')
        options = data.get('options', {})
        restart = data.get('restart')  # None/undefined = check for existing, False = resume, True = restart
        
        if not target:
            return jsonify({'error': 'Target is required'}), 400
        
        if scan_type in ['file', 'urls']:
            target_path = Path(target)
            if not target_path.is_absolute():
                target_path = Path(__file__).parent / target
            target = str(target_path.absolute())
        
        output_dir = options.get('output', 'output')
        
        # Check for existing scan before starting (only on initial request when restart is not provided)
        # When restart is None/undefined, check for existing and show dialog
        # When restart is False (user chose resume), skip check and let script auto-resume
        # When restart is True (user chose restart), skip check and pass --restart flag
        check_existing = restart is None  # Only check if restart parameter was not provided
        
        if check_existing:
            try:
                from bughunter import database
                # Determine the scan database path
                safe_domain = re.sub(r'[^\w\-_\.]', '_', target)
                scan_db_path = Path(output_dir) / f"bughunter_{safe_domain}.db"
                if not scan_db_path.exists():
                    scan_db_path = Path(output_dir) / "bughunter.db"
                
                if scan_db_path.exists():
                    existing = database.find_existing_scan(str(scan_db_path), target, scan_type, output_dir)
                    if existing:
                        # Return existing scan info to GUI so it can show dialog
                        return jsonify({
                            'existing_scan': True,
                            'scan_id': existing['scan_id'],
                            'status': existing['status'],
                            'checkpoint': existing.get('checkpoint', 'N/A'),
                            'start_time': existing['start_time'],
                            'domain': existing['domain']
                        }), 200
            except Exception as e:
                # If check fails, continue with normal scan start
                logging.error(f"Error checking for existing scan: {e}", exc_info=True)
        
        scan_id = str(uuid.uuid4())
        
        PROJECT_ROOT = Path(__file__).parent.parent
        script_path = PROJECT_ROOT / "BugHunterArsenal.py"
        cmd = [sys.executable, str(script_path)]
        
        if scan_type == 'domain':
            cmd.extend(['-d', target])
        elif scan_type == 'file':
            cmd.extend(['-f', target])
        elif scan_type == 'urls':
            cmd.extend(['-l', target])
        else:
            return jsonify({'error': 'Invalid scan type'}), 400
        
        if options.get('verbose'):
            cmd.append('-v')
        
        if options.get('no_subs'):
            cmd.append('--no-subs')
        
        if options.get('cookie'):
            cmd.extend(['--cookie', options['cookie']])
        
        if options.get('x_request_for'):
            cmd.extend(['--x-request-for', options['x_request_for']])
        
        if options.get('output'):
            cmd.extend(['-o', options['output']])
        
        # Add restart flag if requested (restart=True means force restart)
        if restart is True:
            cmd.append('--restart')
        
        # Add tool selection (comma-separated)
        tools = options.get('tools', ['keyhunter'])
        if isinstance(tools, list):
            tools_str = ','.join(tools)
        elif isinstance(tools, str):
            tools_str = tools
        else:
            tools_str = 'keyhunter'
        cmd.extend(['--tool', tools_str])
        
        try:
            # Set environment to ensure unbuffered output
            env = os.environ.copy()
            env['PYTHONUNBUFFERED'] = '1'
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
                cwd=str(PROJECT_ROOT),
                env=env
            )
            
            with scan_lock:
                active_scans[scan_id] = {
                    'process': process,
                    'status': 'running',
                    'started_at': datetime.now(timezone.utc)
                }
            
            save_scan_to_db(scan_id, scan_type, target, options, 'running', output_dir)
            
            thread = threading.Thread(
                target=read_scan_output,
                args=(scan_id, process),
                daemon=True
            )
            thread.start()
            
            scan_data = get_scan_from_db(scan_id)
            return jsonify({
                'scan_id': scan_id,
                'status': 'running',
                'started_at': scan_data['started_at'] if scan_data else datetime.now(timezone.utc).isoformat()
            }), 200
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    except Exception as e:
        return jsonify({'error': f'Error parsing request: {str(e)}'}), 400

def read_scan_output(scan_id, process):
    try:
        last_sync_time = time.time()
        sync_interval = 2.0  # Sync every 2 seconds
        
        # Read output line by line
        while True:
            line = process.stdout.readline()
            if not line:
                # Check if process has finished
                if process.poll() is not None:
                    break
                # Sync data periodically even when no new output
                current_time = time.time()
                if current_time - last_sync_time >= sync_interval:
                    sync_scan_data_to_main_db(scan_id)
                    last_sync_time = current_time
                continue
            add_output_line(scan_id, line)
            
            # Sync data periodically
            current_time = time.time()
            if current_time - last_sync_time >= sync_interval:
                sync_scan_data_to_main_db(scan_id)
                last_sync_time = current_time
        
        # Wait for process to complete and get return code
        process.wait()
        
        status = 'completed' if process.returncode == 0 else 'failed'
        update_scan_status(scan_id, status, process.returncode)
        
        # Final sync of all data when scan completes
        sync_scan_data_to_main_db(scan_id)
        
        # Update scan status in scans table (not web_scans) to completed
        try:
            scan_data = get_scan_from_db(scan_id)
            if scan_data:
                target = scan_data['target']
                output_dir = scan_data.get('output_dir') or 'output'
                db_path = get_db_path()
                conn = get_db_connection(db_path, timeout=10.0)
                try:
                    cursor = conn.cursor()
                    cursor.execute('''
                        UPDATE scans 
                        SET status = ?, end_time = CURRENT_TIMESTAMP
                        WHERE domain = ? AND output_dir = ?
                    ''', (status, target, output_dir))
                    conn.commit()
                finally:
                    conn.close()
        except Exception as e:
            logging.error(f"Error updating scan status in scans table: {e}", exc_info=True)
        
        with scan_lock:
            if scan_id in active_scans:
                active_scans[scan_id]['status'] = status
                
    except Exception as e:
        # Log the error for debugging
        logging.error(f"Error reading scan output for {scan_id}: {e}", exc_info=True)
        
        # Try to get the return code if process has finished
        try:
            return_code = process.poll()
            if return_code is not None:
                # Process has finished, check return code
                status = 'completed' if return_code == 0 else 'failed'
                update_scan_status(scan_id, status, return_code)
                
                with scan_lock:
                    if scan_id in active_scans:
                        active_scans[scan_id]['status'] = status
            else:
                # Process still running, mark as error
                update_scan_status(scan_id, 'error')
        except Exception as e2:
            # If we can't determine status, mark as error
            logging.error(f"Could not determine process status for {scan_id}: {e2}")
            update_scan_status(scan_id, 'error')

@app.route('/api/scans/<scan_id>', methods=['GET'])
def get_scan_status(scan_id):
    scan_data = get_scan_from_db(scan_id)
    
    if not scan_data:
        return jsonify({'error': 'Scan not found'}), 404
    
    # Sync scan data from scan's database to get latest checkpoint
    sync_scan_data_to_main_db(scan_id)
    
    # Get checkpoint from main database scans table
    try:
        scan_data_from_main = get_scan_from_db(scan_id)
        if scan_data_from_main:
            target = scan_data_from_main['target']
            output_dir = scan_data_from_main.get('output_dir') or 'output'
            
            # Try to get checkpoint from scan's database file (handle per-domain databases)
            import re
            safe_domain = re.sub(r'[^\w\-_\.]', '_', target)
            scan_db_path = Path(output_dir) / f"bughunter_{safe_domain}.db"
            if not scan_db_path.exists():
                scan_db_path = Path(output_dir) / "bughunter.db"
            if scan_db_path.exists():
                try:
                    scan_conn = sqlite3.connect(str(scan_db_path), timeout=5.0)
                    scan_conn.row_factory = sqlite3.Row
                    scan_cursor = scan_conn.cursor()
                    scan_cursor.execute('SELECT status, checkpoint FROM scans WHERE domain = ? ORDER BY scan_id DESC LIMIT 1', (target,))
                    checkpoint_row = scan_cursor.fetchone()
                    if checkpoint_row:
                        scan_data['checkpoint'] = checkpoint_row['checkpoint']
                        scan_data['status'] = checkpoint_row['status'] if checkpoint_row['status'] else 'running'
                    scan_conn.close()
                except:
                    pass
            
            # Also try main database
            main_db_path = get_db_path()
            if main_db_path.exists():
                try:
                    main_conn = get_db_connection(main_db_path, timeout=5.0)
                    main_conn.row_factory = sqlite3.Row
                    main_cursor = main_conn.cursor()
                    main_cursor.execute('SELECT status, checkpoint FROM scans WHERE domain = ? AND output_dir = ? ORDER BY scan_id DESC LIMIT 1', (target, output_dir))
                    main_checkpoint_row = main_cursor.fetchone()
                    if main_checkpoint_row and main_checkpoint_row['checkpoint']:
                        scan_data['checkpoint'] = main_checkpoint_row['checkpoint']
                        if main_checkpoint_row['status']:
                            scan_data['status'] = main_checkpoint_row['status']
                    main_conn.close()
                except:
                    pass
    except:
        pass
    
    with scan_lock:
        if scan_id in active_scans:
            process = active_scans[scan_id]['process']
            if process.poll() is None:
                scan_data['status'] = 'running'
            else:
                scan_data['status'] = 'completed' if process.returncode == 0 else 'failed'
                update_scan_status(scan_id, scan_data['status'], process.returncode)
    
    if scan_data.get('options'):
        scan_data['options'] = json.loads(scan_data['options'])
    
    return jsonify(scan_data)

@app.route('/api/scans/<scan_id>/rerun', methods=['POST'])
def rerun_scan(scan_id):
    """Rerun a scan with the same parameters as the original scan."""
    scan_data = get_scan_from_db(scan_id)
    
    if not scan_data:
        return jsonify({'error': 'Scan not found'}), 404
    
    # Only allow rerunning scans that are not currently running
    if scan_data['status'] == 'running':
        return jsonify({'error': 'Cannot rerun a scan that is currently running'}), 400
    
    scan_type = scan_data['scan_type']
    target = scan_data['target']
    options = {}
    
    if scan_data.get('options'):
        try:
            options = json.loads(scan_data['options'])
        except:
            options = {}
    
    # Create new scan with same parameters
    new_scan_id = str(uuid.uuid4())
    
    PROJECT_ROOT = Path(__file__).parent.parent
    script_path = PROJECT_ROOT / "BugHunterArsenal.py"
    cmd = [sys.executable, str(script_path)]
    
    if scan_type == 'domain':
        cmd.extend(['-d', target])
    elif scan_type == 'file':
        cmd.extend(['-f', target])
    elif scan_type == 'urls':
        cmd.extend(['-l', target])
    else:
        return jsonify({'error': 'Invalid scan type'}), 400
    
    if options.get('verbose'):
        cmd.append('-v')
    
    if options.get('no_subs'):
        cmd.append('--no-subs')
    
    if options.get('cookie'):
        cmd.extend(['--cookie', options['cookie']])
    
    if options.get('x_request_for'):
        cmd.extend(['--x-request-for', options['x_request_for']])
    
    if options.get('output'):
        cmd.extend(['-o', options['output']])
    
    # Add tool selection (comma-separated)
    tools = options.get('tools', ['keyhunter'])
    if isinstance(tools, list):
        tools_str = ','.join(tools)
    elif isinstance(tools, str):
        tools_str = tools
    else:
        tools_str = 'keyhunter'
    cmd.extend(['--tool', tools_str])
    
    output_dir = options.get('output', 'output')
    
    try:
        # Set environment to ensure unbuffered output
        env = os.environ.copy()
        env['PYTHONUNBUFFERED'] = '1'
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
            cwd=str(PROJECT_ROOT),
            env=env
        )
        
        with scan_lock:
            active_scans[new_scan_id] = {
                'process': process,
                'status': 'running',
                'started_at': datetime.now(timezone.utc)
            }
        
        save_scan_to_db(new_scan_id, scan_type, target, options, 'running', output_dir)
        
        thread = threading.Thread(
            target=read_scan_output,
            args=(new_scan_id, process),
            daemon=True
        )
        thread.start()
        
        new_scan_data = get_scan_from_db(new_scan_id)
        return jsonify({
            'scan_id': new_scan_id,
            'status': 'running',
            'started_at': new_scan_data['started_at'] if new_scan_data else datetime.now(timezone.utc).isoformat()
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scans/<scan_id>/resume', methods=['POST'])
def resume_scan(scan_id):
    """Resume a scan from its last checkpoint."""
    scan_data = get_scan_from_db(scan_id)
    
    if not scan_data:
        return jsonify({'error': 'Scan not found'}), 404
    
    # Only allow resuming scans that are not currently running
    if scan_data['status'] == 'running':
        return jsonify({'error': 'Cannot resume a scan that is currently running'}), 400
    
    scan_type = scan_data['scan_type']
    target = scan_data['target']
    options = {}
    
    if scan_data.get('options'):
        try:
            options = json.loads(scan_data['options'])
        except:
            options = {}
    
    output_dir = options.get('output', 'output')
    
    # Check if there's an existing scan database that can be resumed
    can_resume = False
    checkpoint_info = None
    try:
        safe_domain = re.sub(r'[^\w\-_\.]', '_', target)
        scan_db_path = Path(output_dir) / f"bughunter_{safe_domain}.db"
        if not scan_db_path.exists():
            scan_db_path = Path(output_dir) / "bughunter.db"
        
        if scan_db_path.exists():
            try:
                scan_conn = sqlite3.connect(str(scan_db_path), timeout=5.0)
                scan_conn.row_factory = sqlite3.Row
                scan_cursor = scan_conn.cursor()
                scan_cursor.execute('''
                    SELECT status, checkpoint 
                    FROM scans 
                    WHERE domain = ? AND scan_type = ? AND output_dir = ?
                    ORDER BY scan_id DESC 
                    LIMIT 1
                ''', (target, scan_type, output_dir))
                checkpoint_row = scan_cursor.fetchone()
                if checkpoint_row:
                    checkpoint_info = {
                        'status': checkpoint_row['status'],
                        'checkpoint': checkpoint_row['checkpoint']
                    }
                    # Can resume if status is not completed (pending, running, failed, etc.)
                    if checkpoint_row['status'] not in ['completed', None]:
                        can_resume = True
                scan_conn.close()
            except Exception as e:
                logging.error(f"Error checking checkpoint: {e}", exc_info=True)
    except Exception as e:
        logging.error(f"Error checking scan database: {e}", exc_info=True)
    
    if not can_resume:
        return jsonify({
            'error': 'Cannot resume scan: No checkpoint found or scan is already completed. Use "Rerun" to start a new scan instead.'
        }), 400
    
    # Create new web scan with same parameters - the underlying scan will resume from checkpoint
    new_scan_id = str(uuid.uuid4())
    
    PROJECT_ROOT = Path(__file__).parent.parent
    script_path = PROJECT_ROOT / "BugHunterArsenal.py"
    cmd = [sys.executable, str(script_path)]
    
    if scan_type == 'domain':
        cmd.extend(['-d', target])
    elif scan_type == 'file':
        cmd.extend(['-f', target])
    elif scan_type == 'urls':
        cmd.extend(['-l', target])
    else:
        return jsonify({'error': 'Invalid scan type'}), 400
    
    if options.get('verbose'):
        cmd.append('-v')
    
    if options.get('no_subs'):
        cmd.append('--no-subs')
    
    if options.get('cookie'):
        cmd.extend(['--cookie', options['cookie']])
    
    if options.get('x_request_for'):
        cmd.extend(['--x-request-for', options['x_request_for']])
    
    if options.get('output'):
        cmd.extend(['-o', options['output']])
    
    # Add tool selection (comma-separated)
    tools = options.get('tools', ['keyhunter'])
    if isinstance(tools, list):
        tools_str = ','.join(tools)
    elif isinstance(tools, str):
        tools_str = tools
    else:
        tools_str = 'keyhunter'
    cmd.extend(['--tool', tools_str])
    
    try:
        # Set environment to ensure unbuffered output
        env = os.environ.copy()
        env['PYTHONUNBUFFERED'] = '1'
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
            cwd=str(PROJECT_ROOT),
            env=env
        )
        
        with scan_lock:
            active_scans[new_scan_id] = {
                'process': process,
                'status': 'running',
                'started_at': datetime.now(timezone.utc)
            }
        
        save_scan_to_db(new_scan_id, scan_type, target, options, 'running', output_dir)
        
        thread = threading.Thread(
            target=read_scan_output,
            args=(new_scan_id, process),
            daemon=True
        )
        thread.start()
        
        new_scan_data = get_scan_from_db(new_scan_id)
        return jsonify({
            'scan_id': new_scan_id,
            'status': 'running',
            'resumed': True,
            'checkpoint': checkpoint_info.get('checkpoint') if checkpoint_info else None,
            'started_at': new_scan_data['started_at'] if new_scan_data else datetime.now(timezone.utc).isoformat()
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scans/<scan_id>/output', methods=['GET'])
def get_scan_output(scan_id):
    scan_data = get_scan_from_db(scan_id)
    
    if not scan_data:
        return jsonify({'error': 'Scan not found'}), 404
    
    def generate():
        last_id = 0
        first_run = True
        
        while True:
            try:
                scan_data = get_scan_from_db(scan_id)
                if not scan_data:
                    yield f"data: {json.dumps({'error': 'Scan not found'})}\n\n"
                    break
                
                process_running = False
                
                with scan_lock:
                    if scan_id in active_scans:
                        process = active_scans[scan_id]['process']
                        if process.poll() is None:
                            process_running = True
                        else:
                            status = 'completed' if process.returncode == 0 else 'failed'
                            update_scan_status(scan_id, status, process.returncode)
                            scan_data = get_scan_from_db(scan_id)
                
                # Get all output lines since last_id
                output_lines = get_output_lines(scan_id, last_id)
                if output_lines:
                    output_text = ''.join(line['output_line'] for line in output_lines)
                    cleaned = clean_ansi_codes(output_text)
                    yield f"data: {json.dumps({'output': cleaned})}\n\n"
                    last_id = output_lines[-1]['id']
                elif first_run:
                    # On first run, send empty output to confirm connection
                    yield f"data: {json.dumps({'output': ''})}\n\n"
                
                first_run = False
                
                # Check if scan is complete
                if not process_running and scan_data and scan_data['status'] != 'running':
                    yield f"data: {json.dumps({'status': scan_data['status'], 'completed': True})}\n\n"
                    break
                
                time.sleep(0.5)
            except GeneratorExit:
                # Client disconnected
                break
            except Exception as e:
                # Log error but continue trying
                logging.error(f"Error in SSE stream for scan {scan_id}: {e}", exc_info=True)
                yield f"data: {json.dumps({'error': str(e)})}\n\n"
                time.sleep(1)
    
    response = Response(generate(), mimetype='text/event-stream')
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['Connection'] = 'keep-alive'
    response.headers['X-Accel-Buffering'] = 'no'
    return response

def clean_ansi_codes(text):
    import re
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

@app.route('/api/scans', methods=['GET'])
def list_scans():
    scans = list_all_scans()
    
    # Batch fetch last output lines for all running scans in a single query
    running_scan_ids = [scan['web_scan_id'] for scan in scans if scan['status'] == 'running']
    last_outputs = get_last_output_lines_batch(running_scan_ids) if running_scan_ids else {}
    
    formatted_scans = []
    for scan in scans:
        scan_data = {
            'scan_id': scan['web_scan_id'],
            'type': scan['scan_type'],
            'target': scan['target'],
            'status': scan['status'],
            'started_at': scan['started_at']
        }
        
        # Include completion time if available
        if scan.get('completed_at'):
            scan_data['completed_at'] = scan['completed_at']
        
        # Include options if available
        if scan.get('options'):
            try:
                scan_data['options'] = json.loads(scan['options'])
            except:
                scan_data['options'] = {}
        
        # Get last output line for running scans from batch query
        if scan['status'] == 'running' and scan['web_scan_id'] in last_outputs:
            last_line = last_outputs[scan['web_scan_id']]
            if last_line:
                scan_data['last_output'] = last_line
        
        formatted_scans.append(scan_data)
    
    return jsonify({'scans': formatted_scans})

@app.route('/api/scans/<scan_id>/stop', methods=['POST'])
def stop_scan(scan_id):
    with scan_lock:
        if scan_id not in active_scans:
            return jsonify({'error': 'Scan not found or not running'}), 404
        
        process = active_scans[scan_id]['process']
        if process.poll() is None:
            process.terminate()
            time.sleep(2)
            if process.poll() is None:
                process.kill()
            
            update_scan_status(scan_id, 'stopped')
            del active_scans[scan_id]
            
            return jsonify({'status': 'stopped'})
    
    return jsonify({'error': 'Could not stop scan'}), 500

@app.route('/api/scans/<scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    """Delete a single scan and its associated data, including per-domain database files."""
    db_path = get_db_path()
    if not db_path.exists():
        return jsonify({'error': 'Database not found'}), 404
    
    def _delete_scan():
        conn = get_db_connection(db_path)
        try:
            cursor = conn.cursor()
            
            # Get scan info before deletion (needed for file cleanup)
            cursor.execute('SELECT target, output_dir FROM web_scans WHERE web_scan_id = ?', (scan_id,))
            scan_row = cursor.fetchone()
            if not scan_row:
                return {'error': 'Scan not found'}, 404
            
            target = scan_row[0]
            output_dir = scan_row[1] or 'output'
            
            # Stop scan if it's running
            with scan_lock:
                if scan_id in active_scans:
                    process = active_scans[scan_id]['process']
                    if process.poll() is None:
                        process.terminate()
                        time.sleep(1)
                        if process.poll() is None:
                            process.kill()
                    del active_scans[scan_id]
            
            # Delete scan output
            cursor.execute('DELETE FROM scan_output WHERE web_scan_id = ?', (scan_id,))
            
            # Delete the scan
            cursor.execute('DELETE FROM web_scans WHERE web_scan_id = ?', (scan_id,))
            
            conn.commit()
            
            # Delete per-domain database file if it exists
            deleted_files = []
            import re
            safe_domain = re.sub(r'[^\w\-_\.]', '_', target)
            output_path = Path(output_dir)
            per_domain_db = output_path / f"bughunter_{safe_domain}.db"
            
            if per_domain_db.exists():
                try:
                    per_domain_db.unlink()
                    deleted_files.append(str(per_domain_db))
                except Exception as e:
                    logging.error(f'Error deleting per-domain database {per_domain_db}: {e}')
            
            result = {'success': True, 'message': 'Scan deleted'}
            if deleted_files:
                result['files_deleted'] = deleted_files
            
            return result, 200
        finally:
            conn.close()
    
    try:
        result, status_code = execute_with_retry(_delete_scan)
        return jsonify(result), status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scans/bulk', methods=['DELETE'])
def bulk_delete_scans():
    """Delete multiple scans and their associated data."""
    data = request.json
    scan_ids = data.get('scan_ids', [])
    
    if not scan_ids:
        return jsonify({'error': 'No scan IDs provided'}), 400
    
    db_path = get_db_path()
    if not db_path.exists():
        return jsonify({'error': 'Database not found'}), 404
    
    def _bulk_delete():
        conn = get_db_connection(db_path)
        try:
            cursor = conn.cursor()
            
            # Get scan info before deletion (needed for file cleanup)
            placeholders = ','.join('?' * len(scan_ids))
            cursor.execute(f'SELECT target, output_dir FROM web_scans WHERE web_scan_id IN ({placeholders})', scan_ids)
            scan_info = cursor.fetchall()
            targets_to_check = {}
            for target, output_dir in scan_info:
                if target:
                    output_dir = output_dir or 'output'
                    if target not in targets_to_check:
                        targets_to_check[target] = set()
                    targets_to_check[target].add(output_dir)
            
            # Stop any running scans
            with scan_lock:
                for scan_id in scan_ids:
                    if scan_id in active_scans:
                        process = active_scans[scan_id]['process']
                        if process.poll() is None:
                            process.terminate()
                            time.sleep(1)
                            if process.poll() is None:
                                process.kill()
                        del active_scans[scan_id]
            
            # Delete scan outputs
            cursor.execute(f'DELETE FROM scan_output WHERE web_scan_id IN ({placeholders})', scan_ids)
            
            # Delete the scans
            cursor.execute(f'DELETE FROM web_scans WHERE web_scan_id IN ({placeholders})', scan_ids)
            
            deleted_count = cursor.rowcount
            conn.commit()
            
            # Check if any targets have no remaining scans, and delete their per-domain databases
            deleted_files = []
            import re
            for target, output_dirs in targets_to_check.items():
                # Check if target still has scans in web_scans
                cursor.execute('SELECT COUNT(*) FROM web_scans WHERE target = ?', (target,))
                remaining_scans = cursor.fetchone()[0] or 0
                
                if remaining_scans == 0:
                    # No more scans for this target, can safely delete per-domain database
                    safe_domain = re.sub(r'[^\w\-_\.]', '_', target)
                    for output_dir in output_dirs:
                        output_path = Path(output_dir)
                        per_domain_db = output_path / f"bughunter_{safe_domain}.db"
                        if per_domain_db.exists():
                            try:
                                per_domain_db.unlink()
                                deleted_files.append(str(per_domain_db))
                            except Exception as e:
                                logging.error(f'Error deleting per-domain database {per_domain_db}: {e}')
            
            result = {'success': True, 'deleted': deleted_count}
            if deleted_files:
                result['files_deleted'] = deleted_files
            
            return result, 200
        finally:
            conn.close()
    
    try:
        result, status_code = execute_with_retry(_bulk_delete)
        return jsonify(result), status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scans/by-domain/<path:domain>', methods=['DELETE'])
def delete_domain(domain):
    from urllib.parse import unquote
    domain = unquote(domain)
    
    db_path = get_db_path()
    if not db_path.exists():
        return jsonify({'error': 'Database not found'}), 404
    
    def _delete_domain():
        conn = get_db_connection(db_path)
        try:
            cursor = conn.cursor()
            
            # Get scan_ids and output_dir before deletion (needed for file cleanup)
            cursor.execute('SELECT scan_id, output_dir FROM scans WHERE domain = ?', (domain,))
            scan_data = cursor.fetchall()
            scan_ids = [row[0] for row in scan_data]
            output_dirs = set(row[1] for row in scan_data if row[1])
            
            if not scan_ids:
                return {'error': 'No scans found for this domain'}, 404
            
            # Get URL IDs for all scans of this domain
            placeholders = ','.join('?' * len(scan_ids))
            cursor.execute(f'''
                SELECT DISTINCT u.url_id
                FROM urls u
                WHERE u.scan_id IN ({placeholders})
            ''', scan_ids)
            url_ids = [row[0] for row in cursor.fetchall()]
            
            # Count URLs and keys before deletion
            url_count = len(url_ids)
            key_count = 0
            if url_ids:
                url_placeholders = ','.join('?' * len(url_ids))
                cursor.execute(f'''
                    SELECT COUNT(*) FROM api_keys WHERE url_id IN ({url_placeholders})
                ''', url_ids)
                key_count = cursor.fetchone()[0] or 0
            
            # Stop any running scans for this domain
            # First, find web_scan_ids for this domain from web_scans table
            cursor.execute('SELECT web_scan_id FROM web_scans WHERE target = ?', (domain,))
            web_scan_ids = [row[0] for row in cursor.fetchall()]
            
            with scan_lock:
                for web_scan_id in web_scan_ids:
                    if web_scan_id in active_scans:
                        process = active_scans[web_scan_id]['process']
                        if process.poll() is None:
                            process.terminate()
                            time.sleep(1)
                            if process.poll() is None:
                                process.kill()
                        del active_scans[web_scan_id]
                        update_scan_status(web_scan_id, 'stopped')
            
            # Explicitly delete API keys first (foreign key constraint)
            if url_ids:
                url_placeholders = ','.join('?' * len(url_ids))
                cursor.execute(f'DELETE FROM api_keys WHERE url_id IN ({url_placeholders})', url_ids)
            
            # Explicitly delete URLs
            if url_ids:
                url_placeholders = ','.join('?' * len(url_ids))
                cursor.execute(f'DELETE FROM urls WHERE url_id IN ({url_placeholders})', url_ids)
            
            # Delete subdomains table entries if they exist
            cursor.execute(f'DELETE FROM subdomains WHERE scan_id IN ({placeholders})', scan_ids)
            
            # Finally delete scans
            cursor.execute('DELETE FROM scans WHERE domain = ?', (domain,))
            
            # Also delete from web_scans table
            if web_scan_ids:
                web_placeholders = ','.join('?' * len(web_scan_ids))
                cursor.execute(f'DELETE FROM scan_output WHERE web_scan_id IN ({web_placeholders})', web_scan_ids)
                cursor.execute(f'DELETE FROM web_scans WHERE web_scan_id IN ({web_placeholders})', web_scan_ids)
            
            conn.commit()
            
            # Delete per-domain database files for each output directory
            deleted_files = []
            import re
            safe_domain = re.sub(r'[^\w\-_\.]', '_', domain)
            
            for output_dir in output_dirs:
                if not output_dir:
                    output_dir = 'output'
                
                output_path = Path(output_dir)
                
                # Try per-domain database file
                per_domain_db = output_path / f"bughunter_{safe_domain}.db"
                if per_domain_db.exists():
                    try:
                        per_domain_db.unlink()
                        deleted_files.append(str(per_domain_db))
                    except Exception as e:
                        logging.error(f'Error deleting per-domain database {per_domain_db}: {e}')
                
                # Also try default database file if it's the only one for this domain
                # (check if it exists and might be used by this domain)
                default_db = output_path / "bughunter.db"
                if default_db.exists():
                    # Only delete if we're sure this domain was the only one using it
                    # For safety, we'll check if there are other scans using this output_dir
                    try:
                        temp_conn = sqlite3.connect(str(default_db), timeout=5.0)
                        temp_cursor = temp_conn.cursor()
                        temp_cursor.execute('SELECT COUNT(DISTINCT domain) FROM scans')
                        other_domains = temp_cursor.fetchone()[0] or 0
                        temp_conn.close()
                        
                        # If only this domain was using it, or if we can't tell, leave it
                        # (we only delete per-domain files to be safe)
                    except:
                        pass  # Can't check, leave it alone
            
            return {
                'status': 'deleted',
                'domain': domain,
                'scans_deleted': len(scan_ids),
                'urls_deleted': url_count,
                'keys_deleted': key_count,
                'files_deleted': deleted_files
            }, 200
        except sqlite3.Error as e:
            logging.error(f'SQL error in delete_domain: {e}', exc_info=True)
            conn.rollback()
            return {'error': f'Database error: {str(e)}'}, 500
        finally:
            conn.close()
    
    try:
        result, status_code = execute_with_retry(_delete_domain)
        if status_code == 404:
            return jsonify(result), status_code
        return jsonify(result), status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/targets/subdomain', methods=['DELETE'])
def delete_subdomain():
    """Delete a subdomain from a domain."""
    data = request.json
    domain = data.get('domain')
    subdomain = data.get('subdomain')
    
    if not domain or not subdomain:
        return jsonify({'error': 'Domain and subdomain are required'}), 400
    
    db_path = get_db_path()
    if not db_path.exists():
        return jsonify({'error': 'Database not found'}), 404
    
    def _delete_subdomain():
        conn = get_db_connection(db_path)
        try:
            cursor = conn.cursor()
            
            # Get all scan_ids for this domain
            cursor.execute('SELECT scan_id FROM scans WHERE domain = ?', (domain,))
            scan_ids = [row[0] for row in cursor.fetchall()]
            
            if not scan_ids:
                return {'error': 'No scans found for this domain'}, 404
            
            # Get URLs that match this subdomain
            # Extract hostname from URLs and match against subdomain
            urls_to_delete = []
            url_ids_to_delete = []
            
            for scan_id in scan_ids:
                cursor.execute('SELECT url_id, url FROM urls WHERE scan_id = ?', (scan_id,))
                urls_data = cursor.fetchall()
                
                for url_row in urls_data:
                    url_id, url = url_row
                    try:
                        from urllib.parse import urlparse
                        parsed = urlparse(url)
                        hostname = parsed.netloc or parsed.path.split('/')[0]
                        if ':' in hostname:
                            hostname = hostname.split(':')[0]
                        
                        # Match subdomain (exact match)
                        if hostname == subdomain:
                            urls_to_delete.append(url)
                            url_ids_to_delete.append(url_id)
                    except:
                        # If URL parsing fails, skip it
                        continue
            
            if not url_ids_to_delete:
                return {'error': 'No URLs found for this subdomain'}, 404
            
            # Count findings before deletion
            placeholders = ','.join('?' * len(url_ids_to_delete))
            cursor.execute(f'''
                SELECT COUNT(*) FROM api_keys WHERE url_id IN ({placeholders})
            ''', tuple(url_ids_to_delete))
            keys_count = cursor.fetchone()[0] or 0
            
            # Delete API keys first (foreign key constraint)
            cursor.execute(f'DELETE FROM api_keys WHERE url_id IN ({placeholders})', tuple(url_ids_to_delete))
            
            # Delete URLs
            cursor.execute(f'DELETE FROM urls WHERE url_id IN ({placeholders})', tuple(url_ids_to_delete))
            
            conn.commit()
            
            return {
                'status': 'deleted',
                'domain': domain,
                'subdomain': subdomain,
                'urls_deleted': len(url_ids_to_delete),
                'keys_deleted': keys_count
            }, 200
        except sqlite3.Error as e:
            logging.error(f'SQL error in delete_subdomain: {e}', exc_info=True)
            conn.rollback()
            return {'error': f'Database error: {str(e)}'}, 500
        finally:
            conn.close()
    
    try:
        result, status_code = execute_with_retry(_delete_subdomain)
        return jsonify(result), status_code
    except Exception as e:
        logging.error(f'Error in delete_subdomain: {e}', exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/results')
def get_results():
    db_path = get_db_path()
    if not db_path.exists():
        return jsonify({'domains': [], 'stats': {'total_domains': 0, 'total_urls': 0, 'total_keys': 0, 'total_providers': 0}})
    
    def _get_results():
        conn = get_db_connection(db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scans'")
            if not cursor.fetchone():
                return {'domains': [], 'stats': {'total_domains': 0, 'total_urls': 0, 'total_keys': 0, 'total_providers': 0}}
            
            # Get all scans that have findings (including running scans)
            # Use a simpler approach: get all scans, then filter to those with findings
            try:
                # First get all scan_ids that have findings
                cursor.execute('''
                    SELECT DISTINCT u.scan_id
                    FROM urls u
                    INNER JOIN api_keys k ON u.url_id = k.url_id
                    WHERE k.false_positive = 0
                ''')
                scan_ids_with_findings = [row[0] for row in cursor.fetchall()]
                
                if not scan_ids_with_findings:
                    return {'domains': [], 'stats': {'total_domains': 0, 'total_urls': 0, 'total_keys': 0, 'total_providers': 0}}
                
                # Get domains for those scans
                placeholders = ','.join('?' * len(scan_ids_with_findings))
                cursor.execute(f'''
                    SELECT DISTINCT domain, scan_id
                    FROM scans
                    WHERE scan_id IN ({placeholders})
                    ORDER BY domain, scan_id DESC
                ''', scan_ids_with_findings)
                domains_data = cursor.fetchall()
            except sqlite3.Error as e:
                logging.error(f"SQL error in get_results query: {e}", exc_info=True)
                return {'domains': [], 'stats': {'total_domains': 0, 'total_urls': 0, 'total_keys': 0, 'total_providers': 0}}
            
            results = {}
            total_urls = 0
            total_keys = 0
            providers_set = set()
            processed_urls = set()  # Track URLs across all scans to avoid double counting
            
            for domain_row in domains_data:
                try:
                    domain = domain_row['domain']
                    scan_id = domain_row['scan_id']
                    
                    if domain not in results:
                        results[domain] = {'domain': domain, 'scan_ids': [], 'api_keys_found': {}}
                    
                    if scan_id not in results[domain]['scan_ids']:
                        results[domain]['scan_ids'].append(scan_id)
                    
                    # Get only URLs that have findings for this scan
                    try:
                        cursor.execute('''
                            SELECT DISTINCT u.url_id, u.url
                            FROM urls u
                            JOIN api_keys k ON u.url_id = k.url_id
                            WHERE u.scan_id = ? AND k.false_positive = 0
                        ''', (scan_id,))
                        urls_data = cursor.fetchall()
                    except sqlite3.Error as e:
                        logging.error(f"Error fetching URLs for scan {scan_id}: {e}")
                        continue
                    
                    for url_row in urls_data:
                        try:
                            url_id = url_row['url_id']
                            url = url_row['url']
                            
                            # Count URL only once across all scans
                            if url not in processed_urls:
                                total_urls += 1
                                processed_urls.add(url)
                            
                            if url not in results[domain]['api_keys_found']:
                                results[domain]['api_keys_found'][url] = {}
                            
                            try:
                                cursor.execute('''
                                    SELECT key_id, provider, key_value, severity, false_positive, verified, validation_status, notes 
                                    FROM api_keys WHERE url_id = ? AND false_positive = 0
                                ''', (url_id,))
                                keys_data = cursor.fetchall()
                            except sqlite3.Error as e:
                                logging.error(f"Error fetching keys for URL {url_id}: {e}")
                                continue
                            
                            for key_row in keys_data:
                                provider = key_row['provider']
                                key_value = key_row['key_value']
                                providers_set.add(provider)
                                total_keys += 1
                                
                                if provider not in results[domain]['api_keys_found'][url]:
                                    results[domain]['api_keys_found'][url][provider] = {'keys': []}
                                
                                # Get values from Row object (sqlite3.Row doesn't have .get() method)
                                # Access columns directly - if NULL, they'll be None
                                validation_status = key_row['validation_status'] if key_row['validation_status'] else 'manual'
                                notes = key_row['notes'] if key_row['notes'] else ''
                                
                                results[domain]['api_keys_found'][url][provider]['keys'].append({
                                    'key_id': key_row['key_id'],
                                    'key_value': key_value,
                                    'severity': key_row['severity'] or 'medium',
                                    'false_positive': bool(key_row['false_positive']),
                                    'verified': bool(key_row['verified']),
                                    'validation_status': validation_status,
                                    'notes': notes
                                })
                        except Exception as e:
                            logging.error(f"Error processing URL row: {e}", exc_info=True)
                            continue
                except Exception as e:
                    logging.error(f"Error processing domain row: {e}", exc_info=True)
                    continue
            
            return {
                'domains': list(results.values()),
                'stats': {
                    'total_domains': len(results),
                    'total_urls': total_urls,
                    'total_keys': total_keys,
                    'total_providers': len(providers_set)
                }
            }
        finally:
            conn.close()
    
    try:
        result = execute_with_retry(_get_results)
        if not result:
            return jsonify({'domains': [], 'stats': {'total_domains': 0, 'total_urls': 0, 'total_keys': 0, 'total_providers': 0}})
        return jsonify(result)
    except Exception as e:
        logging.error(f"Error in get_results: {e}", exc_info=True)
        # Return empty results instead of 500 to prevent breaking the UI
        return jsonify({'domains': [], 'stats': {'total_domains': 0, 'total_urls': 0, 'total_keys': 0, 'total_providers': 0}})

def _calculate_stats():
    """Calculate current stats from database - matches findings query logic."""
    db_path = get_db_path()
    if not db_path.exists():
        return {'total_domains': 0, 'total_subdomains': 0, 'total_urls': 0, 'total_keys': 0, 'total_providers': 0}
    
    try:
        conn = get_db_connection(db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scans'")
            if not cursor.fetchone():
                return {'total_domains': 0, 'total_subdomains': 0, 'total_urls': 0, 'total_keys': 0, 'total_providers': 0}
            
            # Count distinct domains (targets) - all scans, including running ones
            cursor.execute('SELECT COUNT(DISTINCT domain) FROM scans')
            result = cursor.fetchone()
            total_domains = result[0] if result and result[0] is not None else 0
            
            # Count total subdomains from all per-scan databases
            # Subdomains are stored in per-domain databases (bughunter_{domain}.db), not main DB
            total_subdomains = 0
            all_subdomains = set()
            
            # Get all unique domains and their output directories
            cursor.execute('SELECT DISTINCT domain, output_dir FROM scans WHERE output_dir IS NOT NULL')
            domain_outputs = cursor.fetchall()
            
            # Also check default output directory
            default_output = Path("output")
            output_dirs = set()
            if domain_outputs:
                for row in domain_outputs:
                    output_dir = row[1] if row[1] else "output"
                    output_dirs.add(Path(output_dir))
            else:
                output_dirs.add(default_output)
            
            # Count subdomains from all per-domain databases
            for output_dir in output_dirs:
                if not output_dir.exists():
                    continue
                # Find all bughunter_*.db files in this output directory
                for db_file in output_dir.glob("bughunter_*.db"):
                    try:
                        scan_conn = sqlite3.connect(str(db_file), timeout=5.0)
                        scan_conn.row_factory = sqlite3.Row
                        scan_cursor = scan_conn.cursor()
                        try:
                            # Check if subdomains table exists
                            scan_cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='subdomains'")
                            if scan_cursor.fetchone():
                                scan_cursor.execute('SELECT DISTINCT subdomain FROM subdomains')
                                subdomain_rows = scan_cursor.fetchall()
                                for subdomain_row in subdomain_rows:
                                    if subdomain_row[0]:
                                        all_subdomains.add(subdomain_row[0])
                        finally:
                            scan_conn.close()
                    except Exception as e:
                        # Skip databases that can't be accessed
                        continue
                
                # Also check default bughunter.db in this output directory
                default_db = output_dir / "bughunter.db"
                if default_db.exists():
                    try:
                        scan_conn = sqlite3.connect(str(default_db), timeout=5.0)
                        scan_conn.row_factory = sqlite3.Row
                        scan_cursor = scan_conn.cursor()
                        try:
                            scan_cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='subdomains'")
                            if scan_cursor.fetchone():
                                scan_cursor.execute('SELECT DISTINCT subdomain FROM subdomains')
                                subdomain_rows = scan_cursor.fetchall()
                                for subdomain_row in subdomain_rows:
                                    if subdomain_row[0]:
                                        all_subdomains.add(subdomain_row[0])
                        finally:
                            scan_conn.close()
                    except Exception:
                        pass
            
            total_subdomains = len(all_subdomains)
            
            # Count total URLs - all URLs
            cursor.execute('SELECT COUNT(DISTINCT url_id) FROM urls')
            result = cursor.fetchone()
            total_urls = result[0] if result and result[0] is not None else 0
            
            # Count total keys (findings, excluding false positives) - same as findings query
            cursor.execute('SELECT COUNT(*) FROM api_keys WHERE false_positive = 0')
            result = cursor.fetchone()
            total_keys = result[0] if result and result[0] is not None else 0
            
            # Count distinct providers (excluding false positives) - same as findings query
            cursor.execute('SELECT COUNT(DISTINCT provider) FROM api_keys WHERE false_positive = 0')
            result = cursor.fetchone()
            total_providers = result[0] if result and result[0] is not None else 0
            
            return {
                'total_domains': total_domains,
                'total_subdomains': total_subdomains,
                'total_urls': total_urls,
                'total_keys': total_keys,
                'total_providers': total_providers
            }
        finally:
            conn.close()
    except Exception as e:
        logging.error(f"Error calculating stats: {e}", exc_info=True)
        return {'total_domains': 0, 'total_subdomains': 0, 'total_urls': 0, 'total_keys': 0, 'total_providers': 0}

@app.route('/api/stats')
def get_stats():
    """Get current stats (for initial page load)."""
    stats = _calculate_stats()
    system_stats = _calculate_system_stats()
    stats['system'] = system_stats
    return jsonify(stats)

def _calculate_system_stats():
    """Calculate system resource usage stats."""
    if not PSUTIL_AVAILABLE:
        # Even without psutil, we can still calculate output folder size
        output_dir = Path("output")
        output_folder_size = 0
        output_file_count = 0
        
        if output_dir.exists():
            for file_path in output_dir.rglob('*'):
                try:
                    if file_path.is_file():
                        output_folder_size += file_path.stat().st_size
                        output_file_count += 1
                except (OSError, PermissionError):
                    pass
        
        output_folder_size_gb = output_folder_size / (1024**3)
        output_folder_size_mb = output_folder_size / (1024**2)
        output_folder_size_kb = output_folder_size / 1024
        
        return {
            'cpu': {'percent': 0, 'count': 0},
            'ram': {'total_gb': 0, 'used_gb': 0, 'available_gb': 0, 'percent': 0},
            'network': {'sent_mb': 0, 'recv_mb': 0, 'sent_gb': 0, 'recv_gb': 0},
            'output_folder': {
                'size_gb': round(output_folder_size_gb, 2),
                'size_mb': round(output_folder_size_mb, 2),
                'size_kb': round(output_folder_size_kb, 2),
                'size_bytes': output_folder_size,
                'file_count': output_file_count
            }
        }
    
    try:
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=0.1)
        cpu_count = psutil.cpu_count()
        
        # RAM usage
        memory = psutil.virtual_memory()
        ram_total_gb = memory.total / (1024**3)
        ram_used_gb = memory.used / (1024**3)
        ram_percent = memory.percent
        ram_available_gb = memory.available / (1024**3)
        
        # Network stats
        net_io = psutil.net_io_counters()
        network_sent_mb = net_io.bytes_sent / (1024**2)
        network_recv_mb = net_io.bytes_recv / (1024**2)
        
        # Output folder size - measure only the output directory
        output_dir = Path("output")
        output_folder_size = 0
        output_file_count = 0
        
        if output_dir.exists():
            # Calculate size of output directory (all database files and other files)
            for file_path in output_dir.rglob('*'):
                try:
                    if file_path.is_file():
                        output_folder_size += file_path.stat().st_size
                        output_file_count += 1
                except (OSError, PermissionError):
                    pass
        
        # Convert output folder size to GB, MB, KB
        output_folder_size_gb = output_folder_size / (1024**3)
        output_folder_size_mb = output_folder_size / (1024**2)
        output_folder_size_kb = output_folder_size / 1024
        
        return {
            'cpu': {
                'percent': round(cpu_percent, 1),
                'count': cpu_count
            },
            'ram': {
                'total_gb': round(ram_total_gb, 2),
                'used_gb': round(ram_used_gb, 2),
                'available_gb': round(ram_available_gb, 2),
                'percent': round(ram_percent, 1)
            },
            'network': {
                'sent_mb': round(network_sent_mb, 2),
                'recv_mb': round(network_recv_mb, 2),
                'sent_gb': round(network_sent_mb / 1024, 2),
                'recv_gb': round(network_recv_mb / 1024, 2)
            },
            'output_folder': {
                'size_gb': round(output_folder_size_gb, 2),
                'size_mb': round(output_folder_size_mb, 2),
                'size_kb': round(output_folder_size_kb, 2),
                'size_bytes': output_folder_size,
                'file_count': output_file_count
            }
        }
    except ImportError:
        # psutil not available
        return {
            'cpu': {'percent': 0, 'count': 0},
            'ram': {'total_gb': 0, 'used_gb': 0, 'available_gb': 0, 'percent': 0},
            'network': {'sent_mb': 0, 'recv_mb': 0, 'sent_gb': 0, 'recv_gb': 0},
            'output_folder': {'size_gb': 0, 'size_mb': 0, 'size_kb': 0, 'size_bytes': 0, 'file_count': 0}
        }
    except Exception as e:
        logging.error(f"Error calculating system stats: {e}", exc_info=True)
        return {
            'cpu': {'percent': 0, 'count': 0},
            'ram': {'total_gb': 0, 'used_gb': 0, 'available_gb': 0, 'percent': 0},
            'network': {'sent_mb': 0, 'recv_mb': 0, 'sent_gb': 0, 'recv_gb': 0},
            'output_folder': {'size_gb': 0, 'size_mb': 0, 'size_kb': 0, 'size_bytes': 0, 'file_count': 0}
        }

@app.route('/api/system-stats')
def get_system_stats():
    """Get current system resource usage stats."""
    stats = _calculate_system_stats()
    return jsonify(stats)

@app.route('/api/stats/stream')
def stream_stats():
    """Stream real-time stats updates via Server-Sent Events."""
    def generate():
        last_stats = None
        first_send = True
        while True:
            try:
                current_stats = _calculate_stats()
                system_stats = _calculate_system_stats()
                
                # Merge system stats with scan stats
                current_stats['system'] = system_stats
                
                # Always send on first connection, then only if stats changed
                # Compare stats as strings to ensure proper comparison
                current_stats_str = json.dumps(current_stats, sort_keys=True)
                last_stats_str = json.dumps(last_stats, sort_keys=True) if last_stats else None
                
                if first_send or current_stats_str != last_stats_str:
                    yield f"data: {json.dumps(current_stats)}\n\n"
                    last_stats = current_stats.copy() if current_stats else None
                    first_send = False
                
                time.sleep(1)  # Update every second
            except GeneratorExit:
                break
            except Exception as e:
                logging.error(f"Error in stats stream: {e}", exc_info=True)
                time.sleep(1)
    
    response = Response(generate(), mimetype='text/event-stream')
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['Connection'] = 'keep-alive'
    response.headers['X-Accel-Buffering'] = 'no'
    return response

@app.route('/api/findings/<int:key_id>', methods=['GET'])
def get_finding(key_id):
    db_path = get_db_path()
    if not db_path.exists():
        return jsonify({'error': 'Database not found'}), 404
    
    def _get_finding():
        conn = get_db_connection(db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT k.key_id, k.provider, k.key_value, k.severity, k.false_positive, k.verified, k.validation_status, k.notes, k.found_at,
                       u.url, u.url_id, s.domain, s.scan_id
                FROM api_keys k
                JOIN urls u ON k.url_id = u.url_id
                JOIN scans s ON u.scan_id = s.scan_id
                WHERE k.key_id = ?
            ''', (key_id,))
            row = cursor.fetchone()
            if not row:
                return {'error': 'Finding not found'}, 404
            return convert_row_to_dict(row), 200
        finally:
            conn.close()
    
    try:
        result, status_code = execute_with_retry(_get_finding)
        return jsonify(result), status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/findings/<int:key_id>', methods=['PUT'])
def update_finding(key_id):
    data = request.json
    
    db_path = get_db_path()
    if not db_path.exists():
        return jsonify({'error': 'Database not found'}), 404
    
    def _update_finding():
        conn = get_db_connection(db_path)
        try:
            cursor = conn.cursor()
            updates = []
            values = []
            
            if 'severity' in data:
                if data['severity'] not in ['critical', 'high', 'medium', 'low', 'info']:
                    return {'error': 'Invalid severity'}, 400
                updates.append('severity = ?')
                values.append(data['severity'])
            
            if 'false_positive' in data:
                updates.append('false_positive = ?')
                values.append(1 if data['false_positive'] else 0)
            
            if 'verified' in data:
                updates.append('verified = ?')
                values.append(1 if data['verified'] else 0)
            
            if 'notes' in data:
                updates.append('notes = ?')
                values.append(data['notes'])
            
            if not updates:
                return {'error': 'No fields to update'}, 400
            
            values.append(key_id)
            cursor.execute(f'''
                UPDATE api_keys 
                SET {', '.join(updates)}
                WHERE key_id = ?
            ''', values)
            conn.commit()
            return {'success': True, 'message': 'Finding updated'}, 200
        finally:
            conn.close()
    
    try:
        result, status_code = execute_with_retry(_update_finding)
        return jsonify(result), status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/findings/<int:key_id>', methods=['DELETE'])
def delete_finding(key_id):
    db_path = get_db_path()
    if not db_path.exists():
        return jsonify({'error': 'Database not found'}), 404
    
    def _delete_finding():
        conn = get_db_connection(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM api_keys WHERE key_id = ?', (key_id,))
            if cursor.rowcount == 0:
                return {'error': 'Finding not found'}, 404
            conn.commit()
            return {'success': True, 'message': 'Finding deleted'}, 200
        finally:
            conn.close()
    
    try:
        result, status_code = execute_with_retry(_delete_finding)
        return jsonify(result), status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/findings', methods=['GET'])
def list_findings():
    db_path = get_db_path()
    if not db_path.exists():
        return jsonify({'findings': []})
    
    def _list_findings():
        conn = get_db_connection(db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            severity = request.args.get('severity')
            false_positive = request.args.get('false_positive')
            domain = request.args.get('domain')
            provider = request.args.get('provider')
            limit = int(request.args.get('limit', 100))
            offset = int(request.args.get('offset', 0))
            
            query = '''
                SELECT k.key_id, k.provider, k.key_value, k.severity, k.false_positive, k.verified, k.validation_status, k.notes, k.found_at,
                       u.url, u.url_id, s.domain, s.scan_id
                FROM api_keys k
                JOIN urls u ON k.url_id = u.url_id
                JOIN scans s ON u.scan_id = s.scan_id
                WHERE 1=1
            '''
            params = []
            
            if severity:
                query += ' AND k.severity = ?'
                params.append(severity)
            
            if false_positive is not None:
                query += ' AND k.false_positive = ?'
                params.append(1 if false_positive == 'true' else 0)
            
            verified = request.args.get('verified')
            if verified is not None:
                query += ' AND k.verified = ?'
                params.append(1 if verified == 'true' else 0)
            
            if domain:
                query += ' AND s.domain LIKE ? COLLATE NOCASE'
                params.append(f'%{domain}%')
            
            if provider:
                query += ' AND k.provider LIKE ? COLLATE NOCASE'
                params.append(f'%{provider}%')
            
            query += ' ORDER BY k.found_at DESC LIMIT ? OFFSET ?'
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            findings = [convert_row_to_dict(row) for row in rows]
            return {'findings': findings}
        finally:
            conn.close()
    
    try:
        result = execute_with_retry(_list_findings)
        return jsonify(result if result else {'findings': []})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/findings/bulk', methods=['POST'])
def bulk_update_findings():
    data = request.json
    key_ids = data.get('key_ids', [])
    updates = data.get('updates', {})
    
    if not key_ids:
        return jsonify({'error': 'No key IDs provided'}), 400
    
    db_path = get_db_path()
    if not db_path.exists():
        return jsonify({'error': 'Database not found'}), 404
    
    def _bulk_update():
        conn = get_db_connection(db_path)
        try:
            cursor = conn.cursor()
            update_fields = []
            values = []
            
            if 'severity' in updates:
                if updates['severity'] not in ['critical', 'high', 'medium', 'low', 'info']:
                    return {'error': 'Invalid severity'}, 400
                update_fields.append('severity = ?')
                values.append(updates['severity'])
            
            if 'false_positive' in updates:
                update_fields.append('false_positive = ?')
                values.append(1 if updates['false_positive'] else 0)
            
            if 'verified' in updates:
                update_fields.append('verified = ?')
                values.append(1 if updates['verified'] else 0)
            
            if 'notes' in updates:
                update_fields.append('notes = ?')
                values.append(updates['notes'])
            
            if not update_fields:
                return {'error': 'No fields to update'}, 400
            
            placeholders = ','.join('?' * len(key_ids))
            values.extend(key_ids)
            
            cursor.execute(f'''
                UPDATE api_keys 
                SET {', '.join(update_fields)}
                WHERE key_id IN ({placeholders})
            ''', values)
            
            conn.commit()
            return {'success': True, 'updated': cursor.rowcount}, 200
        finally:
            conn.close()
    
    try:
        result, status_code = execute_with_retry(_bulk_update)
        return jsonify(result), status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/findings/bulk', methods=['DELETE'])
def bulk_delete_findings():
    data = request.json
    key_ids = data.get('key_ids', [])
    
    if not key_ids:
        return jsonify({'error': 'No key IDs provided'}), 400
    
    # Convert all key_ids to integers and filter out any invalid values
    try:
        key_ids = [int(kid) for kid in key_ids if kid is not None]
    except (ValueError, TypeError) as e:
        return jsonify({'error': f'Invalid key IDs: {str(e)}'}), 400
    
    if not key_ids:
        return jsonify({'error': 'No valid key IDs provided'}), 400
    
    db_path = get_db_path()
    if not db_path.exists():
        return jsonify({'error': 'Database not found'}), 404
    
    def _bulk_delete():
        conn = get_db_connection(db_path)
        try:
            cursor = conn.cursor()
            
            # Ensure key_ids is a tuple for proper parameter binding
            key_ids_tuple = tuple(key_ids)
            
            if not key_ids_tuple:
                return {'success': True, 'deleted': 0, 'requested': len(key_ids), 'message': 'No valid key IDs'}, 200
            
            # First, count how many will be deleted (for verification)
            placeholders = ','.join('?' * len(key_ids_tuple))
            cursor.execute(f'SELECT COUNT(*) FROM api_keys WHERE key_id IN ({placeholders})', key_ids_tuple)
            count_before = cursor.fetchone()[0]
            
            if count_before == 0:
                return {'success': True, 'deleted': 0, 'requested': len(key_ids), 'message': 'No matching findings found'}, 200
            
            # Delete all findings at once - use tuple for proper parameter binding
            # Use the same placeholders string
            cursor.execute(f'DELETE FROM api_keys WHERE key_id IN ({placeholders})', key_ids_tuple)
            
            # Verify deletion count - sometimes rowcount isn't reliable in SQLite
            # So we verify by counting remaining
            cursor.execute(f'SELECT COUNT(*) FROM api_keys WHERE key_id IN ({placeholders})', key_ids_tuple)
            count_after = cursor.fetchone()[0]
            actual_deleted = count_before - count_after
            
            logging.info(f'Bulk delete: requested {len(key_ids)}, found {count_before}, deleted {actual_deleted}')
            
            if actual_deleted != count_before:
                logging.warning(f'Bulk delete mismatch: expected {count_before}, actually deleted {actual_deleted} rows')
            
            conn.commit()
            return {'success': True, 'deleted': actual_deleted, 'requested': len(key_ids)}, 200
        except sqlite3.Error as e:
            logging.error(f'SQL error in bulk delete: {e}', exc_info=True)
            conn.rollback()
            return {'error': f'Database error: {str(e)}'}, 500
        finally:
            conn.close()
    
    try:
        result, status_code = execute_with_retry(_bulk_delete)
        return jsonify(result), status_code
    except Exception as e:
        logging.error(f'Error in bulk_delete_findings: {e}', exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/targets', methods=['GET'])
def get_targets():
    """Get all targets with their subdomains, URLs, and findings."""
    # Check both main database and per-domain databases in output directory
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)
    
    targets = {}
    
    # First, scan per-domain database files in output directory
    for db_file in output_dir.glob("bughunter_*.db"):
        try:
            # Extract domain from filename: bughunter_{domain}.db
            domain_part = db_file.stem.replace("bughunter_", "")
            # Reverse the sanitization: replace underscores with dots (approximation)
            # Note: This is not perfect, but it's the best we can do from filename
            domain = domain_part.replace("_", ".")
            
            # Initialize database schema if needed
            try:
                from bughunter import database
                database.init_database_with_checkpoints(str(db_file))
            except Exception as e:
                logging.error(f"Error initializing database {db_file}: {e}", exc_info=True)
                continue
            
            # Connect to per-domain database
            conn = get_db_connection(db_file, timeout=10.0)
            conn.row_factory = sqlite3.Row
            try:
                cursor = conn.cursor()
                
                # Check if scans table exists
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scans'")
                if not cursor.fetchone():
                    continue
                
                # Get all scans for this domain
                cursor.execute('SELECT scan_id, domain FROM scans ORDER BY scan_id')
                scans = cursor.fetchall()
                
                # If no scans but database has URLs/subdomains, create a scan record or use existing data
                if not scans:
                    # Check if there's any data (URLs or subdomains) in this database
                    cursor.execute('SELECT COUNT(*) FROM urls')
                    url_count = cursor.fetchone()[0]
                    cursor.execute('SELECT COUNT(*) FROM subdomains')
                    subdomain_count = cursor.fetchone()[0]
                    
                    if url_count > 0 or subdomain_count > 0:
                        # Database has data but no scan record - create one
                        try:
                            cursor.execute('''
                                INSERT INTO scans (domain, scan_type, status, output_dir, start_time)
                                VALUES (?, 'domain', 'completed', 'output', CURRENT_TIMESTAMP)
                            ''', (domain,))
                            conn.commit()
                            # Re-fetch scans
                            cursor.execute('SELECT scan_id, domain FROM scans ORDER BY scan_id')
                            scans = cursor.fetchall()
                        except Exception as e:
                            logging.error(f"Error creating scan record: {e}", exc_info=True)
                            # Continue anyway - we'll use the domain from filename
                            actual_domain = domain
                            if actual_domain not in targets:
                                targets[actual_domain] = {
                                    'domain': actual_domain,
                                    'subdomains': {},
                                    'total_urls': url_count,
                                    'total_findings': 0
                                }
                            continue
                    else:
                        # No scans and no data - skip this database
                        continue
                
                # Use the actual domain from the database if available
                actual_domain = scans[0]['domain'] if scans else domain
                
                if actual_domain not in targets:
                    targets[actual_domain] = {
                        'domain': actual_domain,
                        'subdomains': {},
                        'total_urls': 0,
                        'total_findings': 0
                    }
                
                # Process each scan in this database
                for scan_row in scans:
                    scan_id = scan_row['scan_id']
                    scan_domain = scan_row['domain']
                    
                    # Get URLs for this scan
                    cursor.execute('''
                        SELECT url_id, url, status_code, content_type
                        FROM urls WHERE scan_id = ?
                    ''', (scan_id,))
                    urls_data = cursor.fetchall()
                    
                    # Process URLs
                    for url_row in urls_data:
                        url_id = url_row['url_id']
                        url = url_row['url']
                        
                        # Count findings for this URL (check all finding types)
                        findings_count = 0
                        
                        # API keys
                        cursor.execute('''
                            SELECT COUNT(*) as count
                            FROM api_keys WHERE url_id = ? AND false_positive = 0
                        ''', (url_id,))
                        findings_count += cursor.fetchone()['count']
                        
                        # XSS findings
                        try:
                            cursor.execute('''
                                SELECT COUNT(*) as count
                                FROM xss_findings WHERE url_id = ?
                            ''', (url_id,))
                            findings_count += cursor.fetchone()['count']
                        except:
                            pass
                        
                        # Redirect findings
                        try:
                            cursor.execute('''
                                SELECT COUNT(*) as count
                                FROM redirect_findings WHERE url_id = ?
                            ''', (url_id,))
                            findings_count += cursor.fetchone()['count']
                        except:
                            pass
                        
                        targets[actual_domain]['total_findings'] += findings_count
                        
                        # Extract subdomain from URL
                        try:
                            from urllib.parse import urlparse
                            parsed = urlparse(url)
                            hostname = parsed.netloc or parsed.path.split('/')[0]
                            if ':' in hostname:
                                hostname = hostname.split(':')[0]
                            subdomain = hostname
                        except:
                            subdomain = actual_domain
                        
                        if subdomain not in targets[actual_domain]['subdomains']:
                            targets[actual_domain]['subdomains'][subdomain] = {
                                'subdomain': subdomain,
                                'urls': []
                            }
                        
                        targets[actual_domain]['subdomains'][subdomain]['urls'].append({
                            'url': url,
                            'status_code': url_row['status_code'],
                            'content_type': url_row['content_type']
                        })
                        
                        targets[actual_domain]['total_urls'] += 1
            finally:
                conn.close()
        except Exception as e:
            logging.error(f"Error reading per-domain database {db_file}: {e}", exc_info=True)
            continue
    
    # Also check main database for any additional targets
    db_path = get_db_path()
    if db_path.exists():
        def _get_targets_from_main():
            conn = get_db_connection(db_path)
            conn.row_factory = sqlite3.Row
            try:
                cursor = conn.cursor()
                
                # Check if scans table exists
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scans'")
                if not cursor.fetchone():
                    return
                
                # Get all domains from main database
                cursor.execute('''
                    SELECT DISTINCT domain, scan_id
                    FROM scans
                    ORDER BY domain
                ''')
                domains_data = cursor.fetchall()
                
                for domain_row in domains_data:
                    domain = domain_row['domain']
                    scan_id = domain_row['scan_id']
                    
                    if domain not in targets:
                        targets[domain] = {
                            'domain': domain,
                            'subdomains': {},
                            'total_urls': 0,
                            'total_findings': 0
                        }
                    
                    # Get URLs for this scan
                    cursor.execute('''
                        SELECT url_id, url, status_code, content_type
                        FROM urls WHERE scan_id = ?
                    ''', (scan_id,))
                    urls_data = cursor.fetchall()
                    
                    # Process URLs
                    for url_row in urls_data:
                        url_id = url_row['url_id']
                        url = url_row['url']
                        
                        # Count findings
                        cursor.execute('''
                            SELECT COUNT(*) as count
                            FROM api_keys WHERE url_id = ? AND false_positive = 0
                        ''', (url_id,))
                        findings_count = cursor.fetchone()['count']
                        targets[domain]['total_findings'] += findings_count
                        
                        # Extract subdomain from URL
                        try:
                            from urllib.parse import urlparse
                            parsed = urlparse(url)
                            hostname = parsed.netloc or parsed.path.split('/')[0]
                            if ':' in hostname:
                                hostname = hostname.split(':')[0]
                            subdomain = hostname
                        except:
                            subdomain = domain
                        
                        if subdomain not in targets[domain]['subdomains']:
                            targets[domain]['subdomains'][subdomain] = {
                                'subdomain': subdomain,
                                'urls': []
                            }
                        
                        targets[domain]['subdomains'][subdomain]['urls'].append({
                            'url': url,
                            'status_code': url_row['status_code'],
                            'content_type': url_row['content_type']
                        })
                        
                        targets[domain]['total_urls'] += 1
            finally:
                conn.close()
        
        try:
            execute_with_retry(_get_targets_from_main)
        except Exception as e:
            logging.error(f"Error reading main database: {e}", exc_info=True)
    
    # Convert to list format
    result = []
    for domain, data in targets.items():
        result.append({
            'domain': domain,
            'subdomains': list(data['subdomains'].values()),
            'total_urls': data['total_urls'],
            'total_findings': data['total_findings']
        })
    
    return jsonify({'targets': result})

@app.route('/api/targets', methods=['POST'])
def create_target():
    """Create a new target manually."""
    data = request.json
    domain = data.get('domain', '').strip()
    
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    db_path = get_db_path()
    if not db_path.exists():
        # Create database if it doesn't exist
        init_database()
    
    def _create_target():
        conn = get_db_connection(db_path)
        try:
            cursor = conn.cursor()
            
            # Check if target already exists in main database
            cursor.execute('SELECT COUNT(*) as count FROM scans WHERE domain = ?', (domain,))
            exists_in_main = cursor.fetchone()[0] > 0
            
            # Also check if per-domain database exists
            output_dir = Path("output")
            safe_domain = re.sub(r'[^\w\-_\.]', '_', domain)
            per_domain_db = output_dir / f"bughunter_{safe_domain}.db"
            exists_in_per_domain = False
            
            if per_domain_db.exists():
                # Initialize database schema if needed
                try:
                    from bughunter import database
                    database.init_database_with_checkpoints(str(per_domain_db))
                    # Check if it has scans or data
                    per_domain_conn = get_db_connection(per_domain_db, timeout=5.0)
                    try:
                        per_domain_cursor = per_domain_conn.cursor()
                        # Check for scans
                        per_domain_cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scans'")
                        if per_domain_cursor.fetchone():
                            per_domain_cursor.execute('SELECT COUNT(*) FROM scans WHERE domain = ?', (domain,))
                            scan_count = per_domain_cursor.fetchone()[0]
                            # Check for data (URLs or subdomains)
                            per_domain_cursor.execute('SELECT COUNT(*) FROM urls')
                            url_count = per_domain_cursor.fetchone()[0]
                            per_domain_cursor.execute('SELECT COUNT(*) FROM subdomains')
                            subdomain_count = per_domain_cursor.fetchone()[0]
                            
                            if scan_count > 0 or url_count > 0 or subdomain_count > 0:
                                exists_in_per_domain = True
                    finally:
                        per_domain_conn.close()
                except Exception as e:
                    logging.error(f"Error checking per-domain database: {e}", exc_info=True)
            
            if exists_in_main or exists_in_per_domain:
                # Target already exists - return success (don't error, just acknowledge it exists)
                # DO NOT create a new scan entry or overwrite existing data
                return {'success': True, 'domain': domain, 'already_exists': True}
            
            # Only create a new scan entry if target doesn't exist anywhere
            # This ensures we don't overwrite existing databases
            output_dir_str = "output"
            cursor.execute('''
                INSERT INTO scans (domain, scan_type, status, output_dir, start_time)
                VALUES (?, 'manual', 'pending', ?, CURRENT_TIMESTAMP)
            ''', (domain, output_dir_str))
            
            conn.commit()
            return {'success': True, 'domain': domain}
        finally:
            conn.close()
    
    try:
        result = execute_with_retry(_create_target)
        if isinstance(result, tuple) and len(result) == 2:
            return jsonify(result[0]), result[1]
        return jsonify(result)
    except Exception as e:
        logging.error(f"Error creating target: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/targets/<path:domain>', methods=['PUT'])
def rename_target(domain):
    """Rename a target domain."""
    data = request.json
    new_domain = data.get('domain', '').strip()
    
    if not new_domain:
        return jsonify({'error': 'New domain is required'}), 400
    
    if new_domain == domain:
        return jsonify({'error': 'New domain must be different'}), 400
    
    db_path = get_db_path()
    if not db_path.exists():
        return jsonify({'error': 'Database not found'}), 404
    
    def _rename_target():
        conn = get_db_connection(db_path)
        try:
            cursor = conn.cursor()
            
            # Check if new domain already exists
            cursor.execute('SELECT COUNT(*) as count FROM scans WHERE domain = ?', (new_domain,))
            exists = cursor.fetchone()[0] > 0
            
            if exists:
                return {'error': 'Target with new domain already exists'}, 409
            
            # Update all scans with this domain
            cursor.execute('UPDATE scans SET domain = ? WHERE domain = ?', (new_domain, domain))
            
            conn.commit()
            return {'success': True, 'old_domain': domain, 'new_domain': new_domain}
        finally:
            conn.close()
    
    try:
        result = execute_with_retry(_rename_target)
        if isinstance(result, tuple) and len(result) == 2:
            return jsonify(result[0]), result[1]
        return jsonify(result)
    except Exception as e:
        logging.error(f"Error renaming target: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/targets/<path:domain>', methods=['GET'])
def get_target(domain):
    """Get detailed information about a specific target."""
    # Check both main database and per-domain database
    output_dir = Path("output")
    safe_domain = re.sub(r'[^\w\-_\.]', '_', domain)
    per_domain_db = output_dir / f"bughunter_{safe_domain}.db"
    
    # Try per-domain database first (most likely location)
    db_path = per_domain_db if per_domain_db.exists() else get_db_path()
    
    if not db_path.exists():
        return jsonify({'error': 'Target not found'}), 404
    
    # Initialize database schema if it doesn't exist
    try:
        from bughunter import database
        database.init_database_with_checkpoints(str(db_path))
    except Exception as e:
        logging.error(f"Error initializing database {db_path}: {e}", exc_info=True)
    
    def _get_target():
        conn = get_db_connection(db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            
            # Check if scans table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scans'")
            if not cursor.fetchone():
                return {'error': 'Target not found'}, 404
            
            # Get all scans for this domain
            cursor.execute('SELECT scan_id FROM scans WHERE domain = ?', (domain,))
            scan_ids = [row[0] for row in cursor.fetchall()]
            
            if not scan_ids:
                return {'error': 'Target not found'}, 404
            
            # Get subdomains
            placeholders = ','.join('?' * len(scan_ids))
            cursor.execute(f'''
                SELECT DISTINCT subdomain
                FROM subdomains
                WHERE scan_id IN ({placeholders})
            ''', scan_ids)
            subdomains_data = cursor.fetchall()
            subdomains = [row[0] for row in subdomains_data] if subdomains_data else []
            
            # Get URLs
            cursor.execute(f'''
                SELECT url_id, url, status_code, content_type
                FROM urls
                WHERE scan_id IN ({placeholders})
            ''', scan_ids)
            urls_data = cursor.fetchall()
            urls = [dict(row) for row in urls_data]
            
            # Get findings using JOIN to avoid SQL variable limit
            # Instead of using IN with potentially thousands of URL IDs, 
            # we JOIN through scan_id which is much more efficient
            findings = []
            if scan_ids:
                # Use a JOIN to get findings directly without collecting all URL IDs
                # This avoids the SQLite limit of 999 variables
                # Get API key findings
                cursor.execute(f'''
                    SELECT k.key_id, k.url_id, k.provider, k.key_value, k.severity, 
                           k.false_positive, k.verified, k.validation_status, k.notes,
                           u.url, 'api_key' as finding_type
                    FROM api_keys k
                    INNER JOIN urls u ON k.url_id = u.url_id
                    WHERE u.scan_id IN ({placeholders}) AND k.false_positive = 0
                ''', scan_ids)
                findings_data = cursor.fetchall()
                findings.extend([dict(row) for row in findings_data])
                
                # Get XSS findings
                try:
                    cursor.execute(f'''
                        SELECT x.finding_id as key_id, x.url_id, 'XSS' as provider, x.payload as key_value, 
                               x.severity, x.false_positive, x.verified, 'manual' as validation_status, 
                               x.notes, u.url, 'xss' as finding_type
                        FROM xss_findings x
                        INNER JOIN urls u ON x.url_id = u.url_id
                        WHERE u.scan_id IN ({placeholders}) AND x.false_positive = 0
                    ''', scan_ids)
                    xss_findings = cursor.fetchall()
                    findings.extend([dict(row) for row in xss_findings])
                except:
                    pass
                
                # Get redirect findings
                try:
                    cursor.execute(f'''
                        SELECT r.finding_id as key_id, r.url_id, 'Open Redirect' as provider, r.payload as key_value, 
                               r.severity, r.false_positive, r.verified, 'manual' as validation_status, 
                               r.notes, u.url, 'redirect' as finding_type
                        FROM redirect_findings r
                        INNER JOIN urls u ON r.url_id = u.url_id
                        WHERE u.scan_id IN ({placeholders}) AND r.false_positive = 0
                    ''', scan_ids)
                    redirect_findings = cursor.fetchall()
                    findings.extend([dict(row) for row in redirect_findings])
                except:
                    pass
            
            return {
                'domain': domain,
                'subdomains': subdomains,
                'urls': urls,
                'findings': findings,
                'total_urls': len(urls),
                'total_findings': len(findings)
            }
        finally:
            conn.close()
    
    try:
        result = execute_with_retry(_get_target)
        if isinstance(result, tuple) and len(result) == 2:
            return jsonify(result[0]), result[1]
        return jsonify(result)
    except Exception as e:
        logging.error(f"Error getting target: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/targets/export', methods=['POST'])
def export_targets():
    """Export targets data in various formats."""
    data = request.json
    format_type = data.get('format', 'json')  # json, csv, txt
    scope = data.get('scope', 'all')  # all, target, subdomain
    target_domain = data.get('target_domain', None)
    target_subdomain = data.get('target_subdomain', None)
    
    db_path = get_db_path()
    if not db_path.exists():
        return jsonify({'error': 'Database not found'}), 404
    
    def _get_export_data():
        conn = get_db_connection(db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scans'")
            if not cursor.fetchone():
                return {'error': 'No data found'}, 404
            
            # Build query based on scope - include all scans with findings (not just completed)
            # This matches what's shown on the targets page
            if scope == 'target' and target_domain:
                cursor.execute('''
                    SELECT DISTINCT s.domain, s.scan_id
                    FROM scans s
                    INNER JOIN urls u ON s.scan_id = u.scan_id
                    INNER JOIN api_keys k ON u.url_id = k.url_id
                    WHERE k.false_positive = 0 AND s.domain = ?
                    ORDER BY s.domain
                ''', (target_domain,))
            elif scope == 'all':
                cursor.execute('''
                    SELECT DISTINCT s.domain, s.scan_id
                    FROM scans s
                    INNER JOIN urls u ON s.scan_id = u.scan_id
                    INNER JOIN api_keys k ON u.url_id = k.url_id
                    WHERE k.false_positive = 0
                    ORDER BY s.domain
                ''')
            else:
                # For subdomain scope, we'll filter in Python after extracting subdomains
                cursor.execute('''
                    SELECT DISTINCT s.domain, s.scan_id
                    FROM scans s
                    INNER JOIN urls u ON s.scan_id = u.scan_id
                    INNER JOIN api_keys k ON u.url_id = k.url_id
                    WHERE k.false_positive = 0
                    ORDER BY s.domain
                ''')
            
            domains_data = cursor.fetchall()
            export_data = []
            
            # Get unique domains
            unique_domains = set()
            for domain_row in domains_data:
                unique_domains.add(domain_row['domain'])
            
            for domain in unique_domains:
                # Get ALL URLs from ALL scans for this domain (not just scans with findings)
                # This ensures we export all subdomains and URLs
                if scope == 'target' and target_domain and domain != target_domain:
                    continue
                
                cursor.execute('''
                    SELECT u.url_id, u.url, u.status_code, u.content_type, u.scan_id
                    FROM urls u
                    INNER JOIN scans s ON u.scan_id = s.scan_id
                    WHERE s.domain = ?
                ''', (domain,))
                urls_data = cursor.fetchall()
                
                for url_row in urls_data:
                    url_id = url_row['url_id']
                    url = url_row['url']
                    
                    # Extract subdomain from URL
                    try:
                        from urllib.parse import urlparse
                        parsed = urlparse(url)
                        hostname = parsed.netloc or parsed.path.split('/')[0]
                        if ':' in hostname:
                            hostname = hostname.split(':')[0]
                        subdomain = hostname
                    except:
                        subdomain = domain
                    
                    # Filter by scope
                    if scope == 'subdomain':
                        if not target_subdomain or subdomain != target_subdomain:
                            continue
                    # scope == 'target' already filtered above
                    # scope == 'all' - no filtering needed
                    
                    # Get findings for this URL
                    cursor.execute('''
                        SELECT provider, key_value, severity, false_positive, verified, validation_status, notes
                        FROM api_keys WHERE url_id = ? AND false_positive = 0
                    ''', (url_id,))
                    keys_data = cursor.fetchall()
                    
                    # Always include URL (even without findings) to show all subdomains and URLs
                    findings = []
                    for key_row in keys_data:
                        findings.append({
                            'provider': key_row['provider'],
                            'key_value': key_row['key_value'],
                            'severity': key_row['severity'] or 'medium',
                            'verified': bool(key_row['verified']),
                            'validation_status': key_row['validation_status'] if key_row['validation_status'] else 'manual',
                            'notes': key_row['notes'] if key_row['notes'] else ''
                        })
                    
                    export_data.append({
                        'domain': domain,
                        'subdomain': subdomain,
                        'url': url,
                        'status_code': url_row['status_code'],
                        'content_type': url_row['content_type'],
                        'findings': findings,
                        'findings_count': len(findings)
                    })
            
            return export_data, 200
        finally:
            conn.close()
    
    try:
        export_data, status_code = execute_with_retry(_get_export_data)
        if status_code != 200:
            return jsonify(export_data), status_code
        
        # Format the data based on requested format
        if format_type == 'csv':
            import csv
            import io
            import json
            output = io.StringIO()
            if export_data:
                # Flatten findings for CSV - one row per finding, or one row per URL if no findings
                flattened_data = []
                for item in export_data:
                    if item['findings']:
                        # One row per finding
                        for finding in item['findings']:
                            flattened_data.append({
                                'domain': item['domain'],
                                'subdomain': item['subdomain'],
                                'url': item['url'],
                                'status_code': item['status_code'],
                                'content_type': item['content_type'],
                                'provider': finding['provider'],
                                'key_value': finding['key_value'],
                                'severity': finding['severity'],
                                'verified': finding['verified'],
                                'validation_status': finding['validation_status'],
                                'notes': finding['notes']
                            })
                    else:
                        # URL with no findings - still include it
                        flattened_data.append({
                            'domain': item['domain'],
                            'subdomain': item['subdomain'],
                            'url': item['url'],
                            'status_code': item['status_code'],
                            'content_type': item['content_type'],
                            'provider': '',
                            'key_value': '',
                            'severity': '',
                            'verified': '',
                            'validation_status': '',
                            'notes': ''
                        })
                
                if flattened_data:
                    writer = csv.DictWriter(output, fieldnames=flattened_data[0].keys())
                    writer.writeheader()
                    writer.writerows(flattened_data)
            return Response(output.getvalue(), mimetype='text/csv', 
                          headers={'Content-Disposition': 'attachment; filename=targets_export.csv'})
        
        elif format_type == 'txt':
            lines = []
            for item in export_data:
                lines.append(f"Domain: {item['domain']}")
                lines.append(f"Subdomain: {item['subdomain']}")
                lines.append(f"URL: {item['url']}")
                lines.append(f"Status Code: {item['status_code'] or 'N/A'}")
                lines.append(f"Content Type: {item['content_type'] or 'N/A'}")
                lines.append(f"Findings: {item['findings_count']}")
                if item['findings']:
                    lines.append("Findings Details:")
                    for finding in item['findings']:
                        lines.append(f"  - Provider: {finding['provider']}")
                        lines.append(f"    Key: {finding['key_value']}")
                        lines.append(f"    Severity: {finding['severity']}")
                        lines.append(f"    Verified: {finding['verified']}")
                        lines.append(f"    Validation: {finding['validation_status']}")
                        if finding['notes']:
                            lines.append(f"    Notes: {finding['notes']}")
                else:
                    lines.append("  No findings")
                lines.append("-" * 80)
            return Response('\n'.join(lines), mimetype='text/plain',
                          headers={'Content-Disposition': 'attachment; filename=targets_export.txt'})
        
        else:  # json
            return jsonify({'data': export_data}), 200
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Config Management API Endpoints (Database-based)
@app.route('/api/config/api_patterns', methods=['GET'])
def get_api_patterns():
    """Get all API patterns from database."""
    db_path = get_db_path()
    
    def _get():
        conn = get_db_connection(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT pattern_id, provider, pattern, is_user_added, deleted_at, created_at, updated_at
            FROM config_api_patterns
            ORDER BY provider, pattern
        ''')
        
        patterns = []
        for row in cursor.fetchall():
            patterns.append({
                'id': row['pattern_id'],
                'provider': row['provider'],
                'pattern': row['pattern'],
                'is_user_added': bool(row['is_user_added']),
                'deleted_at': row['deleted_at'],
                'created_at': row['created_at'],
                'updated_at': row['updated_at']
            })
        
        conn.close()
        return patterns
    
    try:
        patterns = execute_with_retry(_get)
        return jsonify({'patterns': patterns})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/config/api_patterns', methods=['POST'])
def add_api_pattern():
    """Add a new API pattern."""
    data = request.json
    provider = data.get('provider', '').strip()
    pattern = data.get('pattern', '').strip()
    
    if not provider or not pattern:
        return jsonify({'error': 'Provider and pattern are required'}), 400
    
    db_path = get_db_path()
    
    def _add():
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO config_api_patterns (provider, pattern, is_user_added, created_at, updated_at)
                VALUES (?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ''', (provider, pattern))
            conn.commit()
            return cursor.lastrowid
        except sqlite3.IntegrityError:
            conn.rollback()
            raise ValueError(f"Pattern already exists for provider '{provider}'")
        finally:
            conn.close()
    
    try:
        pattern_id = execute_with_retry(_add)
        return jsonify({'success': True, 'id': pattern_id})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/config/api_patterns/<int:pattern_id>', methods=['PUT'])
def update_api_pattern(pattern_id):
    """Update an API pattern."""
    data = request.json
    provider = data.get('provider', '').strip()
    pattern = data.get('pattern', '').strip()
    
    if not provider or not pattern:
        return jsonify({'error': 'Provider and pattern are required'}), 400
    
    db_path = get_db_path()
    
    def _update():
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                UPDATE config_api_patterns
                SET provider = ?, pattern = ?, updated_at = CURRENT_TIMESTAMP
                WHERE pattern_id = ? AND deleted_at IS NULL
            ''', (provider, pattern, pattern_id))
            conn.commit()
            if cursor.rowcount == 0:
                raise ValueError('Pattern not found')
        finally:
            conn.close()
    
    try:
        execute_with_retry(_update)
        return jsonify({'success': True})
    except ValueError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/config/api_patterns/<int:pattern_id>', methods=['DELETE'])
def delete_api_pattern(pattern_id):
    """Soft delete an API pattern."""
    db_path = get_db_path()
    
    def _delete():
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                UPDATE config_api_patterns
                SET deleted_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                WHERE pattern_id = ? AND deleted_at IS NULL
            ''', (pattern_id,))
            conn.commit()
            if cursor.rowcount == 0:
                raise ValueError('Pattern not found')
        finally:
            conn.close()
    
    try:
        execute_with_retry(_delete)
        return jsonify({'success': True})
    except ValueError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/config/api_patterns/<int:pattern_id>/restore', methods=['POST'])
def restore_api_pattern(pattern_id):
    """Restore a soft-deleted API pattern."""
    db_path = get_db_path()
    
    def _restore():
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                UPDATE config_api_patterns
                SET deleted_at = NULL, updated_at = CURRENT_TIMESTAMP
                WHERE pattern_id = ?
            ''', (pattern_id,))
            conn.commit()
            if cursor.rowcount == 0:
                raise ValueError('Pattern not found')
        finally:
            conn.close()
    
    try:
        execute_with_retry(_restore)
        return jsonify({'success': True})
    except ValueError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/config/excluded_extensions', methods=['GET'])
def get_excluded_extensions():
    """Get all excluded extensions from database."""
    db_path = get_db_path()
    
    def _get():
        conn = get_db_connection(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT extension_id, extension, is_user_added, deleted_at, created_at, updated_at
            FROM config_excluded_extensions
            ORDER BY extension
        ''')
        
        extensions = []
        for row in cursor.fetchall():
            extensions.append({
                'id': row['extension_id'],
                'extension': row['extension'],
                'is_user_added': bool(row['is_user_added']),
                'deleted_at': row['deleted_at'],
                'created_at': row['created_at'],
                'updated_at': row['updated_at']
            })
        
        conn.close()
        return extensions
    
    try:
        extensions = execute_with_retry(_get)
        return jsonify({'extensions': extensions})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/config/excluded_extensions', methods=['POST'])
def add_excluded_extension():
    """Add a new excluded extension."""
    data = request.json
    extension = data.get('extension', '').strip().lstrip('.')
    
    if not extension:
        return jsonify({'error': 'Extension is required'}), 400
    
    db_path = get_db_path()
    
    def _add():
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO config_excluded_extensions (extension, is_user_added, created_at, updated_at)
                VALUES (?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ''', (extension,))
            conn.commit()
            return cursor.lastrowid
        except sqlite3.IntegrityError:
            conn.rollback()
            raise ValueError(f"Extension '{extension}' already exists")
        finally:
            conn.close()
    
    try:
        extension_id = execute_with_retry(_add)
        return jsonify({'success': True, 'id': extension_id})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/config/excluded_extensions/<int:extension_id>', methods=['DELETE'])
def delete_excluded_extension(extension_id):
    """Soft delete an excluded extension."""
    db_path = get_db_path()
    
    def _delete():
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                UPDATE config_excluded_extensions
                SET deleted_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                WHERE extension_id = ? AND deleted_at IS NULL
            ''', (extension_id,))
            conn.commit()
            if cursor.rowcount == 0:
                raise ValueError('Extension not found')
        finally:
            conn.close()
    
    try:
        execute_with_retry(_delete)
        return jsonify({'success': True})
    except ValueError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/config/excluded_extensions/<int:extension_id>/restore', methods=['POST'])
def restore_excluded_extension(extension_id):
    """Restore a soft-deleted excluded extension."""
    db_path = get_db_path()
    
    def _restore():
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                UPDATE config_excluded_extensions
                SET deleted_at = NULL, updated_at = CURRENT_TIMESTAMP
                WHERE extension_id = ?
            ''', (extension_id,))
            conn.commit()
            if cursor.rowcount == 0:
                raise ValueError('Extension not found')
        finally:
            conn.close()
    
    try:
        execute_with_retry(_restore)
        return jsonify({'success': True})
    except ValueError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/config/xss_payloads', methods=['GET'])
def get_xss_payloads():
    """Get all XSS payloads from database."""
    db_path = get_db_path()
    
    def _get():
        conn = get_db_connection(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT payload_id, payload, is_default, is_user_added, deleted_at, created_at, updated_at
            FROM config_xss_payloads
            ORDER BY is_default DESC, payload
        ''')
        
        payloads = []
        for row in cursor.fetchall():
            payloads.append({
                'id': row['payload_id'],
                'payload': row['payload'],
                'is_default': bool(row['is_default']),
                'is_user_added': bool(row['is_user_added']),
                'deleted_at': row['deleted_at'],
                'created_at': row['created_at'],
                'updated_at': row['updated_at']
            })
        
        conn.close()
        return payloads
    
    try:
        payloads = execute_with_retry(_get)
        return jsonify({'payloads': payloads})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/config/xss_payloads', methods=['POST'])
def add_xss_payload():
    """Add a new XSS payload."""
    data = request.json
    payload = data.get('payload', '').strip()
    is_default = data.get('is_default', False)
    
    if not payload:
        return jsonify({'error': 'Payload is required'}), 400
    
    db_path = get_db_path()
    
    def _add():
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        
        try:
            # If setting as default, unset other defaults first
            if is_default:
                cursor.execute('''
                    UPDATE config_xss_payloads
                    SET is_default = 0, updated_at = CURRENT_TIMESTAMP
                    WHERE is_default = 1 AND deleted_at IS NULL
                ''')
            
            cursor.execute('''
                INSERT INTO config_xss_payloads (payload, is_default, is_user_added, created_at, updated_at)
                VALUES (?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ''', (payload, 1 if is_default else 0))
            conn.commit()
            return cursor.lastrowid
        except sqlite3.IntegrityError:
            conn.rollback()
            raise ValueError("Payload already exists")
        finally:
            conn.close()
    
    try:
        payload_id = execute_with_retry(_add)
        return jsonify({'success': True, 'id': payload_id})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/config/xss_payloads/<int:payload_id>', methods=['PUT'])
def update_xss_payload(payload_id):
    """Update an XSS payload (and optionally set as default)."""
    data = request.json
    payload = data.get('payload', '').strip()
    is_default = data.get('is_default', False)
    
    if not payload:
        return jsonify({'error': 'Payload is required'}), 400
    
    db_path = get_db_path()
    
    def _update():
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        
        try:
            # If setting as default, unset other defaults first
            if is_default:
                cursor.execute('''
                    UPDATE config_xss_payloads
                    SET is_default = 0, updated_at = CURRENT_TIMESTAMP
                    WHERE is_default = 1 AND deleted_at IS NULL AND payload_id != ?
                ''', (payload_id,))
            
            cursor.execute('''
                UPDATE config_xss_payloads
                SET payload = ?, is_default = ?, updated_at = CURRENT_TIMESTAMP
                WHERE payload_id = ? AND deleted_at IS NULL
            ''', (payload, 1 if is_default else 0, payload_id))
            conn.commit()
            if cursor.rowcount == 0:
                raise ValueError('Payload not found')
        finally:
            conn.close()
    
    try:
        execute_with_retry(_update)
        return jsonify({'success': True})
    except ValueError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/config/xss_payloads/<int:payload_id>', methods=['DELETE'])
def delete_xss_payload(payload_id):
    """Soft delete an XSS payload."""
    db_path = get_db_path()
    
    def _delete():
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                UPDATE config_xss_payloads
                SET deleted_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                WHERE payload_id = ? AND deleted_at IS NULL
            ''', (payload_id,))
            conn.commit()
            if cursor.rowcount == 0:
                raise ValueError('Payload not found')
        finally:
            conn.close()
    
    try:
        execute_with_retry(_delete)
        return jsonify({'success': True})
    except ValueError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/config/xss_payloads/<int:payload_id>/restore', methods=['POST'])
def restore_xss_payload(payload_id):
    """Restore a soft-deleted XSS payload."""
    db_path = get_db_path()
    
    def _restore():
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                UPDATE config_xss_payloads
                SET deleted_at = NULL, updated_at = CURRENT_TIMESTAMP
                WHERE payload_id = ?
            ''', (payload_id,))
            conn.commit()
            if cursor.rowcount == 0:
                raise ValueError('Payload not found')
        finally:
            conn.close()
    
    try:
        execute_with_retry(_restore)
        return jsonify({'success': True})
    except ValueError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/config/sync', methods=['POST'])
def sync_configs_from_yaml():
    """Sync all configs from YAML files to database."""
    try:
        from bughunter.config_migration import sync_all_configs_from_yaml
        db_path = get_db_path()
        sync_all_configs_from_yaml(str(db_path))
        return jsonify({'success': True, 'message': 'Configs synced successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def load_running_scans():
    db_path = get_db_path()
    if not db_path.exists():
        return
    
    def _load_scans():
        conn = get_db_connection(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE web_scans SET status = 'lost' 
                WHERE status = 'running'
            ''')
            conn.commit()
        finally:
            conn.close()
    
    try:
        execute_with_retry(_load_scans)
    except:
        pass  # Ignore errors on startup

def get_latest_scan_for_domain(domain):
    """Get the latest web scan for a domain."""
    # Check both main database and per-domain database
    output_dir = Path("output")
    safe_domain = re.sub(r'[^\w\-_\.]', '_', domain)
    per_domain_db = output_dir / f"bughunter_{safe_domain}.db"
    
    # Try per-domain database first
    db_path = per_domain_db if per_domain_db.exists() else get_db_path()
    
    if not db_path.exists():
        return None
    
    def _get_scan():
        conn = get_db_connection(db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            
            # First try web_scans table (for GUI-initiated scans)
            try:
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='web_scans'")
                if cursor.fetchone():
                    cursor.execute('''
                        SELECT * FROM web_scans 
                        WHERE target = ? 
                        ORDER BY started_at DESC 
                        LIMIT 1
                    ''', (domain,))
                    row = cursor.fetchone()
                    if row:
                        return convert_row_to_dict(row)
            except:
                pass
            
            # Fallback to scans table (for CLI scans)
            try:
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scans'")
                if cursor.fetchone():
                    cursor.execute('''
                        SELECT scan_id, domain as target, scan_type, status, checkpoint, 
                               start_time as started_at, output_dir, NULL as options
                        FROM scans 
                        WHERE domain = ? 
                        ORDER BY start_time DESC 
                        LIMIT 1
                    ''', (domain,))
                    row = cursor.fetchone()
                    if row:
                        return convert_row_to_dict(row)
            except:
                pass
            
            return None
        finally:
            conn.close()
    
    return execute_with_retry(_get_scan)

@app.route('/api/targets/<path:domain>/scan-info', methods=['GET'])
def get_scan_info(domain):
    """Get the latest scan configuration for a domain (for rescan wizard)."""
    try:
        scan_data = get_latest_scan_for_domain(domain)
        if not scan_data:
            return jsonify({'error': 'No scan found for this domain'}), 404
        
        options = {}
        if scan_data.get('options'):
            try:
                options = json.loads(scan_data['options'])
            except:
                options = {}
        
        return jsonify({
            'target': scan_data['target'],
            'scan_type': scan_data.get('scan_type', 'domain'),
            'options': options,
            'output_dir': scan_data.get('output_dir', 'output')
        }), 200
    except Exception as e:
        logging.error(f"Error getting scan info: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/targets/<path:domain>/rescan', methods=['POST'])
def rescan_target(domain):
    """Re-scan existing URLs with new parameters (reuse collected URLs)."""
    try:
        scan_data = get_latest_scan_for_domain(domain)
        if not scan_data:
            return jsonify({'error': 'No scan found for this domain'}), 404
        
        target = scan_data['target']
        
        # Get new options from request body (if provided), otherwise use existing options
        new_options = {}
        if request.is_json and request.json:
            new_options = request.json.get('options', {})
        
        # Merge with existing options if new options not fully provided
        existing_options = {}
        if scan_data.get('options'):
            try:
                existing_options = json.loads(scan_data['options'])
            except:
                existing_options = {}
        
        # Use new options (they should be complete from the wizard)
        options = new_options if new_options else existing_options
        
        # Always disable subdomain enum when rescanning (reusing URLs)
        options['no_subs'] = True
        
        output_dir = scan_data.get('output_dir') or 'output'
        
        # Find the scan database path
        safe_domain = re.sub(r'[^\w\-_\.]', '_', target)
        scan_db_path = Path(output_dir) / f"bughunter_{safe_domain}.db"
        if not scan_db_path.exists():
            scan_db_path = Path(output_dir) / "bughunter.db"
        
        if scan_db_path.exists():
            # Reset all URLs to pending status so they will be re-scanned
            try:
                scan_conn = sqlite3.connect(str(scan_db_path), timeout=10.0)
                scan_cursor = scan_conn.cursor()
                scan_cursor.execute('UPDATE urls SET status = ? WHERE status = ?', ('pending', 'checked'))
                scan_cursor.execute('UPDATE urls SET status = ? WHERE status = ?', ('pending', 'failed'))
                scan_conn.commit()
                scan_conn.close()
            except Exception as e:
                logging.error(f"Error resetting URLs: {e}", exc_info=True)
        
        # Start a new scan with the same parameters (will resume and scan pending URLs)
        scan_type = scan_data.get('scan_type', 'domain')
        scan_id = str(uuid.uuid4())
        
        PROJECT_ROOT = Path(__file__).parent.parent
        script_path = PROJECT_ROOT / "BugHunterArsenal.py"
        cmd = [sys.executable, str(script_path)]
        
        if scan_type == 'domain':
            cmd.extend(['-d', target])
        elif scan_type == 'file':
            cmd.extend(['-f', target])
        elif scan_type == 'urls':
            cmd.extend(['-l', target])
        else:
            return jsonify({'error': 'Invalid scan type'}), 400
        
        if options.get('verbose'):
            cmd.append('-v')
        if options.get('no_subs'):
            cmd.append('--no-subs')
        if options.get('cookie'):
            cmd.extend(['--cookie', options['cookie']])
        if options.get('x_request_for'):
            cmd.extend(['--x-request-for', options['x_request_for']])
        if options.get('output'):
            cmd.extend(['-o', options['output']])
        
        tools = options.get('tools', ['keyhunter'])
        if isinstance(tools, list):
            tools_str = ','.join(tools)
        elif isinstance(tools, str):
            tools_str = tools
        else:
            tools_str = 'keyhunter'
        cmd.extend(['--tool', tools_str])
        
        # Start the scan
        env = os.environ.copy()
        env['PYTHONUNBUFFERED'] = '1'
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, universal_newlines=True,
            cwd=str(PROJECT_ROOT), env=env
        )
        
        with scan_lock:
            active_scans[scan_id] = {
                'process': process,
                'status': 'running',
                'started_at': datetime.now(timezone.utc)
            }
        
        save_scan_to_db(scan_id, scan_type, target, options, 'running', output_dir)
        
        thread = threading.Thread(target=read_scan_output, args=(scan_id, process), daemon=True)
        thread.start()
        
        new_scan_data = get_scan_from_db(scan_id)
        return jsonify({
            'scan_id': scan_id,
            'status': 'running',
            'started_at': new_scan_data['started_at'] if new_scan_data else datetime.now(timezone.utc).isoformat()
        }), 200
        
    except Exception as e:
        logging.error(f"Error in rescan_target: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/targets/<path:domain>/recrawl', methods=['POST'])
def recrawl_target(domain):
    """Re-crawl URLs from existing subdomains (keep subdomains, re-collect URLs)."""
    try:
        scan_data = get_latest_scan_for_domain(domain)
        if not scan_data:
            return jsonify({'error': 'No scan found for this domain'}), 404
        
        target = scan_data['target']
        options = {}
        if scan_data.get('options'):
            try:
                options = json.loads(scan_data['options'])
            except:
                options = {}
        output_dir = scan_data.get('output_dir') or 'output'
        
        # Find the scan database path
        safe_domain = re.sub(r'[^\w\-_\.]', '_', target)
        scan_db_path = Path(output_dir) / f"bughunter_{safe_domain}.db"
        if not scan_db_path.exists():
            scan_db_path = Path(output_dir) / "bughunter.db"
        
        if scan_db_path.exists():
            # Delete existing URLs but keep subdomains
            try:
                scan_conn = sqlite3.connect(str(scan_db_path), timeout=10.0)
                scan_cursor = scan_conn.cursor()
                # Reset subdomain URL collection status so URLs will be re-collected
                scan_cursor.execute('UPDATE subdomains SET waybackurls_done = 0, katana_done = 0, urls_collected_at = NULL')
                # Delete all URLs (cascade will handle api_keys)
                scan_cursor.execute('DELETE FROM urls')
                scan_conn.commit()
                scan_conn.close()
            except Exception as e:
                logging.error(f"Error clearing URLs: {e}", exc_info=True)
        
        # Start a new scan with the same parameters (will resume from URL collection)
        scan_type = scan_data.get('scan_type', 'domain')
        scan_id = str(uuid.uuid4())
        
        PROJECT_ROOT = Path(__file__).parent.parent
        script_path = PROJECT_ROOT / "BugHunterArsenal.py"
        cmd = [sys.executable, str(script_path)]
        
        if scan_type == 'domain':
            cmd.extend(['-d', target])
        elif scan_type == 'file':
            cmd.extend(['-f', target])
        elif scan_type == 'urls':
            cmd.extend(['-l', target])
        else:
            return jsonify({'error': 'Invalid scan type'}), 400
        
        if options.get('verbose'):
            cmd.append('-v')
        if options.get('no_subs'):
            cmd.append('--no-subs')
        if options.get('cookie'):
            cmd.extend(['--cookie', options['cookie']])
        if options.get('x_request_for'):
            cmd.extend(['--x-request-for', options['x_request_for']])
        if options.get('output'):
            cmd.extend(['-o', options['output']])
        
        tools = options.get('tools', ['keyhunter'])
        if isinstance(tools, list):
            tools_str = ','.join(tools)
        elif isinstance(tools, str):
            tools_str = tools
        else:
            tools_str = 'keyhunter'
        cmd.extend(['--tool', tools_str])
        
        # Start the scan
        env = os.environ.copy()
        env['PYTHONUNBUFFERED'] = '1'
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, universal_newlines=True,
            cwd=str(PROJECT_ROOT), env=env
        )
        
        with scan_lock:
            active_scans[scan_id] = {
                'process': process,
                'status': 'running',
                'started_at': datetime.now(timezone.utc)
            }
        
        save_scan_to_db(scan_id, scan_type, target, options, 'running', output_dir)
        
        thread = threading.Thread(target=read_scan_output, args=(scan_id, process), daemon=True)
        thread.start()
        
        new_scan_data = get_scan_from_db(scan_id)
        return jsonify({
            'scan_id': scan_id,
            'status': 'running',
            'started_at': new_scan_data['started_at'] if new_scan_data else datetime.now(timezone.utc).isoformat()
        }), 200
        
    except Exception as e:
        logging.error(f"Error in recrawl_target: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/targets/<path:domain>/rediscover', methods=['POST'])
def rediscover_target(domain):
    """Re-discover subdomains and crawl URLs (fresh start with same parameters)."""
    try:
        scan_data = get_latest_scan_for_domain(domain)
        if not scan_data:
            return jsonify({'error': 'No scan found for this domain'}), 404
        
        target = scan_data['target']
        options = {}
        if scan_data.get('options'):
            try:
                options = json.loads(scan_data['options'])
            except:
                options = {}
        output_dir = scan_data.get('output_dir') or 'output'
        
        # Start a new scan with --restart flag (will clear everything and start fresh)
        scan_type = scan_data.get('scan_type', 'domain')
        scan_id = str(uuid.uuid4())
        
        PROJECT_ROOT = Path(__file__).parent.parent
        script_path = PROJECT_ROOT / "BugHunterArsenal.py"
        cmd = [sys.executable, str(script_path)]
        
        if scan_type == 'domain':
            cmd.extend(['-d', target])
        elif scan_type == 'file':
            cmd.extend(['-f', target])
        elif scan_type == 'urls':
            cmd.extend(['-l', target])
        else:
            return jsonify({'error': 'Invalid scan type'}), 400
        
        # Add --restart flag to start fresh
        cmd.append('--restart')
        
        if options.get('verbose'):
            cmd.append('-v')
        if options.get('no_subs'):
            cmd.append('--no-subs')
        if options.get('cookie'):
            cmd.extend(['--cookie', options['cookie']])
        if options.get('x_request_for'):
            cmd.extend(['--x-request-for', options['x_request_for']])
        if options.get('output'):
            cmd.extend(['-o', options['output']])
        
        tools = options.get('tools', ['keyhunter'])
        if isinstance(tools, list):
            tools_str = ','.join(tools)
        elif isinstance(tools, str):
            tools_str = tools
        else:
            tools_str = 'keyhunter'
        cmd.extend(['--tool', tools_str])
        
        # Start the scan
        env = os.environ.copy()
        env['PYTHONUNBUFFERED'] = '1'
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, universal_newlines=True,
            cwd=str(PROJECT_ROOT), env=env
        )
        
        with scan_lock:
            active_scans[scan_id] = {
                'process': process,
                'status': 'running',
                'started_at': datetime.now(timezone.utc)
            }
        
        save_scan_to_db(scan_id, scan_type, target, options, 'running', output_dir)
        
        thread = threading.Thread(target=read_scan_output, args=(scan_id, process), daemon=True)
        thread.start()
        
        new_scan_data = get_scan_from_db(scan_id)
        return jsonify({
            'scan_id': scan_id,
            'status': 'running',
            'started_at': new_scan_data['started_at'] if new_scan_data else datetime.now(timezone.utc).isoformat()
        }), 200
        
    except Exception as e:
        logging.error(f"Error in rediscover_target: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

def start_output_writer():
    """Start the background output writer thread."""
    global output_writer_running
    with output_writer_lock:
        if not output_writer_running:
            output_writer_running = True
            writer_thread = threading.Thread(target=_batch_write_outputs, daemon=True)
            writer_thread.start()

if __name__ == '__main__':
    init_database()
    
    load_running_scans()
    
    # Start the output writer thread
    start_output_writer()
    
    print("[+] BugHunter Arsenal Web Server starting...")
    print("[+] Dashboard available at http://127.0.0.1:5000")
    print("[+] Press Ctrl+C to stop")
    
    try:
        app.run(
            host='127.0.0.1',
            port=5000,
            debug=False,
            threaded=True,
            request_handler=QuietWSGIRequestHandler,
            use_reloader=False,
            use_debugger=False
        )
    finally:
        # Stop the output writer when server shuts down
        output_writer_running = False
        # Wait for queue to empty (with timeout)
        timeout = 5
        start_time = time.time()
        while not output_queue.empty() and (time.time() - start_time) < timeout:
            time.sleep(0.1)

