"""
Config Migration Module
Handles migration of YAML config files to database with change detection and soft deletes
"""

import yaml
import sqlite3
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Set
from datetime import datetime
from .database import get_db_connection, retry_db_operation


def get_main_db_path() -> Path:
    """Get the main database path (bughunter.db in output directory)"""
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)
    return output_dir / "bughunter.db"


def sync_api_patterns_from_yaml(db_path: str, yaml_file: str):
    """
    Sync API patterns from YAML file to database.
    Adds new patterns, preserves user-added patterns, soft deletes removed patterns.
    """
    if not Path(yaml_file).exists():
        return
    
    def _sync():
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        
        try:
            # Load YAML data
            with open(yaml_file, 'r') as f:
                data = yaml.safe_load(f) or {}
            
            api_keys_data = data.get("api_keys", {})
            
            # Get current patterns from DB (not deleted, not user-added)
            cursor.execute('''
                SELECT provider, pattern FROM config_api_patterns
                WHERE deleted_at IS NULL AND is_user_added = 0
            ''')
            existing_patterns = {(row[0], row[1]) for row in cursor.fetchall()}
            
            # Get soft-deleted patterns (so we don't re-add them)
            cursor.execute('''
                SELECT provider, pattern FROM config_api_patterns
                WHERE deleted_at IS NOT NULL
            ''')
            deleted_patterns = {(row[0], row[1]) for row in cursor.fetchall()}
            
            # Extract patterns from YAML
            yaml_patterns = set()
            for provider, pattern in api_keys_data.items():
                if isinstance(pattern, dict):
                    # Handle nested patterns (e.g., Laravel Environment Variables)
                    for key, nested_pattern in pattern.items():
                        yaml_patterns.add((f"{provider} - {key}", nested_pattern))
                elif isinstance(pattern, str):
                    yaml_patterns.add((provider, pattern))
            
            # Find new patterns to add (in YAML but not in DB and not deleted)
            new_patterns = yaml_patterns - existing_patterns - deleted_patterns
            
            # Add new patterns
            for provider, pattern in new_patterns:
                cursor.execute('''
                    INSERT OR IGNORE INTO config_api_patterns (provider, pattern, is_user_added, created_at, updated_at)
                    VALUES (?, ?, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ''', (provider, pattern))
            
            # Soft delete patterns that are in DB but not in YAML (if not user-added)
            patterns_to_delete = existing_patterns - yaml_patterns
            if patterns_to_delete:
                placeholders = ','.join('?' * len(patterns_to_delete))
                # Create a list of tuples for IN clause
                delete_list = list(patterns_to_delete)
                # Use a subquery approach for better performance
                for provider, pattern in delete_list:
                    cursor.execute('''
                        UPDATE config_api_patterns
                        SET deleted_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                        WHERE provider = ? AND pattern = ? AND is_user_added = 0 AND deleted_at IS NULL
                    ''', (provider, pattern))
            
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    retry_db_operation(_sync)


def sync_excluded_extensions_from_yaml(db_path: str, yaml_file: str):
    """
    Sync excluded extensions from YAML file to database.
    Adds new extensions, preserves user-added extensions, soft deletes removed extensions.
    """
    if not Path(yaml_file).exists():
        return
    
    def _sync():
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        
        try:
            # Load YAML data
            with open(yaml_file, 'r') as f:
                data = yaml.safe_load(f) or {}
            
            yaml_extensions = set(data.get("excluded_extensions", []))
            
            # Get current extensions from DB (not deleted, not user-added)
            cursor.execute('''
                SELECT extension FROM config_excluded_extensions
                WHERE deleted_at IS NULL AND is_user_added = 0
            ''')
            existing_extensions = {row[0] for row in cursor.fetchall()}
            
            # Get soft-deleted extensions (so we don't re-add them)
            cursor.execute('''
                SELECT extension FROM config_excluded_extensions
                WHERE deleted_at IS NOT NULL
            ''')
            deleted_extensions = {row[0] for row in cursor.fetchall()}
            
            # Find new extensions to add
            new_extensions = yaml_extensions - existing_extensions - deleted_extensions
            
            # Add new extensions
            for ext in new_extensions:
                cursor.execute('''
                    INSERT OR IGNORE INTO config_excluded_extensions (extension, is_user_added, created_at, updated_at)
                    VALUES (?, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ''', (ext,))
            
            # Soft delete extensions that are in DB but not in YAML (if not user-added)
            extensions_to_delete = existing_extensions - yaml_extensions
            for ext in extensions_to_delete:
                cursor.execute('''
                    UPDATE config_excluded_extensions
                    SET deleted_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                    WHERE extension = ? AND is_user_added = 0 AND deleted_at IS NULL
                ''', (ext,))
            
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    retry_db_operation(_sync)


def sync_xss_payloads_from_yaml(db_path: str, yaml_file: str):
    """
    Sync XSS payloads from YAML file to database.
    Adds new payloads, preserves user-added payloads, soft deletes removed payloads.
    Sets default payload flag.
    """
    if not Path(yaml_file).exists():
        return
    
    def _sync():
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        
        try:
            # Load YAML data
            with open(yaml_file, 'r') as f:
                data = yaml.safe_load(f) or {}
            
            xss_config = data.get("xss_payloads", {})
            default_payload = xss_config.get("default", "")
            yaml_payloads = set(xss_config.get("payloads", []))
            if default_payload:
                yaml_payloads.add(default_payload)
            
            # Get current payloads from DB (not deleted, not user-added)
            cursor.execute('''
                SELECT payload, is_default FROM config_xss_payloads
                WHERE deleted_at IS NULL AND is_user_added = 0
            ''')
            existing_payloads = {row[0] for row in cursor.fetchall()}
            existing_default = None
            cursor.execute('''
                SELECT payload FROM config_xss_payloads
                WHERE deleted_at IS NULL AND is_default = 1
                LIMIT 1
            ''')
            row = cursor.fetchone()
            if row:
                existing_default = row[0]
            
            # Get soft-deleted payloads (so we don't re-add them)
            cursor.execute('''
                SELECT payload FROM config_xss_payloads
                WHERE deleted_at IS NOT NULL
            ''')
            deleted_payloads = {row[0] for row in cursor.fetchall()}
            
            # Find new payloads to add
            new_payloads = yaml_payloads - existing_payloads - deleted_payloads
            
            # Add new payloads
            for payload in new_payloads:
                is_default = 1 if payload == default_payload else 0
                cursor.execute('''
                    INSERT OR IGNORE INTO config_xss_payloads (payload, is_default, is_user_added, created_at, updated_at)
                    VALUES (?, ?, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ''', (payload, is_default))
            
            # Update default flag
            if default_payload and default_payload != existing_default:
                # Clear old default
                cursor.execute('''
                    UPDATE config_xss_payloads
                    SET is_default = 0, updated_at = CURRENT_TIMESTAMP
                    WHERE is_default = 1 AND is_user_added = 0
                ''')
                # Set new default
                cursor.execute('''
                    UPDATE config_xss_payloads
                    SET is_default = 1, updated_at = CURRENT_TIMESTAMP
                    WHERE payload = ? AND deleted_at IS NULL
                ''', (default_payload,))
                # If new default doesn't exist, add it
                cursor.execute('''
                    INSERT OR IGNORE INTO config_xss_payloads (payload, is_default, is_user_added, created_at, updated_at)
                    VALUES (?, 1, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ''', (default_payload,))
            
            # Soft delete payloads that are in DB but not in YAML (if not user-added)
            payloads_to_delete = existing_payloads - yaml_payloads
            for payload in payloads_to_delete:
                cursor.execute('''
                    UPDATE config_xss_payloads
                    SET deleted_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                    WHERE payload = ? AND is_user_added = 0 AND deleted_at IS NULL
                ''', (payload,))
            
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    retry_db_operation(_sync)


def sync_all_configs_from_yaml(db_path: Optional[str] = None):
    """
    Sync all YAML config files to database.
    This should be called on startup to ensure DB is up to date.
    """
    if db_path is None:
        db_path = str(get_main_db_path())
    
    # Ensure config tables exist
    from .database import init_database_with_checkpoints
    init_database_with_checkpoints(db_path)
    
    project_root = Path(__file__).parent.parent
    config_dir = project_root / "config"
    
    # Sync each config file
    api_patterns_file = config_dir / "api_patterns.yaml"
    if api_patterns_file.exists():
        sync_api_patterns_from_yaml(db_path, str(api_patterns_file))
    
    excluded_extensions_file = config_dir / "excluded_extensions.yaml"
    if excluded_extensions_file.exists():
        sync_excluded_extensions_from_yaml(db_path, str(excluded_extensions_file))
    
    xss_payloads_file = config_dir / "xss_payloads.yaml"
    if xss_payloads_file.exists():
        sync_xss_payloads_from_yaml(db_path, str(xss_payloads_file))


def load_api_patterns_from_db(db_path: str) -> Dict[str, str]:
    """
    Load API patterns from database.
    Returns dict mapping provider to pattern.
    """
    def _load():
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT provider, pattern FROM config_api_patterns
            WHERE deleted_at IS NULL
            ORDER BY provider, pattern
        ''')
        
        patterns = {}
        for provider, pattern in cursor.fetchall():
            patterns[provider] = pattern
        
        conn.close()
        return patterns
    
    return retry_db_operation(_load) or {}


def load_excluded_extensions_from_db(db_path: str) -> List[str]:
    """
    Load excluded extensions from database.
    Returns list of extensions.
    """
    def _load():
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT extension FROM config_excluded_extensions
            WHERE deleted_at IS NULL
            ORDER BY extension
        ''')
        
        extensions = [row[0] for row in cursor.fetchall()]
        conn.close()
        return extensions
    
    return retry_db_operation(_load) or []


def load_xss_payloads_from_db(db_path: str) -> Tuple[str, List[str]]:
    """
    Load XSS payloads from database.
    Returns tuple of (default_payload, all_payloads_list).
    """
    def _load():
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        
        # Get default payload
        cursor.execute('''
            SELECT payload FROM config_xss_payloads
            WHERE deleted_at IS NULL AND is_default = 1
            LIMIT 1
        ''')
        row = cursor.fetchone()
        default_payload = row[0] if row else ""
        
        # Get all payloads
        cursor.execute('''
            SELECT payload FROM config_xss_payloads
            WHERE deleted_at IS NULL
            ORDER BY is_default DESC, payload
        ''')
        
        payloads = [row[0] for row in cursor.fetchall()]
        conn.close()
        return default_payload, payloads
    
    result = retry_db_operation(_load)
    if result:
        return result
    # Fallback if no payloads in DB
    return "", []
