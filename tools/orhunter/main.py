"""
ORHunter - Open Redirect Vulnerability Scanner
Focuses on $_GET parameters and detects if they allow open redirects
"""

import warnings
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

import argparse
import asyncio
import os
import re
import sqlite3
import subprocess
import sys
import time
import yaml
from datetime import datetime
from pathlib import Path
from typing import List, Set, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from colorama import Fore, Style, init
from tqdm import tqdm

# Import shared modules
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from bughunter import recon
from bughunter import http_client

VERBOSE = False
OUTPUT_NAME = None
DB_PATH = None
CURRENT_SCAN_ID = None
cookie = ""
X_REQUEST_FOR = ""


REDIRECT_PAYLOAD = "https://google.com"  # Simple open redirect payload


def replace_params(url: str, payload: str) -> str:
    """Replace all URL parameters with the specified payload."""
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    new_params = {key: payload for key in query_params}
    new_query = urlencode(new_params, doseq=True)
    return urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, new_query,
                       parsed_url.fragment))


def check_open_redirect(url: str, payload: str) -> bool:
    """
    Check if the URL redirects to the payload location.
    http_client.fetch_url uses httpx with -irr flag which follows redirects automatically.
    Returns True if final URL starts with payload.
    """
    try:
        # http_client.fetch_url already follows redirects by default (httpx uses -irr flag)
        fetched_url, content, status_code, content_type = http_client.fetch_url(url)
        
        # Check if final URL starts with payload
        if fetched_url and fetched_url.startswith(payload):
            return True
        
        return False
    except Exception as e:
        if VERBOSE:
            print(f"[-] Error checking open redirect: {e}")
        return False


def init_database(db_path: str):
    """Initialize database with checkpoint support (uses shared database module)"""
    from bughunter import database
    return database.init_database_with_checkpoints(db_path)


def create_scan(domain: str, scan_type: str, output_dir: str = None, interactive: bool = None, force_restart: bool = False) -> int:
    """Create or resume a scan with checkpoint support. interactive=None auto-detects from stdin"""
    global DB_PATH
    if not DB_PATH:
        if OUTPUT_NAME:
            output_dir_path = OUTPUT_NAME
        else:
            output_dir_path = "output"
        os.makedirs(output_dir_path, exist_ok=True)
        DB_PATH = os.path.join(output_dir_path, "bughunter.db")
    
    from bughunter import database
    from colorama import Fore
    
    scan_id, is_resumed = database.create_or_resume_scan(
        DB_PATH, domain, scan_type, 
        output_dir or OUTPUT_NAME or "output",
        interactive=interactive,
        force_restart=force_restart
    )
    
    if is_resumed:
        print(Fore.GREEN + f"[+] Resuming existing scan ID {scan_id} from last checkpoint"); sys.stdout.flush()
    else:
        print(Fore.GREEN + f"[+] Created new scan ID {scan_id}"); sys.stdout.flush()
    
    return scan_id


def extract_get_parameters(url: str) -> Set[str]:
    """Extract GET parameter names from a URL"""
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return set(params.keys())
    except Exception:
        return set()


def test_parameter_reflection(url: str, param_name: str, payload: str) -> Tuple[bool, str, str]:
    """
    Test if a parameter value is reflected in the response
    
    Returns:
        Tuple of (is_reflected, location, context)
    """
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        # Set the parameter to our payload
        params[param_name] = [payload]
        
        # Reconstruct URL
        new_query = urlencode(params, doseq=True)
        new_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
        
        # Fetch the URL
        fetched_url, content, status_code, content_type = http_client.fetch_url(new_url)
        
        if not content:
            return False, "", ""
        
        # Check if payload is reflected
        if payload in content:
            # Determine location and context
            location = "body"
            context = "html"
            
            # Check if in script tag
            if f"<script>{payload}" in content or f"<script>{payload}" in content.lower():
                location = "script_tag"
                context = "javascript"
            elif f"<script" in content.lower() and payload in content:
                # Check if payload appears after script tag
                script_pos = content.lower().find("<script")
                payload_pos = content.find(payload)
                if payload_pos > script_pos:
                    location = "script_context"
                    context = "javascript"
            
            # Check if in attribute
            if f'="{payload}"' in content or f"='{payload}'" in content:
                location = "attribute"
                context = "html_attribute"
            elif f' {param_name}="{payload}"' in content or f' {param_name}=\'{payload}\'' in content:
                location = "attribute"
                context = "html_attribute"
            
            # Check if in comment
            if f"<!--{payload}" in content or f"<!--{payload}" in content.lower():
                location = "comment"
                context = "html_comment"
            
            return True, location, context
        
        return False, "", ""
    except Exception as e:
        if VERBOSE:
            print(f"[-] Error testing parameter reflection: {e}")
        return False, "", ""


def scan_url_for_redirect_with_id(url: str, scan_id: int, url_id: int) -> int:
    """
    Scan a URL for REDIRECT vulnerabilities using the proven approach:
    Replace all URL parameters with REDIRECT payload and check for reflection.
    
    Returns:
        Number of REDIRECT findings
    """
    global DB_PATH
    
    if not DB_PATH:
        return 0
    
    from bughunter.database import get_db_connection, retry_db_operation
    
    def _scan():
        conn = get_db_connection(DB_PATH)
        cursor = conn.cursor()
        
        try:
            # Extract GET parameters
            params = extract_get_parameters(url)
            
            if not params:
                return 0
            
            findings_count = 0
            
            # replace all params at once with REDIRECT payload
            modified_url = replace_params(url, REDIRECT_PAYLOAD)
            
            # Check if URL redirects to payload location
            if check_open_redirect(modified_url, REDIRECT_PAYLOAD):
                # Open redirect vulnerability found
                # Get the final redirect URL
                fetched_url, content, status_code, content_type = http_client.fetch_url(modified_url)
                redirect_url = fetched_url if fetched_url else modified_url
                
                # Store finding with all parameters that were tested
                param_names_str = ', '.join(sorted(params))
                
                # Check if already exists
                cursor.execute('''
                    SELECT finding_id FROM redirect_findings 
                    WHERE url_id = ? AND payload = ?
                ''', (url_id, REDIRECT_PAYLOAD))
                
                if not cursor.fetchone():
                    # Determine severity - medium for open redirects
                    severity = "medium"
                    
                    cursor.execute('''
                        INSERT INTO redirect_findings 
                        (url_id, parameter_name, payload, redirect_url, severity)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (url_id, param_names_str, REDIRECT_PAYLOAD, redirect_url, severity))
                    
                    findings_count += 1
                    
                    print(Fore.GREEN + f"[+] Open Redirect Found!")
                    print(Fore.GREEN + f"    Parameters: {param_names_str}")
                    print(Fore.GREEN + f"    Payload: {REDIRECT_PAYLOAD}")
                    print(Fore.GREEN + f"    Redirects to: {redirect_url}")
                    print(Fore.GREEN + f"    URL: {modified_url[:100]}...")
                    print(Fore.GREEN + "-"*60)
            
            conn.commit()
            return findings_count
        except Exception as e:
            if VERBOSE:
                print(Fore.YELLOW + f"[-] Error scanning URL for REDIRECT: {e}")
            return 0
        finally:
            conn.close()
    
    return retry_db_operation(_scan)


def scan_url_for_redirect(url: str, scan_id: int) -> int:
    """
    Scan a URL for REDIRECT vulnerabilities (wrapper function - use scan_url_for_redirect_with_id when url_id is available)
    
    Returns:
        Number of REDIRECT findings
    """
    global DB_PATH
    
    if not DB_PATH:
        return 0
    
    # Get url_id from database
    from bughunter import database
    url_id = database.store_url(DB_PATH, scan_id, url, source='redirect_test')
    
    # Use the new function
    return scan_url_for_redirect_with_id(url, scan_id, url_id)


async def scan_urls_for_redirect_from_db(scan_id: int):
    """Scan URLs from database with checkpoint support"""
    global DB_PATH
    from bughunter import database
    
    findings_count = 0
    processed = 0
    
    # Get pending URLs count
    url_stats = database.count_urls_by_status(DB_PATH, scan_id)
    total_urls = url_stats.get('pending', 0)
    
    if total_urls == 0:
        print(Fore.YELLOW + "[!] No pending URLs to scan"); sys.stdout.flush()
        database.update_scan_checkpoint(DB_PATH, scan_id, 'scanning', 'No URLs to scan for REDIRECT')
        return 0
    
    print(Fore.CYAN + f"[*] Stage: REDIRECT Testing - Processing {total_urls} pending URLs"); sys.stdout.flush()
    database.update_scan_checkpoint(DB_PATH, scan_id, 'scanning', 
                                    f'Starting REDIRECT scan: Testing {total_urls} URLs for open redirect vulnerabilities')
    
    # Process URLs in batches
    batch_num = 0
    while True:
        # Get next batch of pending URLs
        pending_urls = database.get_pending_urls(DB_PATH, scan_id, limit=100)
        
        if not pending_urls:
            break
        
        batch_num += 1
        batch_size = len(pending_urls)
        
        # Update checkpoint: Starting batch
        database.update_scan_checkpoint(DB_PATH, scan_id, 'scanning', 
                                        f'REDIRECT Testing batch {batch_num}: Testing {batch_size} URLs for open redirect...')
        
        for url_info in pending_urls:
            url = url_info['url']
            url_id = url_info['url_id']
            processed += 1
            
            if processed % 50 == 0 or VERBOSE:
                print(Fore.CYAN + f"[*] Stage: REDIRECT Testing - Testing URL {processed}/{total_urls} - {url[:80]}..."); sys.stdout.flush()
            
            # Update checkpoint more frequently
            if processed % 25 == 0:
                remaining = total_urls - processed
                database.update_scan_checkpoint(DB_PATH, scan_id, 'scanning', 
                    f'REDIRECT Testing: {processed}/{total_urls} URLs tested, {findings_count} REDIRECT found, {remaining} remaining')
            
            count = scan_url_for_redirect_with_id(url, scan_id, url_id)
            findings_count += count
            
            # Mark URL as checked
            database.mark_url_checked(DB_PATH, url_id)
        
        # Update checkpoint after batch
        database.update_scan_checkpoint(DB_PATH, scan_id, 'scanning', 
            f'REDIRECT Testing batch {batch_num} complete: {processed}/{total_urls} URLs tested, {findings_count} REDIRECT vulnerabilities found')
    
    # Final checkpoint
    database.update_scan_checkpoint(DB_PATH, scan_id, 'scanning', 
        f'REDIRECT Testing complete: {processed}/{total_urls} URLs tested, {findings_count} REDIRECT vulnerabilities found')
    print(Fore.CYAN + f"[*] Stage: REDIRECT Testing - Completed testing all {processed} URLs"); sys.stdout.flush()
    return findings_count


async def scan_urls_for_redirect(urls: List[str], scan_id: int):
    """Legacy function - use scan_urls_for_redirect_from_db for checkpoint support"""
    global DB_PATH
    from bughunter import database
    
    # Store URLs to database first
    for url in urls:
        if url and url.strip():
            database.store_url(DB_PATH, scan_id, url.strip(), source='manual')
    
    # Then process from database
    return await scan_urls_for_redirect_from_db(scan_id)


def update_scan_status(scan_id: int, status: str = 'completed'):
    """Update scan status in database with checkpoint support"""
    global DB_PATH
    if not DB_PATH:
        return
    
    from bughunter import database
    database.update_scan_checkpoint(DB_PATH, scan_id, status, f'Scan {status}')
    
    # Also update end_time if completed
    if status in ['completed', 'failed', 'error']:
        from bughunter.database import get_db_connection, retry_db_operation
        
        def _update():
            conn = get_db_connection(DB_PATH)
            cursor = conn.cursor()
            try:
                cursor.execute('''
                    UPDATE scans SET end_time = CURRENT_TIMESTAMP
                    WHERE scan_id = ?
                ''', (scan_id,))
                conn.commit()
            finally:
                conn.close()
        
        retry_db_operation(_update)
    
    print(Fore.WHITE + f"[+] Results saved to database: {DB_PATH}")


def load_excluded_extensions(db_path: str = None) -> List[str]:
    """Load excluded extensions from database"""
    try:
        from bughunter.config_migration import load_excluded_extensions_from_db, get_main_db_path
        
        if db_path is None:
            db_path = str(get_main_db_path())
        
        # Ensure DB is initialized and synced
        from bughunter.database import init_database_with_checkpoints
        init_database_with_checkpoints(db_path)
        from bughunter.config_migration import sync_all_configs_from_yaml
        sync_all_configs_from_yaml(db_path)
        
        return load_excluded_extensions_from_db(db_path)
    except Exception as e:
        if VERBOSE:
            print(f"[-] Error loading excluded extensions from DB: {e}")
        return []


async def main():
    """Main function"""
    global VERBOSE, OUTPUT_NAME, DB_PATH, CURRENT_SCAN_ID, cookie, X_REQUEST_FOR
    
    init(autoreset=True)
    
    print(Fore.CYAN + """
    
     ██████╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
    ██╔═══██╗██╔══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
    ██║   ██║██████╔╝███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
    ██║   ██║██╔══██╗██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
    ╚██████╔╝██║  ██║██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
     ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
                                                                          
    Open Redirect Vulnerability Scanner
    Tests GET parameters for open redirect vulnerabilities
    
    """ + Style.RESET_ALL)
    
    parser = argparse.ArgumentParser(description="ORHunter - Open Redirect Vulnerability Scanner")
    
    parser.add_argument("-d", "--domain", help="Target domain for scanning.")
    parser.add_argument("-f", "--file", help="File containing a list of domains to scan.")
    parser.add_argument("-l", "--urls-file", help="File containing a list of URLs to scan directly.")
    parser.add_argument("-ns", "--no-subs", help="Disable subdomain enumeration.", action="store_true")
    parser.add_argument("--cookie", help="Cookie to use for requests.")
    parser.add_argument("--x-request-for", help="X-Request-For header to use for requests.")
    parser.add_argument("-o", "--output", help="Output directory name (default: output).")
    parser.add_argument("-v", "--verbose", help="Enable verbose output.", action="store_true")
    parser.add_argument("--restart", help="Force restart: delete existing scan and start fresh (default: resume from checkpoint if exists).", action="store_true")
    
    args = parser.parse_args()
    
    if args.verbose:
        VERBOSE = True
        recon.set_verbose(True)
        http_client.set_verbose(True)
    
    if args.cookie:
        cookie = args.cookie
        http_client.set_cookie(cookie)
    
    if args.x_request_for:
        X_REQUEST_FOR = args.x_request_for
        http_client.set_x_request_for(X_REQUEST_FOR)
    
    if args.no_subs:
        recon.set_subdomain_enum(False)
    
    if args.output:
        OUTPUT_NAME = args.output
    
    # Load excluded extensions from database
    from bughunter.config_migration import get_main_db_path
    main_db = str(get_main_db_path())
    excluded_exts = load_excluded_extensions(main_db)
    recon.set_excluded_extensions(excluded_exts)
    
    # Set httpx path
    import shutil
    httpx_path = shutil.which("httpx")
    if httpx_path:
        http_client.set_httpx_path(httpx_path)
    else:
        print(Fore.RED + "[-] httpx not found. Please install it first.")
        sys.exit(1)
    
    if args.urls_file:
        print(Fore.WHITE + "-"*60)
        print(Fore.CYAN + "📄 URLs File Configuration")
        print("")
        print(Fore.WHITE + f"  File Path: {Fore.CYAN}{args.urls_file}")
        
        try:
            with open(args.urls_file, 'r') as file:
                urls = [line.strip() for line in file if line.strip()]
        except Exception as e:
            print(Fore.RED + f"[-] Error reading URLs from file: {e}")
            sys.exit(1)
        
        if not urls:
            print(Fore.RED + "[-] No URLs found in the file.")
            sys.exit(1)
        
        print(Fore.WHITE + f"  Total URLs: {Fore.GREEN}{len(urls)}")
        print("")
        
        print(Fore.CYAN + "[*] Stage: Initializing database and scan record..."); sys.stdout.flush()
        output_dir = OUTPUT_NAME or "output"
        os.makedirs(output_dir, exist_ok=True)
        DB_PATH = os.path.join(output_dir, "bughunter.db")
        init_database(DB_PATH)
        
        scan_id = create_scan("urls_file", "urls_file", output_dir, interactive=False, force_restart=getattr(args, 'restart', False))
        CURRENT_SCAN_ID = scan_id
        
        # Set up database context
        from bughunter import database
        database.update_scan_checkpoint(DB_PATH, scan_id, 'url_collection', f'Storing {len(urls)} URLs from file...')
        print(Fore.CYAN + f"[*] Stage: Storing URLs to database..."); sys.stdout.flush()
        
        # Store URLs to database
        for url in urls:
            if url and url.strip():
                database.store_url(DB_PATH, scan_id, url.strip(), source='urls_file')
        
        # Get pending URLs count
        url_stats = database.count_urls_by_status(DB_PATH, scan_id)
        pending_count = url_stats.get('pending', 0)
        
        print(Fore.CYAN + f"[*] Stage: Scan ID {scan_id} created, starting REDIRECT testing..."); sys.stdout.flush()
        print(Fore.WHITE + "[+] Scanning URLs for REDIRECT vulnerabilities...")
        
        database.update_scan_checkpoint(DB_PATH, scan_id, 'scanning', f'REDIRECT Testing: {pending_count} URLs to scan...')
        findings = await scan_urls_for_redirect_from_db(scan_id)
        
        print(Fore.CYAN + "[*] Stage: Scan completed, updating status..."); sys.stdout.flush()
        database.update_scan_checkpoint(DB_PATH, scan_id, 'completed', f'Completed: Found {findings} REDIRECT vulnerabilities')
        update_scan_status(scan_id, 'completed')
        
        # Get final stats
        final_stats = database.count_urls_by_status(DB_PATH, scan_id)
        checked_count = final_stats.get('checked', 0)
        print(Fore.WHITE + f"[+] Scanned {checked_count} URLs.")
        if findings:
            print(Fore.GREEN + f"[+] Found {findings} REDIRECT vulnerabilities!")
        else:
            print(Fore.YELLOW + "[-] No REDIRECT vulnerabilities found.")
        
        print(Fore.WHITE + "[+] Done! 🎉")
        print("")
    
    else:
        domains = []
        if args.domain:
            domains.append(args.domain)
        elif args.file:
            try:
                with open(args.file, 'r') as file:
                    domains = [line.strip() for line in file if line.strip()]
            except Exception as e:
                print(Fore.RED + f"[-] Error reading domains from file: {e}")
                sys.exit(1)
        else:
            print(Fore.RED + "[-] Please provide either a domain (-d), a file containing domains (-f), or a file containing URLs (-l).")
            sys.exit(1)
        
        for domain in domains:
            print(Fore.WHITE + "-"*60)
            print("")
            print(Fore.WHITE + f"- Target: {domain}")
            print(Fore.WHITE + f"- Subdomains: {'✔️' if not args.no_subs else '❌'}")
            print(Fore.WHITE + f"- Cookie: {'✔️' if cookie else '❌'}")
            print(Fore.WHITE + f"- X-Request-For: {X_REQUEST_FOR if X_REQUEST_FOR else '❌'}")
            print("")
            
            # Initialize database and create/resume scan
            # Always use per-domain database files to avoid locking issues when running multiple separate scans
            # This ensures each domain gets its own database even when running separate processes
            print(Fore.CYAN + "[*] Stage: Initializing database and scan record..."); sys.stdout.flush()
            output_dir = OUTPUT_NAME or "output"
            os.makedirs(output_dir, exist_ok=True)
            
            # Sanitize domain name for use in filename
            safe_domain = re.sub(r'[^\w\-_\.]', '_', domain)
            # Always use per-domain database file to avoid conflicts between separate concurrent scans
            # This works even when running separate commands for different domains
            DB_PATH = os.path.join(output_dir, f"bughunter_{safe_domain}.db")
            
            init_database(DB_PATH)
            
            scan_id = create_scan(domain, "domain", output_dir, interactive=False, force_restart=getattr(args, 'restart', False))
            CURRENT_SCAN_ID = scan_id
            
            # Set up database context for recon module
            from bughunter import database
            recon.set_database_context(DB_PATH, scan_id)
            recon.set_verbose(VERBOSE)
            recon.set_subdomain_enum(not args.no_subs)
            
            # Load excluded extensions from database
            from bughunter.config_migration import get_main_db_path
            main_db = str(get_main_db_path())
            excluded_exts = load_excluded_extensions(main_db)
            recon.set_excluded_extensions(excluded_exts)
            
            # Check if URLs already exist (for rescan mode)
            url_stats = database.count_urls_by_status(DB_PATH, scan_id)
            existing_urls = sum(url_stats.values())
            
            # Only collect URLs/subdomains if none exist (new scan) or if not in rescan mode
            if existing_urls == 0:
                # Collect subdomains and URLs with checkpoint support
                if not args.no_subs:
                    database.update_scan_checkpoint(DB_PATH, scan_id, 'subdomain_enum', 'Starting subdomain enumeration...')
                    print(Fore.CYAN + "[*] Stage: Subdomain Enumeration - Starting subdomain discovery..."); sys.stdout.flush()
                    print(Fore.WHITE + "[+] Collecting subdomains...")
                    subdomain_count = recon.collect_subdomains_to_db(domain)
                    print(Fore.GREEN + f"[+] Found {subdomain_count} subdomains 🎯")
                    
                    database.update_scan_checkpoint(DB_PATH, scan_id, 'url_collection', f'Collecting URLs from {subdomain_count} subdomains...')
                else:
                    database.update_scan_checkpoint(DB_PATH, scan_id, 'url_collection', 'Collecting URLs (no subdomains)...')
                
                print(Fore.WHITE + "[+] Collecting URLs...")
                print(Fore.CYAN + "[*] Stage: URL Crawl - Collecting URLs from sources..."); sys.stdout.flush()
                total_urls = recon.collect_urls_to_db(domain, enable_subdomains=not args.no_subs)
                print(Fore.GREEN + f"[+] Found {total_urls} URLs 🎯")
                
                # Get pending URLs count after collection
                url_stats = database.count_urls_by_status(DB_PATH, scan_id)
            else:
                # URLs already exist - rescan mode, skip collection
                print(Fore.CYAN + "[*] Stage: Rescan Mode - Reusing existing URLs..."); sys.stdout.flush()
                print(Fore.WHITE + f"[+] Found {existing_urls} existing URL(s) in database, skipping collection")
            
            pending_count = url_stats.get('pending', 0)
            
            print(Fore.CYAN + f"[*] Stage: Scan ID {scan_id} created, starting REDIRECT testing..."); sys.stdout.flush()
            print(Fore.WHITE + "[+] Scanning URLs for REDIRECT vulnerabilities...")
            
            database.update_scan_checkpoint(DB_PATH, scan_id, 'scanning', f'REDIRECT Testing: {pending_count} URLs to scan...')
            findings = await scan_urls_for_redirect_from_db(scan_id)
            
            print(Fore.CYAN + "[*] Stage: Scan completed, updating status..."); sys.stdout.flush()
            database.update_scan_checkpoint(DB_PATH, scan_id, 'completed', f'Completed: Found {findings} REDIRECT vulnerabilities')
            update_scan_status(scan_id, 'completed')
            
            # Get final stats
            final_stats = database.count_urls_by_status(DB_PATH, scan_id)
            checked_count = final_stats.get('checked', 0)
            print(Fore.WHITE + f"[+] Scanned {checked_count} URLs.")
            if findings:
                print(Fore.GREEN + f"[+] Found {findings} REDIRECT vulnerabilities!")
            else:
                print(Fore.YELLOW + "[-] No REDIRECT vulnerabilities found.")
            
            print(Fore.WHITE + "[+] Done! 🎉")
            print("")


if __name__ == "__main__":
    asyncio.run(main())
