"""
DTOHunter - Domain TakeOver Vulnerability Scanner
Checks subdomains for potential takeover vulnerabilities using can-i-take-over-xyz fingerprints
"""

import warnings
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

import argparse
import asyncio
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
from colorama import Fore, Style, init
import requests

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

FINGERPRINTS_URL = "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/refs/heads/master/fingerprints.json"
LOCAL_FINGERPRINTS_PATH = Path(__file__).parent.parent.parent / "config" / "takeover_fingerprints.json"
FINGERPRINTS_CACHE = None


def fetch_fingerprints() -> List[Dict]:
    """
    Fetch fingerprints from online source, fallback to local if unavailable.
    Updates local cache if online fetch succeeds.
    """
    global FINGERPRINTS_CACHE
    
    # Try online first
    try:
        if VERBOSE:
            print(Fore.CYAN + "[*] Fetching fingerprints from online source..."); sys.stdout.flush()
        
        response = requests.get(FINGERPRINTS_URL, timeout=10)
        response.raise_for_status()
        fingerprints = response.json()
        
        # Save to local cache
        LOCAL_FINGERPRINTS_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(LOCAL_FINGERPRINTS_PATH, 'w') as f:
            json.dump(fingerprints, f, indent=2)
        
        if VERBOSE:
            print(Fore.GREEN + "[+] Updated local fingerprints cache"); sys.stdout.flush()
        
        FINGERPRINTS_CACHE = fingerprints
        return fingerprints
    
    except Exception as e:
        if VERBOSE:
            print(Fore.YELLOW + f"[!] Failed to fetch online fingerprints: {e}"); sys.stdout.flush()
            print(Fore.CYAN + "[*] Using local cache..."); sys.stdout.flush()
        
        # Fallback to local
        if LOCAL_FINGERPRINTS_PATH.exists():
            try:
                with open(LOCAL_FINGERPRINTS_PATH, 'r') as f:
                    fingerprints = json.load(f)
                FINGERPRINTS_CACHE = fingerprints
                return fingerprints
            except Exception as e2:
                print(Fore.RED + f"[-] Failed to load local fingerprints: {e2}"); sys.stdout.flush()
        
        print(Fore.RED + "[-] No fingerprints available (online and local both failed)"); sys.stdout.flush()
        return []


def get_vulnerable_fingerprints() -> List[Dict]:
    """Get only vulnerable fingerprints from cache or fetch if needed"""
    global FINGERPRINTS_CACHE
    
    if FINGERPRINTS_CACHE is None:
        FINGERPRINTS_CACHE = fetch_fingerprints()
    
    # Filter only vulnerable ones
    vulnerable = [fp for fp in FINGERPRINTS_CACHE if fp.get('vulnerable', False) is True]
    
    if VERBOSE:
        print(Fore.CYAN + f"[*] Loaded {len(vulnerable)} vulnerable fingerprint(s) out of {len(FINGERPRINTS_CACHE)} total"); sys.stdout.flush()
    
    return vulnerable


def resolve_cname(subdomain: str) -> Optional[List[str]]:
    """Resolve CNAME record for a subdomain"""
    try:
        import dns.resolver
        import dns.exception
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        answers = resolver.resolve(subdomain, 'CNAME')
        cnames = [str(rdata.target).rstrip('.') for rdata in answers]
        return cnames
    
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        return None
    except Exception as e:
        if VERBOSE:
            print(Fore.YELLOW + f"[!] DNS resolution error for {subdomain}: {e}"); sys.stdout.flush()
        return None


def check_nxdomain(subdomain: str) -> bool:
    """Check if subdomain returns NXDOMAIN"""
    try:
        import dns.resolver
        import dns.exception
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        resolver.resolve(subdomain, 'A')
        return False  # Resolved successfully, not NXDOMAIN
    
    except dns.resolver.NXDOMAIN:
        return True  # NXDOMAIN found
    except Exception:
        return False  # Other error, not NXDOMAIN


def check_fingerprint_match(url: str, fingerprint: Dict) -> Tuple[bool, Optional[str]]:
    """
    Check if the URL response matches the fingerprint.
    Returns (is_match, response_text_or_error)
    """
    try:
        fetched_url, content, status_code, content_type = http_client.fetch_url(url)
        
        if not content:
            return False, None
        
        fingerprint_text = fingerprint.get('fingerprint', '')
        http_status = fingerprint.get('http_status')
        
        # Check HTTP status if specified
        if http_status is not None and status_code != http_status:
            return False, None
        
        # Check fingerprint text in content
        if fingerprint_text:
            # Handle NXDOMAIN case - if fingerprint is "NXDOMAIN", skip content check
            if fingerprint_text == "NXDOMAIN":
                # This should be handled by DNS check, not HTTP check
                return False, None
            
            if fingerprint_text in content:
                return True, content[:500]  # Return first 500 chars
        
        return False, None
    
    except Exception as e:
        if VERBOSE:
            print(Fore.YELLOW + f"[!] Error checking fingerprint for {url}: {e}"); sys.stdout.flush()
        return False, None


def check_subdomain_takeover(subdomain: str, fingerprints: List[Dict]) -> Optional[Dict]:
    """
    Check if a subdomain is vulnerable to takeover.
    Fetches the domain once and compares with all fingerprints.
    Returns fingerprint dict if vulnerable, None otherwise.
    """
    # Resolve CNAME first
    cnames = resolve_cname(subdomain)
    if VERBOSE and cnames:
        print(Fore.CYAN + f"[*] {subdomain} -> CNAME: {', '.join(cnames)}"); sys.stdout.flush()
    
    # Filter fingerprints that match CNAME patterns (if CNAME exists)
    matching_fingerprints = []
    for fingerprint in fingerprints:
        cname_patterns = fingerprint.get('cname', [])
        
        # If CNAME patterns specified, check if they match
        if cname_patterns:
            if not cnames:
                continue  # Skip if no CNAME but patterns required
            
            # Check if any CNAME matches any pattern
            cname_matches = False
            for cname in cnames:
                for pattern in cname_patterns:
                    # Simple substring match or exact match
                    if pattern.lower() in cname.lower() or cname.lower() == pattern.lower():
                        cname_matches = True
                        break
                if cname_matches:
                    break
            
            if not cname_matches:
                continue  # Skip if CNAME doesn't match
        
        matching_fingerprints.append(fingerprint)
    
    if not matching_fingerprints:
        return None
    
    # Check NXDOMAIN fingerprints first (no HTTP request needed)
    for fingerprint in matching_fingerprints:
        fingerprint_text = fingerprint.get('fingerprint', '')
        nxdomain_check = fingerprint.get('nxdomain', False)
        
        if nxdomain_check and fingerprint_text == "NXDOMAIN":
            if check_nxdomain(subdomain):
                # NXDOMAIN found and fingerprint matches
                return fingerprint
    
    # Build URLs to test (http and https)
    test_urls = []
    if not subdomain.startswith('http://') and not subdomain.startswith('https://'):
        test_urls = [f"https://{subdomain}", f"http://{subdomain}"]
    else:
        test_urls = [subdomain]
    
    # Fetch domain content once (try https first, then http)
    content = None
    status_code = None
    fetched_url = None
    content_type = None
    
    for url in test_urls:
        try:
            fetched_url, content, status_code, content_type = http_client.fetch_url(url)
            if content:
                break  # Successfully fetched content, stop trying other URLs
        except Exception:
            continue
    
    # If we couldn't fetch content, check if any fingerprint doesn't require HTTP check
    if not content:
        # Some services don't require fingerprint matching (already checked NXDOMAIN above)
        # Return None if no content and no NXDOMAIN match
        return None
    
    # Compare fetched content with all matching fingerprints
    for fingerprint in matching_fingerprints:
        fingerprint_text = fingerprint.get('fingerprint', '')
        http_status = fingerprint.get('http_status')
        nxdomain_check = fingerprint.get('nxdomain', False)
        
        # Skip NXDOMAIN fingerprints (already checked above)
        if nxdomain_check and fingerprint_text == "NXDOMAIN":
            continue
        
        # Check HTTP status if specified
        if http_status is not None and status_code != http_status:
            continue
        
        # Check fingerprint text in content
        if fingerprint_text and fingerprint_text in content:
            return fingerprint
    
    return None


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


def scan_subdomain_for_takeover(subdomain: str, scan_id: int, subdomain_id: int) -> int:
    """Scan a subdomain for takeover vulnerabilities"""
    global DB_PATH
    from bughunter.database import get_db_connection, retry_db_operation
    
    fingerprints = get_vulnerable_fingerprints()
    if not fingerprints:
        return 0
    
    def _scan():
        conn = get_db_connection(DB_PATH)
        cursor = conn.cursor()
        findings_count = 0
        
        try:
            vulnerable_fp = check_subdomain_takeover(subdomain, fingerprints)
            
            if vulnerable_fp:
                service = vulnerable_fp.get('service', 'Unknown')
                fingerprint_text = vulnerable_fp.get('fingerprint', '')
                cname_patterns = vulnerable_fp.get('cname', [])
                
                # Get CNAME if available
                cnames = resolve_cname(subdomain)
                cname_str = ', '.join(cnames) if cnames else 'None'
                
                # Check if already exists
                cursor.execute('''
                    SELECT finding_id FROM takeover_findings
                    WHERE subdomain_id = ? AND service = ?
                ''', (subdomain_id, service))
                
                if not cursor.fetchone():
                    cursor.execute('''
                        INSERT INTO takeover_findings (
                            subdomain_id, service, fingerprint, cname, severity, found_at
                        ) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    ''', (subdomain_id, service, fingerprint_text, cname_str, 'high'))
                    
                    findings_count = 1
                    
                    print(Fore.GREEN + f"[+] Takeover Found!")
                    print(Fore.GREEN + f"    Subdomain: {subdomain}")
                    print(Fore.GREEN + f"    Service: {service}")
                    print(Fore.GREEN + f"    CNAME: {cname_str}")
                    print(Fore.GREEN + f"    Fingerprint: {fingerprint_text[:100]}...")
                    print(Fore.GREEN + "-"*60)
            
            conn.commit()
            return findings_count
        
        finally:
            conn.close()
    
    return retry_db_operation(_scan) or 0


async def scan_subdomains_for_takeover_from_db(scan_id: int):
    """Scan subdomains from database for takeover vulnerabilities"""
    global DB_PATH
    from bughunter import database
    
    findings_count = 0
    processed = 0
    
    # Get all unique subdomains for this scan (distinct by subdomain name)
    # This ensures each subdomain/domain is only checked once, even if it appears multiple times
    conn = database.get_db_connection(DB_PATH)
    cursor = conn.cursor()
    try:
        # Get distinct subdomains with their first subdomain_id (to avoid duplicates)
        cursor.execute('''
            SELECT MIN(subdomain_id) as subdomain_id, subdomain 
            FROM subdomains
            WHERE scan_id = ?
            GROUP BY subdomain
            ORDER BY subdomain_id
        ''', (scan_id,))
        subdomains = cursor.fetchall()
        
        # Track which subdomains already have takeover findings to avoid re-checking
        cursor.execute('''
            SELECT DISTINCT s.subdomain 
            FROM subdomains s
            INNER JOIN takeover_findings tf ON s.subdomain_id = tf.subdomain_id
            WHERE s.scan_id = ?
        ''', (scan_id,))
        already_checked = {row[0] for row in cursor.fetchall()}
    finally:
        conn.close()
    
    # Filter out subdomains that already have takeover findings
    unique_subdomains = [(subdomain_id, subdomain) for subdomain_id, subdomain in subdomains 
                         if subdomain not in already_checked]
    
    total_subdomains = len(unique_subdomains)
    
    if total_subdomains == 0:
        print(Fore.YELLOW + "[!] No subdomains to scan"); sys.stdout.flush()
        database.update_scan_checkpoint(DB_PATH, scan_id, 'scanning', 'No subdomains to scan')
        return 0
    
    print(Fore.CYAN + f"[*] Stage: Takeover Testing - Processing {total_subdomains} subdomains"); sys.stdout.flush()
    database.update_scan_checkpoint(DB_PATH, scan_id, 'scanning', 
                                    f'Starting takeover scan: Testing {total_subdomains} subdomains')
    
    # Load fingerprints once
    fingerprints = get_vulnerable_fingerprints()
    if not fingerprints:
        print(Fore.RED + "[-] No vulnerable fingerprints available"); sys.stdout.flush()
        return 0
    
    print(Fore.CYAN + f"[*] Testing against {len(fingerprints)} vulnerable service(s)"); sys.stdout.flush()
    
    if already_checked:
        print(Fore.CYAN + f"[*] Skipping {len(already_checked)} subdomain(s) that already have takeover findings"); sys.stdout.flush()
    
    # Process unique subdomains only
    for subdomain_id, subdomain in unique_subdomains:
        processed += 1
        
        if processed % 10 == 0 or VERBOSE:
            print(Fore.CYAN + f"[*] Stage: Takeover Testing - Testing subdomain {processed}/{total_subdomains} - {subdomain}"); sys.stdout.flush()
        
        if processed % 25 == 0:
            database.update_scan_checkpoint(DB_PATH, scan_id, 'scanning', 
                f'Takeover Testing: {processed}/{total_subdomains} subdomains tested, {findings_count} takeover(s) found')
        
        count = scan_subdomain_for_takeover(subdomain, scan_id, subdomain_id)
        findings_count += count
        
        # Small delay to avoid rate limiting
        await asyncio.sleep(0.1)
    
    # Final checkpoint
    database.update_scan_checkpoint(DB_PATH, scan_id, 'scanning', 
        f'Takeover Testing complete: {processed}/{total_subdomains} subdomains tested, {findings_count} takeover(s) found')
    print(Fore.CYAN + f"[*] Stage: Takeover Testing - Completed testing all {processed} subdomains"); sys.stdout.flush()
    return findings_count


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


async def main():
    """Main function"""
    global VERBOSE, OUTPUT_NAME, DB_PATH, CURRENT_SCAN_ID, cookie, X_REQUEST_FOR
    
    init(autoreset=True)
    
    print(Fore.CYAN + """
    
    ██████╗ ████████╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
    ██╔══██╗╚══██╔══╝██╔═══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
    ██║  ██║   ██║   ██║   ██║███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
    ██║  ██║   ██║   ██║   ██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
    ██████╔╝   ██║   ╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
    ╚═════╝    ╚═╝    ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
                                                                                    
    Domain TakeOver Vulnerability Scanner
    Detects subdomain takeover vulnerabilities using can-i-take-over-xyz fingerprints
    
    """ + Style.RESET_ALL)
    
    parser = argparse.ArgumentParser(description="DTOHunter - Domain TakeOver Vulnerability Scanner")
    
    parser.add_argument("-d", "--domain", help="Target domain for scanning.")
    parser.add_argument("-f", "--file", help="File containing a list of domains to scan.")
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
    try:
        from bughunter.config_migration import get_main_db_path, load_excluded_extensions_from_db
        main_db = str(get_main_db_path())
        excluded_exts = load_excluded_extensions_from_db(main_db)
        recon.set_excluded_extensions(excluded_exts)
    except Exception as e:
        if VERBOSE:
            print(Fore.YELLOW + f"[!] Failed to load excluded extensions: {e}"); sys.stdout.flush()
    
    # Set httpx path
    import shutil
    httpx_path = shutil.which("httpx")
    if httpx_path:
        http_client.set_httpx_path(httpx_path)
    else:
        print(Fore.RED + "[-] httpx not found. Please install it first.")
        sys.exit(1)
    
    # Check for dnspython
    try:
        import dns.resolver
    except ImportError:
        print(Fore.RED + "[-] dnspython not found. Install it with: pip install dnspython")
        sys.exit(1)
    
    # Fetch fingerprints
    print(Fore.CYAN + "[*] Loading fingerprints..."); sys.stdout.flush()
    fingerprints = get_vulnerable_fingerprints()
    if not fingerprints:
        print(Fore.RED + "[-] Failed to load fingerprints. Cannot proceed.")
        sys.exit(1)
    
    print(Fore.GREEN + f"[+] Loaded {len(fingerprints)} vulnerable fingerprint(s)"); sys.stdout.flush()
    
    # Collect domains
    domains = []
    if args.domain:
        domains = [args.domain]
    elif args.file:
        try:
            with open(args.file, 'r') as file:
                domains = [line.strip() for line in file if line.strip()]
        except Exception as e:
            print(Fore.RED + f"[-] Error reading domains from file: {e}")
            sys.exit(1)
    else:
        print(Fore.RED + "[-] Please provide either a domain (-d) or a file containing domains (-f).")
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
        print(Fore.CYAN + "[*] Stage: Initializing database and scan record..."); sys.stdout.flush()
        output_dir = OUTPUT_NAME or "output"
        os.makedirs(output_dir, exist_ok=True)
        
        # Sanitize domain name for use in filename
        safe_domain = re.sub(r'[^\w\-_\.]', '_', domain)
        DB_PATH = os.path.join(output_dir, f"bughunter_{safe_domain}.db")
        
        init_database(DB_PATH)
        
        scan_id = create_scan(domain, "domain", output_dir, interactive=False, force_restart=getattr(args, 'restart', False))
        CURRENT_SCAN_ID = scan_id
        
        # Set up database context for recon module
        from bughunter import database
        recon.set_database_context(DB_PATH, scan_id)
        recon.set_verbose(VERBOSE)
        recon.set_subdomain_enum(not args.no_subs)
        
        # Check if subdomains already exist (for rescan mode)
        conn = database.get_db_connection(DB_PATH)
        cursor = conn.cursor()
        try:
            cursor.execute('SELECT COUNT(*) FROM subdomains WHERE scan_id = ?', (scan_id,))
            existing_subdomains = cursor.fetchone()[0]
        finally:
            conn.close()
        
        # Only collect subdomains if none exist (new scan)
        if existing_subdomains == 0:
            # Collect subdomains with checkpoint support
            if not args.no_subs:
                database.update_scan_checkpoint(DB_PATH, scan_id, 'subdomain_enum', 'Starting subdomain enumeration...')
                print(Fore.CYAN + "[*] Stage: Subdomain Enumeration - Starting subdomain discovery..."); sys.stdout.flush()
                print(Fore.WHITE + "[+] Collecting subdomains...")
                subdomain_count = recon.collect_subdomains_to_db(domain)
                print(Fore.GREEN + f"[+] Found {subdomain_count} subdomains 🎯")
            else:
                # Still need to store the main domain as a subdomain
                database.store_subdomain(DB_PATH, scan_id, domain, domain)
                subdomain_count = 1
        else:
            # Subdomains already exist - rescan mode, skip collection
            print(Fore.CYAN + "[*] Stage: Rescan Mode - Reusing existing subdomains..."); sys.stdout.flush()
            print(Fore.WHITE + f"[+] Found {existing_subdomains} existing subdomain(s) in database, skipping collection")
            subdomain_count = existing_subdomains
        
        print(Fore.CYAN + f"[*] Stage: Scan ID {scan_id} created, starting takeover testing..."); sys.stdout.flush()
        print(Fore.WHITE + "[+] Scanning subdomains for takeover vulnerabilities...")
        
        database.update_scan_checkpoint(DB_PATH, scan_id, 'scanning', f'Takeover Testing: {subdomain_count} subdomains to scan...')
        findings = await scan_subdomains_for_takeover_from_db(scan_id)
        
        print(Fore.CYAN + "[*] Stage: Scan completed, updating status..."); sys.stdout.flush()
        database.update_scan_checkpoint(DB_PATH, scan_id, 'completed', f'Completed: Found {findings} takeover vulnerability/vulnerabilities')
        update_scan_status(scan_id, 'completed')
        
        if findings:
            print(Fore.GREEN + f"[+] Found {findings} takeover vulnerability/vulnerabilities!")
        else:
            print(Fore.YELLOW + "[-] No takeover vulnerabilities found.")
        
        print(Fore.WHITE + "[+] Done! 🎉")
        print("")


if __name__ == "__main__":
    asyncio.run(main())
