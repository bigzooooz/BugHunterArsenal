"""
Shared Reconnaissance Module
Provides subdomain enumeration and URL collection functionality
for use by multiple security tools (KeyHunter, XSSHunter, etc.)
"""

import subprocess
import re
from pathlib import Path
from typing import List, Iterator, Optional
import sys

# Global configuration (can be set by tools)
VERBOSE = False
with_subs = True
excluded_extensions = []
DB_PATH = None
SCAN_ID = None


def set_verbose(enabled: bool):
    """Set verbose output mode"""
    global VERBOSE
    VERBOSE = enabled


def set_subdomain_enum(enabled: bool):
    """Enable or disable subdomain enumeration"""
    global with_subs
    with_subs = enabled


def set_excluded_extensions(extensions: List[str]):
    """Set list of file extensions to exclude"""
    global excluded_extensions
    excluded_extensions = extensions


def set_database_context(db_path: str, scan_id: int):
    """Set database path and scan_id for storing results"""
    global DB_PATH, SCAN_ID
    DB_PATH = db_path
    SCAN_ID = scan_id


def remove_version_param(url: str) -> str:
    """Remove version parameters from URLs"""
    return re.sub(r'(\?v=|ver=|version=|rev=|timestamp=|build=|_token=)[^&]+', '', url).rstrip('?')


def run_subfinder(domain: str) -> Iterator[str]:
    """
    Run subfinder to enumerate subdomains
    
    Args:
        domain: Target domain
        
    Returns:
        Iterator of subdomain strings
    """
    try:
        cmd = ["subfinder", "-d", domain, "-all", "-recursive"]
        if not VERBOSE:
            cmd.append("-silent")
        result = subprocess.run(cmd, capture_output=True, text=True)
        return (line.strip() for line in result.stdout.splitlines() if line.strip())
    except Exception as e:
        if VERBOSE:
            print(f"Error running subfinder: {e}")
        return iter([])


def run_waybackurls(domain: str) -> List[str]:
    """
    Run waybackurls to collect URLs from Wayback Machine
    
    Args:
        domain: Target domain
        
    Returns:
        List of URLs
    """
    try:
        if with_subs:
            cmd = f'echo {domain} | waybackurls'
        else:
            cmd = f'echo {domain} | waybackurls -no-subs'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
        filtered_urls = result.stdout.splitlines()
        filtered_urls = [url for url in filtered_urls if not any(url.lower().endswith(ext) for ext in excluded_extensions)]
        filtered_urls = [remove_version_param(url) for url in filtered_urls]
        filtered_urls = list(set(filtered_urls))
        return filtered_urls
    except subprocess.TimeoutExpired:
        if VERBOSE:
            print(f"Timeout running waybackurls for {domain}")
        return []
    except Exception as e:
        if VERBOSE:
            print(f"Error running WaybackURLs: {e}")
        return []


def run_katana(target: str, depth: int = 5) -> List[str]:
    """
    Run katana to crawl and discover URLs
    
    Args:
        target: Target URL or domain
        depth: Crawling depth (default: 5)
        
    Returns:
        List of discovered URLs
    """
    try:
        ef = ",".join(ext.lstrip(".") for ext in excluded_extensions) if excluded_extensions else ""
        cmd = ["katana", "-u", target, "-jc", "-d", str(depth), "-timeout", "10"]
        if ef:
            cmd.extend(["-ef", ef])
        if not VERBOSE:
            cmd.append("-silent")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        urls = result.stdout.splitlines()
        urls = [u.strip() for u in urls if u.strip()]
        urls = [u for u in urls if not any(u.lower().endswith(ext) for ext in excluded_extensions)]
        urls = [remove_version_param(u) for u in urls]
        urls = list(set(urls))
        return urls
    except subprocess.TimeoutExpired:
        if VERBOSE:
            print(f"Timeout running katana for {target}")
        return []
    except Exception as e:
        if VERBOSE:
            print(f"Error running katana: {e}")
        return []


def collect_urls(domain: str, enable_subdomains: bool = True) -> List[str]:
    """
    Collect URLs for a domain using all available methods
    DEPRECATED: Use collect_urls_to_db for checkpoint-based scanning
    
    Args:
        domain: Target domain
        enable_subdomains: Whether to enumerate subdomains first
        
    Returns:
        List of collected URLs
    """
    urls = []
    
    if enable_subdomains:
        subdomains = [domain] + list(run_subfinder(domain))
        for subdomain in subdomains:
            urls.extend(run_waybackurls(subdomain))
            urls.extend(run_katana(subdomain, depth=5))
    else:
        urls.extend(run_waybackurls(domain))
        urls.extend(run_katana(domain, depth=5))
    
    # Deduplicate
    urls = list(set(urls))
    return urls


def collect_subdomains_to_db(domain: str) -> int:
    """
    Collect subdomains and store them in database with checkpoint support
    
    Args:
        domain: Target domain
        
    Returns:
        Number of subdomains stored
    """
    global DB_PATH, SCAN_ID
    
    if not DB_PATH or not SCAN_ID:
        raise ValueError("Database context not set. Call set_database_context() first.")
    
    from .database import store_subdomain, update_scan_checkpoint
    
    count = 0
    
    # Update checkpoint: Running subfinder
    update_scan_checkpoint(DB_PATH, SCAN_ID, 'subdomain_enum', f'Running subfinder on {domain}...')
    
    # Store main domain
    store_subdomain(DB_PATH, SCAN_ID, domain, domain)
    count += 1
    
    # Collect and store subdomains
    for subdomain in run_subfinder(domain):
        if subdomain and subdomain.strip():
            store_subdomain(DB_PATH, SCAN_ID, domain, subdomain.strip())
            count += 1
            
            # Update checkpoint periodically
            if count % 10 == 0:
                update_scan_checkpoint(DB_PATH, SCAN_ID, 'subdomain_enum', f'Found {count} subdomains so far...')
            
            if VERBOSE and count % 50 == 0:
                print(f"[*] Stored {count} subdomains...")
                sys.stdout.flush()
    
    # Final checkpoint update
    update_scan_checkpoint(DB_PATH, SCAN_ID, 'subdomain_enum', f'Subdomain enumeration complete: Found {count} subdomains')
    
    return count


def collect_urls_for_subdomain_to_db(subdomain: str, subdomain_id: int):
    """
    Collect URLs for a specific subdomain and store in database
    
    Args:
        subdomain: Subdomain to collect URLs for
        subdomain_id: Database ID of the subdomain
        
    Returns:
        Number of URLs collected
    """
    global DB_PATH, SCAN_ID
    
    if not DB_PATH or not SCAN_ID:
        raise ValueError("Database context not set. Call set_database_context() first.")
    
    from .database import store_urls_batch, mark_subdomain_tool_done, mark_subdomain_collection_complete
    
    url_count = 0
    
    # Collect URLs from waybackurls
    wayback_urls = run_waybackurls(subdomain)
    # Batch insert URLs for better performance and reduced locking
    url_batch = [(url.strip(), subdomain_id, 'waybackurls') for url in wayback_urls if url and url.strip()]
    if url_batch:
        url_count += store_urls_batch(DB_PATH, SCAN_ID, url_batch)
    
    mark_subdomain_tool_done(DB_PATH, subdomain_id, 'waybackurls')
    
    # Collect URLs from katana
    katana_urls = run_katana(subdomain, depth=5)
    # Batch insert URLs for better performance and reduced locking
    url_batch = [(url.strip(), subdomain_id, 'katana') for url in katana_urls if url and url.strip()]
    if url_batch:
        url_count += store_urls_batch(DB_PATH, SCAN_ID, url_batch)
    
    mark_subdomain_tool_done(DB_PATH, subdomain_id, 'katana')
    mark_subdomain_collection_complete(DB_PATH, subdomain_id)
    
    return url_count


def collect_urls_to_db(domain: str, enable_subdomains: bool = True) -> int:
    """
    Collect URLs for a domain and store in database with checkpoint support
    
    Args:
        domain: Target domain
        enable_subdomains: Whether to enumerate subdomains first
        
    Returns:
        Total number of URLs collected
    """
    global DB_PATH, SCAN_ID
    
    if not DB_PATH or not SCAN_ID:
        raise ValueError("Database context not set. Call set_database_context() first.")
    
    from .database import (
        get_pending_subdomains, mark_subdomain_collection_start,
        store_url, mark_subdomain_tool_done, mark_subdomain_collection_complete
    )
    
    total_urls = 0
    
    if enable_subdomains:
        # Check for pending subdomains first (resume support)
        pending_subs = get_pending_subdomains(DB_PATH, SCAN_ID)
        
        if not pending_subs:
            # Need to collect subdomains first
            if VERBOSE:
                print(f"[*] Collecting subdomains for {domain}...")
                sys.stdout.flush()
            collect_subdomains_to_db(domain)
            pending_subs = get_pending_subdomains(DB_PATH, SCAN_ID)
        
        # Process each pending subdomain
        total_subs = len(pending_subs)
        current_sub = 0
        for sub_info in pending_subs:
            subdomain = sub_info['subdomain']
            subdomain_id = sub_info['subdomain_id']
            current_sub += 1
            
            mark_subdomain_collection_start(DB_PATH, subdomain_id)
            
            # Update checkpoint: Processing subdomain
            from .database import update_scan_checkpoint
            update_scan_checkpoint(DB_PATH, SCAN_ID, 'url_collection', 
                                  f'Collecting URLs from subdomain {current_sub}/{total_subs}: {subdomain}')
            
            # Collect waybackurls if not done
            if not sub_info.get('waybackurls_done', 0):
                update_scan_checkpoint(DB_PATH, SCAN_ID, 'url_collection', 
                                      f'Running waybackurls on {subdomain}...')
                wayback_urls = run_waybackurls(subdomain)
                # Batch insert URLs for better performance and reduced locking
                url_batch = [(url.strip(), subdomain_id, 'waybackurls') for url in wayback_urls if url and url.strip()]
                if url_batch:
                    from .database import store_urls_batch
                    inserted = store_urls_batch(DB_PATH, SCAN_ID, url_batch)
                    total_urls += inserted
                    update_scan_checkpoint(DB_PATH, SCAN_ID, 'url_collection', 
                                          f'Collected {inserted} URLs from waybackurls for {subdomain}')
                mark_subdomain_tool_done(DB_PATH, subdomain_id, 'waybackurls')
            
            # Collect katana if not done
            if not sub_info.get('katana_done', 0):
                update_scan_checkpoint(DB_PATH, SCAN_ID, 'url_collection', 
                                      f'Running katana crawler on {subdomain}...')
                katana_urls = run_katana(subdomain, depth=5)
                # Batch insert URLs for better performance and reduced locking
                url_batch = [(url.strip(), subdomain_id, 'katana') for url in katana_urls if url and url.strip()]
                if url_batch:
                    from .database import store_urls_batch
                    inserted = store_urls_batch(DB_PATH, SCAN_ID, url_batch)
                    total_urls += inserted
                    update_scan_checkpoint(DB_PATH, SCAN_ID, 'url_collection', 
                                          f'Collected {inserted} URLs from katana for {subdomain}')
                mark_subdomain_tool_done(DB_PATH, subdomain_id, 'katana')
            
            mark_subdomain_collection_complete(DB_PATH, subdomain_id)
    else:
        # No subdomains - collect URLs directly for domain
        from .database import store_urls_batch, update_scan_checkpoint
        
        update_scan_checkpoint(DB_PATH, SCAN_ID, 'url_collection', f'Running waybackurls on {domain}...')
        wayback_urls = run_waybackurls(domain)
        # Batch insert URLs for better performance and reduced locking
        url_batch = [(url.strip(), None, 'waybackurls') for url in wayback_urls if url and url.strip()]
        if url_batch:
            inserted = store_urls_batch(DB_PATH, SCAN_ID, url_batch)
            total_urls += inserted
            update_scan_checkpoint(DB_PATH, SCAN_ID, 'url_collection', 
                                  f'Collected {inserted} URLs from waybackurls')
        
        update_scan_checkpoint(DB_PATH, SCAN_ID, 'url_collection', f'Running katana crawler on {domain}...')
        katana_urls = run_katana(domain, depth=5)
        # Batch insert URLs for better performance and reduced locking
        url_batch = [(url.strip(), None, 'katana') for url in katana_urls if url and url.strip()]
        if url_batch:
            inserted = store_urls_batch(DB_PATH, SCAN_ID, url_batch)
            total_urls += inserted
            update_scan_checkpoint(DB_PATH, SCAN_ID, 'url_collection', 
                                  f'Collected {inserted} URLs from katana')
        
        update_scan_checkpoint(DB_PATH, SCAN_ID, 'url_collection', 
                              f'URL collection complete: {total_urls} total URLs collected')
    
    return total_urls
