"""
Shared HTTP Client Module
Provides URL fetching functionality using httpx
for use by multiple security tools
"""

import subprocess
import json
import random
from typing import Tuple, Optional

# Global configuration
VERBOSE = False
HTTPX_PATH = None
cookie = ""
X_REQUEST_FOR = ""

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:54.0) Gecko/20100101 Firefox/54.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/17.17134",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:68.0) Gecko/20100101 Firefox/68.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"
]


def set_verbose(enabled: bool):
    """Set verbose output mode"""
    global VERBOSE
    VERBOSE = enabled


def set_httpx_path(path: str):
    """Set path to httpx binary"""
    global HTTPX_PATH
    HTTPX_PATH = path


def set_cookie(cookie_value: str):
    """Set cookie for authenticated requests"""
    global cookie
    cookie = cookie_value


def set_x_request_for(header_value: str):
    """Set X-Request-For header"""
    global X_REQUEST_FOR
    X_REQUEST_FOR = header_value


def fetch_url(url: str) -> Tuple[Optional[str], Optional[str], Optional[int], Optional[str]]:
    """
    Fetch URL content using httpx
    
    Args:
        url: URL to fetch
        
    Returns:
        Tuple of (url, content, status_code, content_type)
        Returns (None, None, None, None) on error
    """
    global HTTPX_PATH, cookie, X_REQUEST_FOR
    
    if not url or not isinstance(url, str) or not url.strip():
        if VERBOSE:
            print(f"[-] Invalid URL (empty or None): {url}")
        return None, None, None, None
    
    url = url.strip()
    
    if not (url.startswith("http://") or url.startswith("https://")):
        if VERBOSE:
            print(f"[-] Invalid URL format (missing http/https): {url[:100]}")
        return None, None, None, None

    try:
        if HTTPX_PATH is None:
            import shutil
            found_path = shutil.which("httpx")
            if not found_path:
                if VERBOSE:
                    print("[-] httpx not found")
                return None, None, None, None
            HTTPX_PATH = found_path
        
        cmd = [HTTPX_PATH, "-u", url, "-json", "-irr", "-fhr", "-timeout", "5", "-nc"]
        if VERBOSE:
            cmd.append("-v")
        
        user_agent = random.choice(USER_AGENTS)
        cmd.extend(["-H", f"User-Agent: {user_agent}"])
        cmd.extend(["-H", "Accept-Language: en-US,en;q=0.9"])
        cmd.extend(["-H", "Referer: https://www.google.com/"])
        cmd.extend(["-H", "Accept: */*"])
        cmd.extend(["-H", "Connection: keep-alive"])
        
        if X_REQUEST_FOR:
            cmd.extend(["-H", f"X-Request-For: {X_REQUEST_FOR}"])
        
        if cookie:
            cmd.extend(["-H", f"Cookie: {cookie}"])

        if VERBOSE:
            print(f"[httpx] Executing: {' '.join(cmd)}")
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        
        if result.returncode != 0:
            if VERBOSE:
                print(f"[-] httpx error for {url}: return code {result.returncode}")
            return None, None, None, None

        if not result.stdout.strip():
            if VERBOSE:
                print(f"[-] No output from httpx for {url}")
            return None, None, None, None

        try:
            output_lines = result.stdout.strip().split('\n')
            if not output_lines:
                return None, None, None, None
            
            json_line = output_lines[-1].strip()
            if not json_line:
                return None, None, None, None
            
            httpx_output = json.loads(json_line)
            
            status_code = (httpx_output.get("status_code") or 
                          httpx_output.get("status-code") or 
                          httpx_output.get("status") or 0)
            
            try:
                status_code = int(status_code)
            except (ValueError, TypeError):
                status_code = 0
            
            if status_code != 200:
                if VERBOSE:
                    print(f"[-] Non-200 status {status_code} for {url}")
                return None, None, status_code, None

            content_type = (httpx_output.get("content_type") or 
                          httpx_output.get("content-type") or 
                          "").lower()
            
            if not any(t in content_type for t in ["text/html", "application/javascript", "text/javascript", "application/json"]):
                if VERBOSE:
                    print(f"[-] Skipping {url} - content type: {content_type}")
                return None, None, status_code, content_type

            content = ""
            
            if "response" in httpx_output:
                response_data = httpx_output.get("response", {})
                if isinstance(response_data, dict):
                    content = (response_data.get("body") or 
                              response_data.get("response-body") or 
                              response_data.get("body_decoded") or "")
                elif isinstance(response_data, str):
                    content = response_data
            else:
                content = (httpx_output.get("body") or 
                          httpx_output.get("response-body") or 
                          httpx_output.get("body_decoded") or 
                          httpx_output.get("response") or "")
            
            if not content:
                if VERBOSE:
                    print(f"[-] No content body for {url}")
                return None, None, status_code, content_type
            
            if len(content) > 500_000:
                content = content[:500_000]

            return url, content, status_code, content_type

        except json.JSONDecodeError as e:
            if VERBOSE:
                print(f"[-] Failed to parse httpx JSON output for {url}: {e}")
            return None, None, None, None
        except Exception as e:
            if VERBOSE:
                print(f"[-] Unexpected error parsing httpx output for {url}: {e}")
            return None, None, None, None

    except subprocess.TimeoutExpired:
        if VERBOSE:
            print(f"[-] Timeout for {url}")
    except Exception as e:
        if VERBOSE:
            print(f"[-] Unexpected error for {url}: {e}")

    return None, None, None, None
