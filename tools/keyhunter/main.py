import warnings
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

import subprocess, argparse, json, re, asyncio, os, yaml, gc, time, random, requests, shutil, sys, hashlib, sqlite3
from datetime import datetime
from pathlib import Path
from colorama import Fore, Style, init
from tqdm import tqdm
from tools.keyhunter.validator import validate_api_key

with_subs = True
VERBOSE = False

BATCH_SIZE = 5000 
cookie = ""
# Project root is 2 levels up from tools/keyhunter/main.py (go up to tools, then to project root)
PROJECT_ROOT = Path(__file__).parent.parent.parent

X_REQUEST_FOR = ""
HTTPX_PATH = None
OUTPUT_NAME = None
DB_PATH = None
CURRENT_SCAN_ID = None

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

REQUIRED_TOOLS = {
    "subfinder": {
        "check_paths": ["subfinder"],
        "install_go": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    },
    "waybackurls": {
        "check_paths": ["waybackurls"],
        "install_go": "go install github.com/tomnomnom/waybackurls@latest"
    },
    "httpx": {
        "check_paths": ["/usr/bin/httpx", "httpx"],
        "install_go": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
    },
    "katana": {
        "check_paths": ["katana"],
        "install_go": "go install github.com/projectdiscovery/katana/cmd/katana@latest"
    }
}

def is_root():
    return os.geteuid() == 0 if hasattr(os, 'geteuid') else False

def check_tool(tool_name):
    tool_info = REQUIRED_TOOLS.get(tool_name)
    if not tool_info:
        return None, None
    
    for path in tool_info["check_paths"]:
        full_path = shutil.which(path)
        if full_path:
            return True, full_path
        if os.path.exists(path) and os.access(path, os.X_OK):
            return True, path
    
    return False, None

def install_go():
    if shutil.which("go") is not None:
        return True
    
    print(Fore.YELLOW + "[*] Go is not installed. Installing Go...")
    
    if not shutil.which("apt-get"):
        print(Fore.RED + "[-] apt-get not available. Cannot install Go automatically.")
        print(Fore.YELLOW + "[!] Please install Go manually: https://golang.org/doc/install")
        return False
    
    try:
        print(Fore.CYAN + "[*] Installing Go using apt-get...")
        result = subprocess.run(
            ["apt-get", "update"],
            capture_output=True,
            text=True,
            timeout=300
        )
        
        result = subprocess.run(
            ["apt-get", "install", "-y", "golang-go"],
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if result.returncode == 0:
            if shutil.which("go") is not None:
                print(Fore.GREEN + "[+] Go installed successfully!")
                return True
            else:
                print(Fore.YELLOW + "[!] Go installed but not found in PATH. You may need to restart your terminal.")
                return True
        else:
            print(Fore.RED + f"[-] Failed to install Go: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        print(Fore.RED + "[-] Timeout while installing Go")
        return False
    except Exception as e:
        print(Fore.RED + f"[-] Error installing Go: {e}")
        return False

def move_binaries_to_path(tool_name, target_path="/usr/bin"):
    gopath = os.environ.get("GOPATH", os.path.expanduser("~/go"))
    go_bin_path = os.path.join(gopath, "bin", tool_name)
    target_bin_path = os.path.join(target_path, tool_name)
    
    if not os.path.exists(go_bin_path):
        return False
    
    try:
        if os.path.exists(target_bin_path):
            os.remove(target_bin_path)
        
        shutil.copy2(go_bin_path, target_bin_path)
        os.chmod(target_bin_path, 0o755)
        print(Fore.GREEN + f"[+] Moved {tool_name} to {target_bin_path}")
        return True
    except PermissionError:
        print(Fore.YELLOW + f"[!] Permission denied moving {tool_name} to {target_path}. Using {go_bin_path}")
        return False
    except Exception as e:
        print(Fore.YELLOW + f"[!] Could not move {tool_name}: {e}. Using {go_bin_path}")
        return False

def install_tool(tool_name, bin_path="/usr/bin"):
    tool_info = REQUIRED_TOOLS.get(tool_name)
    if not tool_info:
        return False
    
    if not install_go():
        return False
    
    print(Fore.YELLOW + f"[*] Installing {tool_name} using Go...")
    try:
        result = subprocess.run(
            tool_info["install_go"].split(),
            capture_output=True,
            text=True,
            timeout=600
        )
        
        if result.returncode == 0:
            found, path = check_tool(tool_name)
            if found:
                print(Fore.GREEN + f"[+] Successfully installed {tool_name} at {path}")
                return True
            
            gopath = os.environ.get("GOPATH", os.path.expanduser("~/go"))
            go_bin_path = os.path.join(gopath, "bin", tool_name)
            
            if os.path.exists(go_bin_path):
                if move_binaries_to_path(tool_name, bin_path):
                    found, path = check_tool(tool_name)
                    if found:
                        return True
                
                print(Fore.GREEN + f"[+] Successfully installed {tool_name} at {go_bin_path}")
                print(Fore.YELLOW + f"[!] Binary is in {go_bin_path}. Consider adding {gopath}/bin to your PATH or moving it to /usr/bin")
                return True
            else:
                print(Fore.RED + f"[-] {tool_name} installation completed but binary not found at {go_bin_path}")
                if result.stdout:
                    print(Fore.YELLOW + f"    Go output: {result.stdout[:200]}")
                return False
        else:
            print(Fore.RED + f"[-] Failed to install {tool_name} via Go")
            if result.stderr:
                print(Fore.RED + f"    Error: {result.stderr[:500]}")
            if result.stdout:
                print(Fore.YELLOW + f"    Output: {result.stdout[:500]}")
            return False
    except subprocess.TimeoutExpired:
        print(Fore.RED + f"[-] Timeout while installing {tool_name} via Go")
        return False
    except Exception as e:
        print(Fore.RED + f"[-] Error installing {tool_name} via Go: {e}")
        return False

def check_dependencies(install=False):
    missing_tools = []
    
    for tool_name in REQUIRED_TOOLS.keys():
        found, path = check_tool(tool_name)
        if not found:
            print(Fore.YELLOW + f"[-] {tool_name} not found")
            missing_tools.append(tool_name)
    
    if not missing_tools:
        if install:
            print(Fore.GREEN + "[+] All dependencies are already installed!")
        return True
    
    print("")
    if install:
        if not is_root():
            print(Fore.RED + "[-] Installation requires root privileges. Please run with sudo.")
            print(Fore.YELLOW + "[!] Example: sudo python3 BugHunterArsenal.py --install")
            return False
        
        print(Fore.CYAN + "[*] Installing missing dependencies...")
        print(Fore.CYAN + "[*] This may take a few minutes...")
        print("")
        
        bin_path = "/usr/bin"
        if os.environ.get("KEYHUNTER_BIN_PATH"):
            bin_path = os.environ.get("KEYHUNTER_BIN_PATH")
            print(Fore.CYAN + f"[*] Using custom binary path: {bin_path}")
        else:
            print(Fore.CYAN + f"[*] Binaries will be moved to: {bin_path} (set KEYHUNTER_BIN_PATH env var to change)")
        
        failed_tools = []
        for tool_name in missing_tools:
            if not install_tool(tool_name, bin_path):
                failed_tools.append(tool_name)
        
        if failed_tools:
            print("")
            print(Fore.RED + f"[-] Failed to install: {', '.join(failed_tools)}")
            print(Fore.YELLOW + "[!] Please install them manually and try again.")
            return False
        
        print("")
        print(Fore.WHITE + "[+] Re-checking dependencies...")
        all_found = True
        for tool_name in missing_tools:
            found, path = check_tool(tool_name)
            if not found:
                print(Fore.RED + f"[-] {tool_name} still not found after installation")
                all_found = False
        
        if all_found:
            print(Fore.GREEN + "[+] All dependencies are now installed!")
            return True
        else:
            print(Fore.YELLOW + "[!] Some tools may need to be added to PATH. Please restart your terminal or add them manually.")
            return False
    else:
        print(Fore.RED + f"[-] Missing dependencies: {', '.join(missing_tools)}")
        print(Fore.YELLOW + "[!] Install dependencies using: sudo python3 BugHunterArsenal.py --install")
        print(Fore.YELLOW + "[!] Or install them manually using Go:")
        for tool_name in missing_tools:
            tool_info = REQUIRED_TOOLS[tool_name]
            print(Fore.WHITE + f"    {tool_info['install_go']}")
        if not shutil.which("go"):
            print(Fore.YELLOW + "[!] Go is required. Install it with: sudo apt-get install -y golang-go")
        return False


def run_subfinder(domain):
    try:
        cmd = ["subfinder", "-d", domain, "-all", "-recursive"]
        if not VERBOSE:
            cmd.append("-silent")
        result = subprocess.run(cmd, capture_output=True, text=True)
        return (line.strip() for line in result.stdout.splitlines()) 
    except Exception as e:
        print(f"Error running subfinder: {e}")
        return iter([])

def run_waybackurls(domain):
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

def run_katana(target, depth=5):
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

def remove_version_param(url):
    return re.sub(r'(\?v=|ver=|version=|rev=|timestamp=|build=|_token=)[^&]+', '', url).rstrip('?')

def init_database(db_path):
    """Initialize database with checkpoint support"""
    from bughunter import database
    return database.init_database_with_checkpoints(db_path)

def create_scan(domain, scan_type, output_dir=None, interactive=None, force_restart=False):
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


def batched(iterable, size):
    batch = []
    for item in iterable:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch

def load_api_key_patterns_from_db(db_path: str = None):
    """Load API key patterns from database and compile as regex patterns"""
    global api_key_patterns
    try:
        from bughunter.config_migration import load_api_patterns_from_db, get_main_db_path
        
        if db_path is None:
            db_path = str(get_main_db_path())
        
        # Ensure DB is initialized and synced
        from bughunter.database import init_database_with_checkpoints
        init_database_with_checkpoints(db_path)
        from bughunter.config_migration import sync_all_configs_from_yaml
        sync_all_configs_from_yaml(db_path)
        
        # Load patterns from DB
        patterns_dict = load_api_patterns_from_db(db_path)
        
        # Compile regex patterns
        compiled_patterns = {}
        for provider, pattern_str in patterns_dict.items():
            try:
                compiled_patterns[provider] = re.compile(r"{}".format(pattern_str))
            except re.error as e:
                if VERBOSE:
                    print(Fore.YELLOW + f"[-] Error compiling pattern for {provider}: {e}")
        
        api_key_patterns = compiled_patterns
        return compiled_patterns
    except Exception as e:
        if VERBOSE:
            print(Fore.YELLOW + f"[-] Error loading API key patterns from DB: {e}")
        return {}

def load_excluded_extensions_from_db(db_path: str = None):
    """Load excluded extensions from database"""
    global excluded_extensions
    try:
        from bughunter.config_migration import load_excluded_extensions_from_db, get_main_db_path
        
        if db_path is None:
            db_path = str(get_main_db_path())
        
        # Ensure DB is initialized and synced
        from bughunter.database import init_database_with_checkpoints
        init_database_with_checkpoints(db_path)
        from bughunter.config_migration import sync_all_configs_from_yaml
        sync_all_configs_from_yaml(db_path)
        
        excluded_extensions = load_excluded_extensions_from_db(db_path)
        return excluded_extensions
    except Exception as e:
        if VERBOSE:
            print(Fore.YELLOW + f"[-] Error loading excluded extensions from DB: {e}")
        return []

# Initialize patterns and extensions from database (lazy load on first use)
# Project root is 2 levels up from tools/keyhunter/main.py
PROJECT_ROOT = Path(__file__).parent.parent.parent
api_key_patterns = {}  # Will be loaded from DB on first use
excluded_extensions = []  # Will be loaded from DB on first use

# Load from DB at module level (ensure main DB exists)
try:
    from bughunter.config_migration import get_main_db_path
    main_db = str(get_main_db_path())
    load_api_key_patterns_from_db(main_db)
    load_excluded_extensions_from_db(main_db)
except Exception:
    # Fallback: patterns will be loaded when search_for_api_keys is called
    pass

def search_for_api_keys(content, url, scan_id, status_code=None, content_type=None, url_id=None):
    """Search for API keys in content. url_id should be provided when using checkpoint system."""
    global DB_PATH
    if not DB_PATH:
        return {}
    
    from bughunter.database import get_db_connection, retry_db_operation
    
    def _search():
        conn = get_db_connection(DB_PATH)
        cursor = conn.cursor()
        
        try:
            # If url_id not provided, look it up (backward compatibility)
            current_url_id = url_id
            if current_url_id is None:
                cursor.execute('SELECT url_id FROM urls WHERE scan_id = ? AND url = ?', (scan_id, url))
                url_row = cursor.fetchone()
                if url_row:
                    current_url_id = url_row[0]
                    # Update status code if provided
                    if status_code is not None or content_type is not None:
                        cursor.execute('''
                            UPDATE urls SET status_code = ?, content_type = ?, checked_at = CURRENT_TIMESTAMP
                            WHERE url_id = ?
                        ''', (status_code, content_type, current_url_id))
                else:
                    cursor.execute('''
                        INSERT INTO urls (scan_id, url, status_code, content_type)
                        VALUES (?, ?, ?, ?)
                    ''', (scan_id, url, status_code, content_type))
                    current_url_id = cursor.lastrowid
            
            keys_found = {}
            for provider, pattern in api_key_patterns.items():
                matches = pattern.findall(content)
                if matches:
                    unique_matches = []
                    seen = set()
                    for match in matches:
                        match_str = str(match) if not isinstance(match, str) else match
                        if match_str not in seen:
                            seen.add(match_str)
                            unique_matches.append(match_str)
                    
                    if unique_matches:
                        keys_found[provider] = unique_matches
                        
                        print(Fore.GREEN + f"[+] Found {provider}:")
                        for key in unique_matches:
                            validation_status = validate_api_key(provider, key)
                            time.sleep(0.2)
                            status_color = Fore.GREEN if validation_status == "valid" else (Fore.RED if validation_status == "invalid" else Fore.YELLOW)
                            status_icon = "✓" if validation_status == "valid" else ("✗" if validation_status == "invalid" else "?")
                            
                            try:
                                cursor.execute('''
                                    INSERT INTO api_keys (url_id, provider, key_value, validation_status)
                                    VALUES (?, ?, ?, ?)
                                ''', (current_url_id, provider, key, validation_status))
                                print(Fore.GREEN + f"    - {key} {status_color}[{status_icon} {validation_status.upper()}]" + Style.RESET_ALL)
                            except sqlite3.IntegrityError:
                                cursor.execute('''
                                    UPDATE api_keys SET validation_status = ? 
                                    WHERE url_id = ? AND provider = ? AND key_value = ?
                                ''', (validation_status, current_url_id, provider, key))
                                print(Fore.GREEN + f"    - {key} {status_color}[{status_icon} {validation_status.upper()}]" + Style.RESET_ALL)
                        
                        print(Fore.GREEN + f"    URL: {url}")
                        print(Fore.GREEN + "-"*60)
            
            conn.commit()
            return keys_found
        finally:
            conn.close()
    
    return retry_db_operation(_search)


def fetch_url(url):
    global cookie
    global X_REQUEST_FOR

    if not url or not isinstance(url, str) or not url.strip():
        if VERBOSE:
            print(Fore.YELLOW + f"[-] Invalid URL (empty or None): {url}")
        return None, None, None, None
    
    url = url.strip()
    
    try:
        if ' ' in url and not url.startswith("http://") and not url.startswith("https://"):
            if VERBOSE:
                print(Fore.YELLOW + f"[-] URL contains spaces, might be malformed: {url[:100]}")
    except:
        pass
    
    if not (url.startswith("http://") or url.startswith("https://")):
        if VERBOSE:
            print(Fore.YELLOW + f"[-] Invalid URL format (missing http/https): {url[:100]}")
        return None, None, None, None

    try:
        global HTTPX_PATH
        if HTTPX_PATH is None:
            found, path = check_tool("httpx")
            if not found:
                if VERBOSE:
                    print(Fore.RED + f"[-] httpx not found")
                return None, None, None, None
            HTTPX_PATH = path
        
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
            print(Fore.CYAN + f"[httpx] Executing: {' '.join(cmd)}")
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        
        if VERBOSE:
            if result.stdout:
                print(Fore.CYAN + f"[httpx stdout] {url}: {result.stdout.strip()[:500]}")
            if result.stderr:
                print(Fore.CYAN + f"[httpx stderr] {url}: {result.stderr.strip()[:500]}")
            print(Fore.CYAN + f"[httpx] Return code: {result.returncode}")
        
        if result.returncode != 0:
            error_parts = []
            if result.stderr and result.stderr.strip():
                error_parts.append(f"stderr: {result.stderr.strip()}")
            if result.stdout and result.stdout.strip():
                stdout_lines = result.stdout.strip().split('\n')
                error_lines = [line for line in stdout_lines if any(keyword in line.lower() for keyword in ['error', 'failed', 'invalid', 'unable', 'cannot'])]
                if error_lines:
                    error_parts.append(f"stdout errors: {'; '.join(error_lines[:3])}")
                elif len(stdout_lines) < 5:
                    error_parts.append(f"stdout: {result.stdout.strip()[:200]}")
            
            error_msg = "; ".join(error_parts) if error_parts else "Unknown error (no output in stderr or stdout)"
            
            if VERBOSE:
                print(Fore.YELLOW + f"[-] httpx error for {url}: {error_msg}")
                print(Fore.YELLOW + f"    Return code: {result.returncode}")
                if result.stdout:
                    print(Fore.YELLOW + f"    Full stdout: {result.stdout[:500]}")
                if result.stderr:
                    print(Fore.YELLOW + f"    Full stderr: {result.stderr[:500]}")
            return None, None, None, None

        if not result.stdout.strip():
            if VERBOSE:
                print(Fore.YELLOW + f"[-] No output from httpx for {url}")
                print(Fore.YELLOW + f"    Return code: {result.returncode}")
                if result.stderr:
                    print(Fore.YELLOW + f"    stderr: {result.stderr.strip()[:200]}")
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
                    print(Fore.YELLOW + f"[-] Non-200 status {status_code} for {url}")
                return None, None, status_code, None

            content_type = (httpx_output.get("content_type") or 
                          httpx_output.get("content-type") or 
                          "").lower()
            
            if not any(t in content_type for t in ["text/html", "application/javascript", "text/javascript", "application/json"]):
                if VERBOSE:
                    print(Fore.YELLOW + f"[-] Skipping {url} - content type: {content_type}")
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
                    print(Fore.YELLOW + f"[-] No content body for {url}")
                return None, None, status_code, content_type
            
            if len(content) > 500_000:
                content = content[:500_000]

            return url, content, status_code, content_type

        except json.JSONDecodeError as e:
            if VERBOSE:
                print(Fore.YELLOW + f"[-] Failed to parse httpx JSON output for {url}: {e}")
                print(Fore.YELLOW + f"    Return code: {result.returncode}")
                print(Fore.YELLOW + f"    stdout (first 500 chars): {result.stdout[:500]}")
                print(Fore.YELLOW + f"    stderr (first 500 chars): {result.stderr[:500] if result.stderr else '(empty)'}")
                if result.stdout and not result.stdout.strip().startswith('{'):
                    print(Fore.YELLOW + f"    Note: stdout doesn't appear to be JSON - might be an error message")
            return None, None, None, None
        except Exception as e:
            if VERBOSE:
                print(Fore.YELLOW + f"[-] Unexpected error parsing httpx output for {url}: {e}")
                print(Fore.YELLOW + f"    Return code: {result.returncode}")
                print(Fore.YELLOW + f"    stdout: {result.stdout[:500] if result.stdout else '(empty)'}")
                print(Fore.YELLOW + f"    stderr: {result.stderr[:500] if result.stderr else '(empty)'}")
            return None, None, None, None

    except subprocess.TimeoutExpired:
        if VERBOSE:
            print(Fore.YELLOW + f"[-] Timeout for {url}")
    except Exception as e:
        if VERBOSE:
            print(Fore.YELLOW + f"[-] Unexpected error for {url}: {e}")

    return None, None, None, None


async def visit_and_check_for_keys_from_db(scan_id, announce_urls=False):
    """Check URLs from database with checkpoint support"""
    global DB_PATH
    from bughunter import database
    
    api_keys_found = 0
    processed = 0
    
    # Get pending URLs count
    url_stats = database.count_urls_by_status(DB_PATH, scan_id)
    total_urls = url_stats.get('pending', 0)
    
    if total_urls == 0:
        print(Fore.YELLOW + "[!] No pending URLs to scan"); sys.stdout.flush()
        database.update_scan_checkpoint(DB_PATH, scan_id, 'scanning', 'No URLs to scan')
        return 0
    
    print(Fore.CYAN + f"[*] Stage: Processing {total_urls} pending URLs in batches of {BATCH_SIZE}"); sys.stdout.flush()
    database.update_scan_checkpoint(DB_PATH, scan_id, 'scanning', 
                                    f'Starting API key scanning: {total_urls} URLs in batches of {BATCH_SIZE}')
    
    # Process URLs in batches
    batch_num = 0
    while True:
        # Get next batch of pending URLs
        pending_urls = database.get_pending_urls(DB_PATH, scan_id, limit=BATCH_SIZE)
        
        if not pending_urls:
            break
        
        batch_size = len(pending_urls)
        batch_num += 1
        processed_in_batch = 0
        
        # Update checkpoint: Processing batch
        estimated_total_batches = (total_urls // BATCH_SIZE) + 1
        database.update_scan_checkpoint(DB_PATH, scan_id, 'scanning', 
                                        f'Processing batch {batch_num}/{estimated_total_batches}: Fetching {batch_size} URLs...')
        print(Fore.CYAN + f"[*] Stage: Processing batch {batch_num} ({batch_size} URLs)"); sys.stdout.flush()
        
        # Create tasks for fetching URLs
        url_dict = {url_info['url']: url_info for url_info in pending_urls}
        tasks = [asyncio.to_thread(fetch_url, url_info['url']) for url_info in pending_urls]
        results = await asyncio.gather(*tasks)
        
        # Update checkpoint: Scanning content for API keys
        database.update_scan_checkpoint(DB_PATH, scan_id, 'scanning', 
                                        f'Batch {batch_num}: Scanning content for API key leaks...')
        
        for i, (url, content, status_code, content_type) in enumerate(results):
            url_info = pending_urls[i]
            url_id = url_info['url_id']
            
            if not url:
                url = url_info['url']
            
            processed += 1
            processed_in_batch += 1
            
            if processed % 100 == 0 or VERBOSE or announce_urls:
                print(Fore.CYAN + f"[*] Stage: Checking URL {processed}/{total_urls} - {url[:80]}..."); sys.stdout.flush()
            
            # Update checkpoint more frequently for better real-time updates
            if processed_in_batch % 50 == 0 or processed % 200 == 0:
                remaining = total_urls - processed
                database.update_scan_checkpoint(DB_PATH, scan_id, 'scanning', 
                    f'Batch {batch_num}: Scanning content for API keys - {processed}/{total_urls} processed ({remaining} remaining)')
            
            # Mark URL as checked
            database.mark_url_checked(DB_PATH, url_id, status_code, content_type)
            
            if content:
                keys = search_for_api_keys(content, url, scan_id, status_code, content_type, url_id=url_id)
                if keys:
                    api_keys_found += 1
            else:
                # Mark as failed if no content
                database.mark_url_failed(DB_PATH, url_id)
        
        gc.collect()
        
        # Update checkpoint after batch completion
        database.update_scan_checkpoint(DB_PATH, scan_id, 'scanning', 
            f'Batch {batch_num} complete: {processed}/{total_urls} URLs processed, {api_keys_found} URLs with API keys found so far')
        print(Fore.CYAN + f"[*] Stage: Completed batch {batch_num}, processed {processed}/{total_urls} URLs"); sys.stdout.flush()
        
        # Check if there are more URLs to process
        remaining_urls = database.get_pending_urls(DB_PATH, scan_id, limit=1)
        if not remaining_urls:
            # Final checkpoint update
            database.update_scan_checkpoint(DB_PATH, scan_id, 'scanning', 
                f'Completed scanning: {processed}/{total_urls} URLs processed, {api_keys_found} URLs with API keys found')
            break

    print(Fore.CYAN + f"[*] Stage: Finished processing all {processed} URLs"); sys.stdout.flush()
    return api_keys_found


async def visit_and_check_for_keys(urls, scan_id, announce_urls=False):
    """Legacy function - use visit_and_check_for_keys_from_db for checkpoint support"""
    # Store URLs to database first
    from bughunter import database
    
    url_ids = []
    for url in urls:
        url_id = database.store_url(DB_PATH, scan_id, url, source='manual')
        url_ids.append(url_id)
    
    # Then process from database
    return await visit_and_check_for_keys_from_db(scan_id, announce_urls)


def update_scan_status(scan_id, status='completed'):
    """Update scan status - uses checkpoint system if available"""
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
    global with_subs
    global cookie
    global X_REQUEST_FOR
    global VERBOSE
    global OUTPUT_NAME
    global DB_PATH
    global CURRENT_SCAN_ID

    init(autoreset=True)

    print(Fore.CYAN + f"""

    ██╗  ██╗███████╗██╗   ██╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
    ██║ ██╔╝██╔════╝╚██╗ ██╔╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
    █████╔╝ █████╗   ╚████╔╝ ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
    ██╔═██╗ ██╔══╝    ╚██╔╝  ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
    ██║  ██╗███████╗   ██║   ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
    ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
                                                                                    
    API Key Security Scanning Tool
                                
    """ + Style.RESET_ALL)

    time.sleep(1)
    print(Fore.YELLOW + "="*60)
    print(Fore.CYAN + "     💖 Support BugHunter Arsenal Development 💖")
    print("")
    print(Fore.GREEN + " ☕ Ko-fi:   " + Fore.CYAN + "https://ko-fi.com/s/cb4c85e80b")
    print(Fore.GREEN + " 💸 PayPal:  " + Fore.CYAN + "https://paypal.me/b4zb0z")
    print(Fore.GREEN + " 🌐 Website: " + Fore.CYAN + "https://abdulaziz-d.com")
    print("")
    print(Fore.YELLOW + " Your support helps maintain and improve BugHunter Arsenal")
    print("")
    print(Fore.YELLOW + "="*60)
    print("")
    time.sleep(2)

    parser = argparse.ArgumentParser(description="BugHunter Arsenal - KeyHunter Tool: API key security scanning and management.")

    parser.usage = "BugHunterArsenal.py -d TARGET_DOMAIN | -f DOMAINS_FILE | -l URLS_FILE [--tool keyhunter] [--cookie COOKIE] [--no-subs]"

    parser.add_argument("-d", "--domain", help="Target domain for scanning.")
    parser.add_argument("-f", "--file", help="File containing a list of domains to scan.")
    parser.add_argument("-l", "--urls-file", help="File containing a list of URLs to scan directly.")
    parser.add_argument("-ns", "--no-subs", help="Disable subdomain enumeration.", action="store_true")
    parser.add_argument("--cookie", help="Cookie to use for requests.")
    parser.add_argument("--x-request-for", help="X-Request-For header to use for requests. (i.e. --x-request-for HackerOne)")
    parser.add_argument("-o", "--output", help="Output directory name (default: output).")
    parser.add_argument("-v","--verbose", help="Enable verbose output.", action="store_true")
    parser.add_argument("--restart", help="Force restart: delete existing scan and start fresh (default: resume from checkpoint if exists).", action="store_true")

    args = parser.parse_args()

    if args.verbose:
        VERBOSE = True

    if args.x_request_for:
        X_REQUEST_FOR = args.x_request_for

    if args.cookie:
        cookie = args.cookie

    if args.no_subs:
        with_subs = False
    
    if args.output:
        OUTPUT_NAME = args.output

    if not check_dependencies(install=False):
        print("")
        print(Fore.RED + "[-] Cannot proceed without required dependencies.")
        print(Fore.YELLOW + "[!] Install dependencies using: sudo python3 BugHunterArsenal.py --install")
        print("")
        sys.exit(1)
    
    # Start scanning
    global HTTPX_PATH
    found, path = check_tool("httpx")
    if found:
        HTTPX_PATH = path
    else:
        print(Fore.RED + "[-] httpx not found even after dependency check. Exiting.")
        sys.exit(1)
    
    print("")

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
            exit(1)
        
        if not urls:
            print(Fore.RED + "[-] No URLs found in the file.")
            exit(1)
        
        print(Fore.WHITE + f"  Total URLs: {Fore.GREEN}{len(urls)}")
        print("")
        
        print(Fore.WHITE + "-"*60)
        print("")
        print(Fore.WHITE + f"- Cookie: {'✔️'  if cookie else '❌'}")
        print(Fore.WHITE + f"- X-Request-For: {X_REQUEST_FOR if X_REQUEST_FOR else '❌'}")
        print("")
        
        print(Fore.GREEN + f"[+] Loaded {len(urls)} URLs from file 🎯")
        print(Fore.CYAN + f"[*] Stage: Initializing database and scan record..."); sys.stdout.flush()
        
        if OUTPUT_NAME:
            output_dir = OUTPUT_NAME
        else:
            output_dir = "output"
        os.makedirs(output_dir, exist_ok=True)
        DB_PATH = os.path.join(output_dir, "bughunter.db")
        init_database(DB_PATH)
        
        scan_id = create_scan("urls_file", "urls_file", output_dir, interactive=False, force_restart=getattr(args, 'restart', False))
        CURRENT_SCAN_ID = scan_id
        
        # Set up database context
        from bughunter import recon, database
        recon.set_database_context(DB_PATH, scan_id)
        
        # Store URLs to database with checkpoint support
        database.update_scan_checkpoint(DB_PATH, scan_id, 'url_collection', f'Storing {len(urls)} URLs from file...')
        print(Fore.CYAN + f"[*] Stage: Storing URLs to database..."); sys.stdout.flush()
        
        for url in urls:
            if url and url.strip():
                database.store_url(DB_PATH, scan_id, url.strip(), source='urls_file')
        
        # Get pending URLs count
        url_stats = database.count_urls_by_status(DB_PATH, scan_id)
        pending_count = url_stats.get('pending', 0)
        
        print(Fore.CYAN + f"[*] Stage: Scan ID {scan_id} created, starting URL processing..."); sys.stdout.flush()
        print(Fore.WHITE + "[+] Scanning URLs for API key leaks... This may take a while.")
        print("")
        
        database.update_scan_checkpoint(DB_PATH, scan_id, 'scanning', f'Scanning {pending_count} URLs for API keys...')
        api_keys_found = await visit_and_check_for_keys_from_db(scan_id, announce_urls=True)
        
        print(Fore.CYAN + "[*] Stage: Scan completed, updating status..."); sys.stdout.flush()
        database.update_scan_checkpoint(DB_PATH, scan_id, 'completed', f'Completed: Found {api_keys_found} URLs with API keys')
        update_scan_status(scan_id, 'completed')
        
        # Get final stats
        final_stats = database.count_urls_by_status(DB_PATH, scan_id)
        checked_count = final_stats.get('checked', 0)
        print(Fore.WHITE + f"[+] Scanned {checked_count} URLs.")

        if api_keys_found:
            print(Fore.GREEN + f"[+] Found {api_keys_found} URLs with API keys.")
        else:
            print(Fore.YELLOW + "[-] No API keys found.")
        
        print(Fore.WHITE + "[+] Done! 🎉")
        print("")
    
    else:
        domains = []
        if args.domain:
            domains.append(args.domain)
        elif args.file:
            print(Fore.WHITE + "-"*60)
            print(Fore.CYAN + "📄 Domains File Configuration")
            print("")
            print(Fore.WHITE + f"  File Path: {Fore.CYAN}{args.file}")
            
            try:
                with open(args.file, 'r') as file:
                    domains = [line.strip() for line in file if line.strip()]
            except Exception as e:
                print(Fore.RED + f"[-] Error reading domains from file: {e}")
                exit(1)
            
            if not domains:
                print(Fore.RED + "[-] No domains found in the file.")
                exit(1)
            
            print(Fore.WHITE + f"  Total Targets: {Fore.GREEN}{len(domains)}")
            print("")
        else:
            print(Fore.RED + "[-] Please provide either a domain (-d), a file containing domains (-f), or a file containing URLs (-l).")
            exit(1)

        for domain in domains:
            urls = []
            print(Fore.WHITE + "-"*60)
            print("")
            print(Fore.WHITE + f"- Target: {domain}")
            print(Fore.WHITE + f"- Subdomains: {'✔️' if with_subs else '❌'}")
            print(Fore.WHITE + f"- Cookie: {'✔️'  if cookie else '❌'}")
            print(Fore.WHITE + f"- X-Request-For: {X_REQUEST_FOR if X_REQUEST_FOR else '❌'}")
            print("")

            # Initialize database and create/resume scan
            # Always use per-domain database files to avoid locking issues when running multiple separate scans
            # This ensures each domain gets its own database even when running separate processes
            if OUTPUT_NAME:
                output_dir = OUTPUT_NAME
            else:
                output_dir = "output"
            os.makedirs(output_dir, exist_ok=True)
            
            # Sanitize domain name for use in filename
            safe_domain = re.sub(r'[^\w\-_\.]', '_', domain)
            # Always use per-domain database file to avoid conflicts between separate concurrent scans
            # This works even when running separate commands: python script.py -d domain1.com (separate process)
            # and python script.py -d domain2.com (another separate process)
            DB_PATH = os.path.join(output_dir, f"bughunter_{safe_domain}.db")
            
            init_database(DB_PATH)
            
            print(Fore.CYAN + f"[*] Stage: Initializing database and scan record..."); sys.stdout.flush()
            scan_id = create_scan(domain, "domain", output_dir, interactive=False, force_restart=getattr(args, 'restart', False))
            CURRENT_SCAN_ID = scan_id
            
            # Set up database context for recon module
            from bughunter import recon, database
            
            # Configure recon module
            recon.set_database_context(DB_PATH, scan_id)
            recon.set_verbose(VERBOSE)
            recon.set_subdomain_enum(with_subs)
            
            # Load excluded extensions from database
            from bughunter.config_migration import get_main_db_path
            main_db = str(get_main_db_path())
            excluded_exts = load_excluded_extensions_from_db(main_db)
            recon.set_excluded_extensions(excluded_exts)
            
            # Update checkpoint to subdomain enumeration
            database.update_scan_checkpoint(DB_PATH, scan_id, 'subdomain_enum', 'Starting subdomain enumeration...')
            
            # Check if URLs already exist (for rescan mode)
            url_stats = database.count_urls_by_status(DB_PATH, scan_id)
            existing_urls = sum(url_stats.values())
            
            # Only collect URLs/subdomains if none exist (new scan) or if not in rescan mode
            if existing_urls == 0:
                # Collect subdomains and URLs with checkpoint support
                if with_subs:
                    print(Fore.CYAN + "[*] Stage: Starting subdomain enumeration..."); sys.stdout.flush()
                    print(Fore.WHITE + "[+] Looking for subdomains ...")
                    subdomain_count = recon.collect_subdomains_to_db(domain)
                    print(Fore.GREEN + f"[+] Found {subdomain_count} subdomains 🎯")
                    
                    database.update_scan_checkpoint(DB_PATH, scan_id, 'url_collection', f'Collecting URLs from {subdomain_count} subdomains...')
                    print(Fore.CYAN + f"[*] Stage: Collecting URLs from {subdomain_count} subdomains..."); sys.stdout.flush()
                    print(Fore.WHITE + "[+] Looking for URLs ...")
                    total_urls = recon.collect_urls_to_db(domain, enable_subdomains=True)
                else:
                    database.update_scan_checkpoint(DB_PATH, scan_id, 'url_collection', 'Collecting URLs (no subdomains)...')
                    print(Fore.CYAN + "[*] Stage: Collecting URLs (subdomain enumeration disabled)..."); sys.stdout.flush()
                    print(Fore.WHITE + "[+] Looking for URLs ...")
                    total_urls = recon.collect_urls_to_db(domain, enable_subdomains=False)
                
                print(Fore.GREEN + f"[+] Collected {total_urls} URLs 🎯")
                
                # Get URL count stats after collection
                url_stats = database.count_urls_by_status(DB_PATH, scan_id)
            else:
                # URLs already exist - rescan mode, skip collection
                print(Fore.CYAN + "[*] Stage: Rescan Mode - Reusing existing URLs..."); sys.stdout.flush()
                print(Fore.WHITE + f"[+] Found {existing_urls} existing URL(s) in database, skipping collection")
            
            pending_count = url_stats.get('pending', 0)
            
            print(Fore.CYAN + f"[*] Stage: Starting API key scanning on {pending_count} pending URLs..."); sys.stdout.flush()
            print(Fore.WHITE + "[+] Scanning URLs for API key leaks... This may take a while.")
            
            database.update_scan_checkpoint(DB_PATH, scan_id, 'scanning', f'Scanning {pending_count} URLs for API keys...')
            
            api_keys_found = await visit_and_check_for_keys_from_db(scan_id)

            print(Fore.CYAN + "[*] Stage: Scan completed, updating status..."); sys.stdout.flush()
            
            # Get final URL stats
            final_stats = database.count_urls_by_status(DB_PATH, scan_id)
            checked_count = final_stats.get('checked', 0)
            
            database.update_scan_checkpoint(DB_PATH, scan_id, 'completed', f'Completed: Found {api_keys_found} URLs with API keys')
            update_scan_status(scan_id, 'completed')

            print(Fore.WHITE + f"[+] Scanned {checked_count} URLs.")

            if api_keys_found:
                print(Fore.GREEN + f"[+] Found {api_keys_found} URLs with API keys.")
            else:
                print(Fore.YELLOW + "[-] No API keys found.")
            
            print(Fore.WHITE + "[+] Done! 🎉")
            print("")

if __name__ == "__main__":
    asyncio.run(main())