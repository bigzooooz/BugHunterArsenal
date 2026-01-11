#!/usr/bin/env python3
"""
BugHunter Arsenal - Multi-Tool Security Scanning Platform
Main entry point for routing to different security tools
"""

import sys
import argparse
import subprocess
import requests
import warnings
import time
from pathlib import Path
from colorama import Fore, Style, init

# Suppress SSL warnings
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# Initialize colorama
init(autoreset=True)

# Add project root to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

# Version check
VERSION = open(PROJECT_ROOT / "version.txt", "r").read().strip()
GITHUB_VERSION_URL = "https://raw.githubusercontent.com/bigzooooz/BugHunterArsenal/refs/heads/main/version.txt"

def check_version():
    """Check for updates from GitHub"""
    try:
        response = requests.get(GITHUB_VERSION_URL, verify=False, timeout=5)
        if response.status_code == 200:
            github_version = response.text.strip()
            if github_version > VERSION:
                print(Fore.YELLOW + f"[!] A new version of BugHunter Arsenal is available.")
                print(Fore.YELLOW + f"[!] Current: v{VERSION}, Latest: v{github_version}")
                print(Fore.YELLOW + f"[!] Update using: python BugHunterArsenal.py --update")
                print("")
    except Exception:
        pass  # Silently fail if can't check version

def update_project():
    """Update BugHunter Arsenal from GitHub"""
    try:
        response = requests.get(GITHUB_VERSION_URL, verify=False, timeout=5)
        if response.status_code == 200:
            github_version = response.text.strip()
            if github_version != VERSION:
                print(Fore.WHITE + "[+] Updating BugHunter Arsenal to the latest version...")
                subprocess.run(["git", "fetch", "origin", "main"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["git", "reset", "--hard", "origin/main"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print(Fore.GREEN + "[+] BugHunter Arsenal updated successfully. Please re-run the command.")
                sys.exit(0)
            else:
                print(Fore.GREEN + "[+] BugHunter Arsenal is already up-to-date.")
                sys.exit(0)
        else:
            print(Fore.RED + "[-] Failed to check for updates. Please update manually.")
            sys.exit(1)
    except Exception as e:
        print(Fore.RED + f"[-] Error updating: {e}")
        sys.exit(1)

def install_dependencies():
    """Install missing dependencies"""
    from tools.keyhunter.main import check_dependencies
    if check_dependencies(install=True):
        print(Fore.GREEN + "[+] All dependencies installed successfully!")
        sys.exit(0)
    else:
        print(Fore.RED + "[-] Installation failed or incomplete.")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="BugHunter Arsenal - Multi-tool security scanning platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Available Tools:
  keyhunter    - API key detection and validation (default)
  xsshunter    - Reflected XSS vulnerability scanner
  xss          - XSS vulnerability scanner (alias for xsshunter)
  orhunter     - Open redirect vulnerability scanner (ORHunter)
  openredirect - Open redirect vulnerability scanner (alias for orhunter)
  redirect     - Open redirect vulnerability scanner (alias for orhunter)
  dtohunter    - Domain TakeOver vulnerability scanner (DTOHunter)
  takeover     - Domain TakeOver vulnerability scanner (alias for dtohunter)

Examples:
  python BugHunterArsenal.py -d example.com --tool keyhunter
  python BugHunterArsenal.py -f domains.txt --tool keyhunter
  python BugHunterArsenal.py --gui
        """
    )
    
    parser.add_argument("--tool", dest="tools", 
                       help="Tool(s) to run (comma-separated, e.g., 'keyhunter,xsshunter'). Default: keyhunter",
                       default="keyhunter")
    
    # Common arguments
    parser.add_argument("-d", "--domain", help="Target domain for scanning.")
    parser.add_argument("-f", "--file", help="File containing a list of domains to scan.")
    parser.add_argument("-l", "--urls-file", help="File containing a list of URLs to scan directly.")
    parser.add_argument("-ns", "--no-subs", help="Disable subdomain enumeration.", action="store_true")
    parser.add_argument("--cookie", help="Cookie to use for requests.")
    parser.add_argument("--x-request-for", help="X-Request-For header to use for requests.")
    parser.add_argument("-o", "--output", help="Output directory name (default: output).")
    parser.add_argument("-v", "--verbose", help="Enable verbose output.", action="store_true")
    parser.add_argument("--restart", help="Force restart: delete existing scan and start fresh (default: resume from checkpoint if exists).", action="store_true")
    parser.add_argument("--gui", help="Start the web dashboard GUI server.", action="store_true")
    parser.add_argument("--install", "--setup", help="Install missing dependencies (requires sudo).", 
                       action="store_true", dest="install")
    parser.add_argument("--update", help="Update BugHunter Arsenal to the latest version.", action="store_true")
    parser.add_argument("--version", help="Show BugHunter Arsenal version.", action="store_true")
    
    args = parser.parse_args()
    
    # Handle --version flag
    if args.version:
        print(Fore.WHITE + f"[+] BugHunter Arsenal version: {VERSION}")
        sys.exit(0)
    
    # Handle --update flag
    if args.update:
        update_project()
    
    # Handle --install flag
    if args.install:
        install_dependencies()
    
    # Handle --gui flag
    if args.gui:
        # Display banner
        print(Fore.CYAN + f"""
    ██████╗ ██╗   ██╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
    ██╔══██╗██║   ██║██╔════╝ ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
    ██████╔╝██║   ██║██║  ███╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
    ██╔══██╗██║   ██║██║   ██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
    ██████╔╝╚██████╔╝╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
    ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
                                                                                    
    █████╗ ██████╗ ███████╗███████╗███╗   ██╗ █████╗ ██╗      
    ██╔══██╗██╔══██╗██╔════╝██╔════╝████╗  ██║██╔══██╗██║                        
    ███████║██████╔╝███████╗█████╗  ██╔██╗ ██║███████║██║                        
    ██╔══██║██╔══██╗╚════██║██╔══╝  ██║╚██╗██║██╔══██║██║                        
    ██║  ██║██║  ██║███████║███████╗██║ ╚████║██║  ██║███████╗                   
    ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝                   
                                                                                    
    Multi-tool security scanning platform for bug bounty hunters.  
                                
    """ + Style.RESET_ALL)
        
        time.sleep(1)
        
        # Display support message
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
        time.sleep(1)
        
        try:
            from bughunter import server
            import os
            import werkzeug
            server.app.logger.disabled = True
            werkzeug_env_vars = ['WERKZEUG_SERVER_FD', 'WERKZEUG_RUN_MAIN']
            for var in werkzeug_env_vars:
                if var not in os.environ:
                    os.environ[var] = '0'
            server.app.run(host='127.0.0.1', port=5000, debug=False, use_reloader=False)
            sys.exit(0)
        except Exception as e:
            print(f"Error: Failed to start web dashboard: {e}")
            sys.exit(1)
    
    # Check for updates (non-blocking)
    check_version()
    
    # Display banner
    print(Fore.CYAN + f"""
    ██████╗ ██╗   ██╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
    ██╔══██╗██║   ██║██╔════╝ ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
    ██████╔╝██║   ██║██║  ███╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
    ██╔══██╗██║   ██║██║   ██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
    ██████╔╝╚██████╔╝╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
    ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
                                                                                    
    █████╗ ██████╗ ███████╗███████╗███╗   ██╗ █████╗ ██╗      
    ██╔══██╗██╔══██╗██╔════╝██╔════╝████╗  ██║██╔══██╗██║                        
    ███████║██████╔╝███████╗█████╗  ██╔██╗ ██║███████║██║                        
    ██╔══██║██╔══██╗╚════██║██╔══╝  ██║╚██╗██║██╔══██║██║                        
    ██║  ██║██║  ██║███████║███████╗██║ ╚████║██║  ██║███████╗                   
    ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝                   
                                                                                    
    Multi-tool security scanning platform for bug bounty hunters.  
                                
    """ + Style.RESET_ALL)
    
    time.sleep(1)
    
    # Display support message
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
    
    # Normalize tools list - handle comma-separated values
    if args.tools is None:
        tools = ["keyhunter"]
    elif isinstance(args.tools, str):
        # Split by comma and strip whitespace
        tools = [t.strip() for t in args.tools.split(',') if t.strip()]
        # Validate tool names
        valid_tools = ["keyhunter", "xss", "xsshunter", "orhunter", "openredirect", "redirect", "dtohunter", "takeover"]
        invalid_tools = [t for t in tools if t not in valid_tools]
        if invalid_tools:
            parser.error(f"Invalid tool(s): {', '.join(invalid_tools)}. Valid options: {', '.join(valid_tools)}")
        if not tools:
            tools = ["keyhunter"]
    else:
        tools = args.tools if isinstance(args.tools, list) else [args.tools]
    
    # Filter out --tool argument from sys.argv before passing to child tools
    # Child tools will parse sys.argv themselves and don't know about --tool
    filtered_argv = []
    skip_next = False
    for i, arg in enumerate(sys.argv[1:], 1):  # Skip script name
        if skip_next:
            skip_next = False
            continue
        if arg == "--tool":
            skip_next = True
            continue
        filtered_argv.append(arg)
    
    # Store original argv and temporarily replace it
    original_argv = sys.argv[:]
    sys.argv = [sys.argv[0]] + filtered_argv
    
    try:
        # Route to appropriate tool(s)
        for tool in tools:
            if tool == "keyhunter":
                # Import and run keyhunter tool
                # It will parse arguments itself from sys.argv (without --tool)
                try:
                    from tools.keyhunter import main as keyhunter_main
                    import asyncio
                    # Pass all arguments to keyhunter by letting it parse sys.argv
                    asyncio.run(keyhunter_main.main())
                except ImportError as e:
                    print(f"Error: Failed to import keyhunter tool: {e}")
                    print("Make sure all dependencies are installed.")
                    sys.exit(1)
            elif tool == "xss" or tool == "xsshunter":
                # Import and run xsshunter tool
                try:
                    from tools.xsshunter import main as xsshunter_main
                    import asyncio
                    # Pass all arguments to xsshunter by letting it parse sys.argv
                    asyncio.run(xsshunter_main.main())
                except ImportError as e:
                    print(f"Error: Failed to import xsshunter tool: {e}")
                    print("Make sure all dependencies are installed.")
                    sys.exit(1)
            elif tool == "orhunter" or tool == "openredirect" or tool == "redirect":
                # Import and run ORHunter tool
                try:
                    from tools.orhunter import main as orhunter_main
                    import asyncio
                    # Pass all arguments to ORHunter by letting it parse sys.argv
                    asyncio.run(orhunter_main.main())
                except ImportError as e:
                    print(f"Error: Failed to import ORHunter tool: {e}")
                    print("Make sure all dependencies are installed.")
                    sys.exit(1)
            elif tool == "dtohunter" or tool == "takeover":
                # Import and run DTOHunter tool
                try:
                    from tools.dtohunter import main as dtohunter_main
                    import asyncio
                    # Pass all arguments to DTOHunter by letting it parse sys.argv
                    asyncio.run(dtohunter_main.main())
                except ImportError as e:
                    print(f"Error: Failed to import DTOHunter tool: {e}")
                    print("Make sure all dependencies are installed (dnspython required).")
                    sys.exit(1)
            else:
                print(f"Error: Unknown tool '{tool}'")
                sys.exit(1)
    finally:
        # Restore original argv
        sys.argv = original_argv

if __name__ == "__main__":
    main()
