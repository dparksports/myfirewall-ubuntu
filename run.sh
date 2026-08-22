#!/usr/bin/env bash
# ==============================================================================
# GORT FIREWALL - Autonomous Linux Endpoint Defense & Connection Inspector
# Universal Launcher Script
# ==============================================================================

set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
BOLD='\033[1m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

print_banner() {
    echo -e "${CYAN}${BOLD}"
    echo "   ____  ___  ____ _____   _____ ___ ____  ______        ___    _     _     "
    echo "  / ___|/ _ \|  _ |_   _| |  ___|_ _|  _ \| ____\ \    / / \  | |   | |    "
    echo " | |  _| | | | |_) || |   | |_   | || |_) |  _|  \ \  / / _ \ | |   | |    "
    echo " | |_| | |_| |  _ < | |   |  _|  | ||  _ <| |___  \ \/ / ___ \| |___| |___ "
    echo "  \____|\___/|_| \_\|_|   |_|   |___|_| \_\_____|  \_/_/   \_\_____|_____| "
    echo "       Autonomous Linux Endpoint Defense • Made with ❤️ in California"
    echo -e "${NC}"
}

usage() {
    print_banner
    echo -e "${BOLD}Usage:${NC} ./run.sh [OPTIONS]"
    echo ""
    echo -e "${BOLD}Options:${NC}"
    echo "  -s, --security     Run in active firewall mode with root (sudo required)"
    echo "  -m, --mock         Run in safe/monitor-only mode (no root required)"
    echo "  -l, --login        Sign in with your Google account via browser (no API key needed)"
    echo "  -i, --install      Install/update all required dependencies"
    echo "  -t, --test         Run automated unit tests"
    echo "  -h, --help         Display this help message and exit"
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo "  sudo ./run.sh            # Run in active blocking mode"
    echo "  ./run.sh --mock          # Run in monitor-only safe mode"
    echo "  ./run.sh --login         # 1-Click Google account browser sign-in"
    echo "  ./run.sh --install       # Setup Python venv and dependencies"
    exit 0
}

# Ensure Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[ERROR] python3 is not installed on this system.${NC}"
    echo "Please install python3 (e.g., sudo apt install python3 python3-venv python3-pip) and try again."
    exit 1
fi

# Detect virtual environment
PYTHON_BIN=""
if [ -f "./venv/bin/python" ]; then
    PYTHON_BIN="./venv/bin/python"
elif [ -f "./.venv/bin/python" ]; then
    PYTHON_BIN="./.venv/bin/python"
elif [ -n "$VIRTUAL_ENV" ]; then
    PYTHON_BIN="$VIRTUAL_ENV/bin/python"
else
    # Auto-create venv if missing
    echo -e "${YELLOW}[INFO] Virtual environment not found. Setting up ./venv...${NC}"
    python3 -m venv venv
    ./venv/bin/pip install --upgrade pip
    ./venv/bin/pip install -r requirements.txt
    PYTHON_BIN="./venv/bin/python"
    echo -e "${GREEN}[OK] Virtual environment initialized successfully.${NC}"
fi

# Handle CLI Flags
MODE="auto"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -s|--security)
            MODE="security"
            shift
            ;;
        -m|--mock)
            MODE="mock"
            shift
            ;;
        -l|--login)
            echo -e "${CYAN}[INFO] Launching 1-Click Google Account Sign-In...${NC}"
            if [ "$EUID" -eq 0 ] && [ -n "$SUDO_USER" ]; then
                sudo -u "$SUDO_USER" "$PYTHON_BIN" myfirewall2.py --login
            else
                "$PYTHON_BIN" myfirewall2.py --login
            fi
            exit $?
            ;;
        -i|--install)
            echo -e "${CYAN}[INFO] Installing dependencies from requirements.txt...${NC}"
            "$PYTHON_BIN" -m pip install -r requirements.txt
            echo -e "${GREEN}[OK] Dependencies installed successfully!${NC}"
            exit 0
            ;;
        -t|--test)
            echo -e "${CYAN}[INFO] Running Gort Firewall test suite...${NC}"
            "$PYTHON_BIN" test_network_monitor.py
            "$PYTHON_BIN" test_firewall_manager.py
            "$PYTHON_BIN" test_connection_history.py
            "$PYTHON_BIN" test_event_monitors.py
            "$PYTHON_BIN" test_zero_trust.py
            "$PYTHON_BIN" test_autonomous_sentinel.py
            "$PYTHON_BIN" test_auth_manager.py
            echo -e "${GREEN}[OK] All tests passed successfully!${NC}"
            exit 0
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo -e "${RED}[ERROR] Unknown option: $1${NC}"
            usage
            ;;
    esac
done

# Check execution privilege
if [ "$MODE" = "security" ] || ([ "$MODE" = "auto" ] && [ "$EUID" -eq 0 ]); then
    if [ "$EUID" -ne 0 ]; then
        echo -e "${YELLOW}[INFO] Security Mode requires root privileges for Netfilter / iptables rules.${NC}"
        exec sudo "$PYTHON_BIN" myfirewall2.py "$@"
    else
        exec "$PYTHON_BIN" myfirewall2.py "$@"
    fi
else
    # Non-root / Mock Mode
    if [ "$EUID" -ne 0 ] && [ "$MODE" = "auto" ]; then
        echo -e "${CYAN}[INFO] Launching in Monitor-Only Safe Mode (No root).${NC}"
        echo -e "${CYAN}[TIP] To enable active kernel blocking, run: ${BOLD}sudo ./run.sh${NC}"
        sleep 1
    fi
    exec "$PYTHON_BIN" myfirewall2.py "$@"
fi
