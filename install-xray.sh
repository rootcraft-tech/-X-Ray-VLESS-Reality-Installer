#!/bin/bash

# X-Ray VLESS + REALITY VPN Automated Installation Script
# Based on the guide: "Creating VPN Server with X-Ray VLESS + REALITY"
# Compatible with Ubuntu 24.04 LTS
# Version: 1.2
# Author: ViT
# Repository: https://github.com/rootcraft-tech/-X-Ray-VLESS-Reality-Installer

set -e

# Set non-interactive mode for apt
export DEBIAN_FRONTEND=noninteractive

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function for colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}"
}

# Check root privileges
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        print_error "Use: sudo bash $0"
        exit 1
    fi
}

# Check Ubuntu version
check_ubuntu() {
    if ! grep -q "Ubuntu" /etc/os-release; then
        print_error "This script is designed for Ubuntu"
        exit 1
    fi
    
    VERSION=$(lsb_release -rs)
    if [[ "$VERSION" != "24.04" ]]; then
        print_warning "Script tested on Ubuntu 24.04, you have version $VERSION"
        
        # Check if running interactively
        if [[ -t 0 ]]; then
            read -p "Continue installation? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
        else
            print_status "Non-interactive mode: continuing with Ubuntu $VERSION"
        fi
    fi
}

# Get external IP address
get_external_ip() {
    print_status "Detecting external IP address..."
    
    # Priority to IPv4 addresses
    EXTERNAL_IP=$(curl -s -4 ifconfig.me 2>/dev/null || curl -s -4 ipinfo.io/ip 2>/dev/null || curl -s -4 icanhazip.com 2>/dev/null)
    
    # If IPv4 not found, try IPv6
    if [[ -z "$EXTERNAL_IP" ]]; then
        EXTERNAL_IP=$(curl -s -6 ifconfig.me 2>/dev/null || curl -s -6 ipinfo.io/ip 2>/dev/null || curl -s -6 icanhazip.com 2>/dev/null)
    fi
    
    if [[ -z "$EXTERNAL_IP" ]]; then
        print_error "Failed to detect external IP address"
        if [[ -t 0 ]]; then
            read -p "Enter server external IP address manually: " EXTERNAL_IP
        else
            print_error "Cannot prompt for IP in non-interactive mode"
            exit 1
        fi
    fi
    
    print_status "External IP address: $EXTERNAL_IP"
}

# Update system
update_system() {
    print_header "SYSTEM UPDATE"
    print_status "Updating system packages..."
    print_status "Using non-interactive mode to avoid configuration prompts"
    
    # Ensure non-interactive mode
    export DEBIAN_FRONTEND=noninteractive
    
    apt update -y
    apt upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"
    apt install curl wget unzip openssl net-tools -y
    print_status "System updated"
}

# Configure firewall
setup_firewall() {
    print_header "FIREWALL CONFIGURATION"
    print_status "Configuring UFW..."
    ufw --force reset
    ufw allow 22/tcp
    ufw allow 443/tcp
    ufw --force enable
    print_status "Firewall configured"
}

# Stop conflicting services
stop_conflicting_services() {
    print_header "STOPPING CONFLICTING SERVICES"
    
    services=("nginx" "apache2" "httpd")
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            print_status "Stopping $service..."
            systemctl stop "$service"
            systemctl disable "$service"
        fi
    done
    
    # Check if port 443 is occupied
    if netstat -tlnp 2>/dev/null | grep -q ":443 "; then
        print_warning "Port 443 is occupied by another process!"
        netstat -tlnp | grep ":443 "
        
        # Check if running interactively
        if [[ -t 0 ]]; then
            read -p "Continue installation? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
        else
            print_status "Non-interactive mode: continuing despite port conflict"
        fi
    fi
}

# Install X-Ray
install_xray() {
    print_header "X-RAY INSTALLATION"
    print_status "Downloading and installing X-Ray..."
    
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    
    # Check installation
    if /usr/local/bin/xray version >/dev/null 2>&1; then
        XRAY_VERSION=$(/usr/local/bin/xray version | head -n1)
        print_status "X-Ray installed successfully: $XRAY_VERSION"
    else
        print_error "X-Ray installation failed"
        exit 1
    fi
}

# Generate keys
generate_keys() {
    print_header "KEY GENERATION"
    
    print_status "Generating UUID..."
    UUID=$(/usr/local/bin/xray uuid)
    print_status "UUID: $UUID"
    
    print_status "Generating REALITY keys..."
    KEYS_OUTPUT=$(/usr/local/bin/xray x25519)
    
    # Extract keys from X-Ray 25.9.11+ format
    PRIVATE_KEY=$(echo "$KEYS_OUTPUT" | grep "PrivateKey:" | cut -d' ' -f2)
    PUBLIC_KEY=$(echo "$KEYS_OUTPUT" | grep "Password:" | cut -d' ' -f2)
    
    # Check that keys are not empty
    if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
        print_error "Failed to extract REALITY keys"
        print_error "Private Key: '$PRIVATE_KEY'"
        print_error "Public Key: '$PUBLIC_KEY'"
        print_error "Full output from xray x25519:"
        echo "$KEYS_OUTPUT"
        exit 1
    fi
    
    print_status "Private Key: $PRIVATE_KEY"
    print_status "Public Key: $PUBLIC_KEY"
    
    print_status "Generating Short ID..."
    SHORT_ID=$(openssl rand -hex 8)
    print_status "Short ID: $SHORT_ID"
}

# Create X-Ray configuration
create_xray_config() {
    print_header "X-RAY CONFIGURATION CREATION"
    
    print_status "Creating configuration file..."
    cat > /usr/local/etc/xray/config.json << EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$UUID",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "www.microsoft.com:443",
          "xver": 0,
          "serverNames": [
            "www.microsoft.com"
          ],
          "privateKey": "$PRIVATE_KEY",
          "shortIds": [
            "$SHORT_ID"
          ]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "protocol": [
          "bittorrent"
        ],
        "outboundTag": "blocked"
      }
    ]
  }
}
EOF

    # Check configuration
    print_status "Checking X-Ray configuration..."
    if /usr/local/bin/xray -test -config /usr/local/etc/xray/config.json; then
        print_status "X-Ray configuration created and verified"
    else
        print_error "Error in X-Ray configuration"
        print_error "Contents of config.json:"
        cat /usr/local/etc/xray/config.json
        exit 1
    fi
}

# Start X-Ray service
start_xray_service() {
    print_header "X-RAY SERVICE START"
    
    print_status "Enabling and starting X-Ray service..."
    systemctl enable xray
    systemctl start xray
    
    # Wait for startup
    sleep 3
    
    # Check status
    if systemctl is-active --quiet xray; then
        print_status "X-Ray service started successfully"
    else
        print_error "X-Ray service startup failed"
        systemctl status xray
        exit 1
    fi
    
    # Final restart for stable operation
    print_status "Final X-Ray restart for stabilization..."
    systemctl restart xray
    sleep 3
    
    # Check port with retries
    for i in {1..5}; do
        sleep 2
        if ss -tlnp | grep -q ":443.*xray"; then
            print_status "X-Ray is listening on port 443"
            break
        elif [[ $i -eq 5 ]]; then
            print_warning "X-Ray is not listening on port 443, but service is running"
            print_status "Try restarting: systemctl restart xray"
        fi
    done
}

# Create client configurations
create_client_configs() {
    print_header "CLIENT CONFIGURATIONS CREATION"
    
    # VLESS URL
    VLESS_URL="vless://${UUID}@${EXTERNAL_IP}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp&headerType=none#MyVPN"
    
    # Create configuration file
    CONFIG_FILE="/root/xray_client_configs.txt"
    cat > "$CONFIG_FILE" << EOF
================================================================================
                    X-RAY VLESS + REALITY VPN CONFIGURATION
================================================================================

Server successfully configured and running!

SERVER DATA:
- IP address: $EXTERNAL_IP
- Port: 443
- Protocol: VLESS
- Transport: TCP
- Security: REALITY

KEYS:
- UUID: $UUID
- Private Key: $PRIVATE_KEY
- Public Key: $PUBLIC_KEY
- Short ID: $SHORT_ID

VLESS URL FOR CLIENT IMPORT:
$VLESS_URL

CLIENT SETUP:

=== iOS (Streisand) ===
1. Download Streisand from App Store
2. Copy the VLESS URL above
3. Import configuration into the app

=== macOS (V2rayU) ===
1. Download V2rayU: https://github.com/yanue/V2rayU/releases
2. Intel Mac file: V2rayU-64.dmg
3. Apple Silicon file: V2rayU-arm64.dmg
4. Import via "Import Server From Pasteboard" (⌘P)

=== Android (v2rayNG) ===
1. Download v2rayNG from Google Play or GitHub
2. Import VLESS URL via QR code or paste directly

=== Windows (v2rayN) ===
1. Download v2rayN from GitHub: https://github.com/2dust/v2rayN/releases
2. Import configuration via clipboard

=== Manual Setup ===
Protocol: VLESS
Address: $EXTERNAL_IP
Port: 443
UUID: $UUID
Encryption: none
Flow: xtls-rprx-vision
Transport: TCP
TLS: Reality
SNI: www.microsoft.com
Fingerprint: chrome
PublicKey: $PUBLIC_KEY
ShortID: $SHORT_ID

MANAGEMENT COMMANDS:
- Service status: systemctl status xray
- Restart: systemctl restart xray
- Stop: systemctl stop xray
- Logs: journalctl -u xray -f
- Active connections: ss -tnp | grep :443
- Port check: ss -tlnp | grep :443

OPERATION CHECK:
Open 2ip.ru or whatismyipaddress.com
Should display IP: $EXTERNAL_IP

TROUBLESHOOTING:
If X-Ray is not listening on port 443:
1. systemctl restart xray
2. journalctl -u xray -n 20
3. ss -tlnp | grep xray

Configuration saved to file: $CONFIG_FILE

================================================================================
EOF

    print_status "Configurations saved to file: $CONFIG_FILE"
}

# Final check
final_check() {
    print_header "FINAL CHECK"
    
    print_status "Checking service status..."
    systemctl status xray --no-pager -l
    
    print_status "Checking ports..."
    ss -tlnp | grep ":443"
    
    print_status "Checking logs..."
    journalctl -u xray -n 5 --no-pager
}

# Main function
main() {
    print_header "X-RAY VLESS + REALITY VPN AUTO-INSTALLER v1.2"
    print_status "Automated installation of X-Ray VLESS + REALITY VPN server"
    print_warning "Make sure you're running this script on a clean Ubuntu 24.04 server"
    print_status "Repository: https://github.com/rootcraft-tech/-X-Ray-VLESS-Reality-Installer"
    
    echo
    
    # Check if running interactively
    if [[ -t 0 ]]; then
        # Interactive mode
        read -p "Continue installation? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_status "Installation cancelled"
            exit 0
        fi
    else
        # Non-interactive mode (pipe)
        print_status "Running in non-interactive mode, proceeding with installation..."
        sleep 2
    fi
    
    check_root
    check_ubuntu
    get_external_ip
    update_system
    setup_firewall
    stop_conflicting_services
    install_xray
    generate_keys
    create_xray_config
    start_xray_service
    create_client_configs
    final_check
    
    print_header "INSTALLATION COMPLETED SUCCESSFULLY!"
    print_status "X-Ray VLESS + REALITY VPN server is ready to use!"
    print_status "Client configurations: /root/xray_client_configs.txt"
    echo
    print_status "VLESS URL for client import:"
    echo -e "${GREEN}$VLESS_URL${NC}"
    echo
    print_status "Management commands:"
    echo "  cat /root/xray_client_configs.txt  # View configurations"
    echo "  systemctl status xray              # Service status"
    echo "  journalctl -u xray -f              # Real-time logs"
    echo "  ss -tlnp | grep :443               # Port check"
    
    print_warning "Save configurations in a secure place!"
    print_header "VPN SERVER IS READY TO USE! 🚀"
}

# Signal handling
trap 'print_error "Installation interrupted by user"; exit 1' INT TERM

# Run main function
main "$@"
