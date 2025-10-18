#!/bin/bash

# X-Ray VLESS + REALITY VPN Automated Installation Script (SECURE VERSION)
# Based on the guide: "Creating VPN Server with X-Ray VLESS + REALITY"
# Compatible with Ubuntu 24.04 LTS
# Version: 2.0 (Security Hardened)
# Author: ViT
# Repository: https://github.com/rootcraft-tech/-X-Ray-VLESS-Reality-Installer
# 
# SECURITY IMPROVEMENTS v2.0:
# - Blocked SMTP ports (25, 465, 587) to prevent spam
# - Blocked BitTorrent protocol
# - Blocked private IP ranges (geoip:private)
# - Blocked advertising domains (geosite:category-ads-all)
# - Added comprehensive access and error logging
# - Protected configuration files (chmod 600)
# - Added traffic monitoring script
# - Added security warnings about UUID protection
# - Improved routing rules to prevent abuse

set -e

# Set non-interactive mode for apt
export DEBIAN_FRONTEND=noninteractive

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
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

print_security() {
    echo -e "${MAGENTA}[SECURITY]${NC} $1"
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
    apt install curl wget unzip openssl net-tools lsb-release -y
    print_status "System updated"
}

# Configure firewall
setup_firewall() {
    print_header "FIREWALL CONFIGURATION"
    
    # Check if UFW is installed
    if ! command -v ufw &> /dev/null; then
        print_status "UFW not found, installing UFW..."
        apt update -y
        apt install ufw -y
        print_status "UFW installed successfully"
    else
        print_status "UFW is already installed"
    fi
    
    print_status "Configuring UFW..."
    
    # Reset UFW to default state
    ufw --force reset
    
    # Set default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH and HTTPS
    ufw allow 22/tcp comment 'SSH'
    ufw allow 443/tcp comment 'X-Ray VLESS'
    
    # Enable UFW
    ufw --force enable
    
    # Show status
    print_status "UFW status:"
    ufw status numbered
    
    print_security "Firewall configured: Only ports 22 (SSH) and 443 (X-Ray) are open"
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
    
    print_security "Keys generated successfully"
    print_security "NEVER share these keys publicly (GitHub, forums, chats)!"
}

# Create X-Ray configuration with security hardening
create_xray_config() {
    print_header "X-RAY CONFIGURATION CREATION (SECURITY HARDENED)"
    
    # Create log directory
    print_status "Creating log directory..."
    mkdir -p /var/log/xray
    chmod 755 /var/log/xray
    
    print_status "Creating secure configuration file..."
    print_security "Applying security rules:"
    print_security "  ✓ Blocking SMTP ports (25, 465, 587) - prevents spam"
    print_security "  ✓ Blocking BitTorrent protocol - prevents torrent abuse"
    print_security "  ✓ Blocking private IP ranges - prevents internal network scanning"
    print_security "  ✓ Blocking advertising domains - additional protection"
    print_security "  ✓ Enabling comprehensive logging - for security monitoring"
    
    cat > /usr/local/etc/xray/config.json << EOF
{
  "log": {
    "loglevel": "info",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
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
      "settings": {
        "domainStrategy": "UseIP"
      },
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "domainStrategy": "IPOnDemand",
    "rules": [
      {
        "type": "field",
        "protocol": [
          "bittorrent"
        ],
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "port": "25",
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "port": "465",
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "port": "587",
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "network": "udp",
        "port": "443",
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "ip": [
          "geoip:private"
        ],
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "domain": [
          "geosite:category-ads-all"
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
    
    # Secure configuration file
    print_status "Securing configuration file..."
    chmod 600 /usr/local/etc/xray/config.json
    chown root:root /usr/local/etc/xray/config.json
    
    print_security "Configuration file protected (chmod 600)"
    print_security "Only root can read/write this file"
}

# Setup log rotation
setup_log_rotation() {
    print_header "LOG ROTATION SETUP"
    
    print_status "Creating logrotate configuration..."
    cat > /etc/logrotate.d/xray << EOF
/var/log/xray/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 nobody nogroup
    sharedscripts
    postrotate
        systemctl reload xray > /dev/null 2>&1 || true
    endscript
}
EOF

    print_status "Log rotation configured: 7 days retention"
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

# Create monitoring script
create_monitoring_script() {
    print_header "MONITORING SCRIPT CREATION"
    
    print_status "Creating traffic monitoring script..."
    cat > /root/check_xray_traffic.sh << 'EOF'
#!/bin/bash

echo "===== X-Ray Traffic Monitor ====="
echo "Date: $(date)"
echo ""

# Check active connections
echo "=== Active connections to port 443 ==="
CONNECTIONS=$(ss -tnp 2>/dev/null | grep :443 | grep xray | wc -l)
echo "$CONNECTIONS connections"

# Check last 20 access log entries
echo ""
echo "=== Last 20 access log entries ==="
if [ -f /var/log/xray/access.log ]; then
    tail -20 /var/log/xray/access.log
else
    echo "No access log found"
fi

# Check errors
echo ""
echo "=== Errors in last hour ==="
if [ -f /var/log/xray/error.log ]; then
    grep "$(date -d '1 hour ago' '+%Y/%m/%d %H' 2>/dev/null || date '+%Y/%m/%d %H')" /var/log/xray/error.log 2>/dev/null | tail -10
else
    echo "No error log found"
fi

# Check suspicious SMTP attempts (should be 0)
echo ""
echo "=== SMTP connection attempts (should be 0) ==="
if [ -f /var/log/xray/access.log ]; then
    SMTP_COUNT=$(grep -E ":(25|465|587)" /var/log/xray/access.log 2>/dev/null | wc -l)
    echo "$SMTP_COUNT attempts"
    if [ $SMTP_COUNT -gt 0 ]; then
        echo "⚠️ WARNING: SMTP attempts detected! This should be blocked."
        grep -E ":(25|465|587)" /var/log/xray/access.log 2>/dev/null | tail -10
    fi
else
    echo "No access log found"
fi

# Check top 10 destination IPs
echo ""
echo "=== Top 10 destination IPs ==="
if [ -f /var/log/xray/access.log ]; then
    grep "accepted" /var/log/xray/access.log 2>/dev/null | awk '{print $NF}' | sort | uniq -c | sort -rn | head -10
else
    echo "No access log found"
fi

# Check BitTorrent attempts (should be 0)
echo ""
echo "=== BitTorrent attempts (should be 0) ==="
if [ -f /var/log/xray/access.log ]; then
    BT_COUNT=$(grep -i "bittorrent" /var/log/xray/access.log 2>/dev/null | wc -l)
    echo "$BT_COUNT attempts"
    if [ $BT_COUNT -gt 0 ]; then
        echo "⚠️ WARNING: BitTorrent attempts detected! This should be blocked."
    fi
else
    echo "No access log found"
fi

# Service status
echo ""
echo "=== X-Ray service status ==="
systemctl is-active xray && echo "✓ Service is active" || echo "✗ Service is not active"

# Port check
echo ""
echo "=== Port 443 status ==="
ss -tlnp 2>/dev/null | grep :443 | grep xray && echo "✓ X-Ray is listening on port 443" || echo "✗ X-Ray is NOT listening on port 443"

echo ""
echo "===== Monitor complete ====="
EOF

    chmod +x /root/check_xray_traffic.sh
    
    print_status "Monitoring script created: /root/check_xray_traffic.sh"
    print_status "Run: /root/check_xray_traffic.sh to check X-Ray traffic"
}

# Create security check script
create_security_check_script() {
    print_header "SECURITY CHECK SCRIPT CREATION"
    
    print_status "Creating security audit script..."
    cat > /root/xray_security_check.sh << 'EOF'
#!/bin/bash

echo "===== X-Ray Security Audit ====="
echo "Date: $(date)"
echo ""

# Check configuration file permissions
echo "=== Configuration file security ==="
CONFIG_PERMS=$(stat -c "%a" /usr/local/etc/xray/config.json 2>/dev/null)
if [ "$CONFIG_PERMS" = "600" ]; then
    echo "✓ Configuration file permissions: $CONFIG_PERMS (SECURE)"
else
    echo "✗ Configuration file permissions: $CONFIG_PERMS (INSECURE - should be 600)"
fi

# Check if SMTP ports are blocked in config
echo ""
echo "=== SMTP blocking check ==="
if grep -q '"port": "25"' /usr/local/etc/xray/config.json && \
   grep -q '"port": "465"' /usr/local/etc/xray/config.json && \
   grep -q '"port": "587"' /usr/local/etc/xray/config.json; then
    echo "✓ SMTP ports (25, 465, 587) are blocked in configuration"
else
    echo "✗ SMTP ports are NOT properly blocked"
fi

# Check if BitTorrent is blocked
echo ""
echo "=== BitTorrent blocking check ==="
if grep -q '"bittorrent"' /usr/local/etc/xray/config.json; then
    echo "✓ BitTorrent protocol is blocked in configuration"
else
    echo "✗ BitTorrent protocol is NOT blocked"
fi

# Check if private IPs are blocked
echo ""
echo "=== Private IP blocking check ==="
if grep -q 'geoip:private' /usr/local/etc/xray/config.json; then
    echo "✓ Private IP ranges are blocked in configuration"
else
    echo "✗ Private IP ranges are NOT blocked"
fi

# Check firewall status
echo ""
echo "=== Firewall status ==="
if ufw status | grep -q "Status: active"; then
    echo "✓ UFW firewall is active"
    ufw status numbered | grep -E "443|22"
else
    echo "✗ UFW firewall is NOT active"
fi

# Check for suspicious activity
echo ""
echo "=== Suspicious activity check (last 24 hours) ==="
if [ -f /var/log/xray/access.log ]; then
    # SMTP attempts
    SMTP_24H=$(grep -E ":(25|465|587)" /var/log/xray/access.log 2>/dev/null | wc -l)
    if [ $SMTP_24H -gt 0 ]; then
        echo "⚠️ WARNING: $SMTP_24H SMTP attempts in last 24h"
    else
        echo "✓ No SMTP attempts detected"
    fi
    
    # Unique destination IPs
    UNIQUE_IPS=$(grep "accepted" /var/log/xray/access.log 2>/dev/null | awk '{print $NF}' | sort -u | wc -l)
    echo "  Unique destination IPs: $UNIQUE_IPS"
    if [ $UNIQUE_IPS -gt 1000 ]; then
        echo "⚠️ WARNING: High number of unique destination IPs"
    fi
else
    echo "No access log found"
fi

# Check X-Ray service status
echo ""
echo "=== X-Ray service status ==="
systemctl is-active xray && echo "✓ Service is running" || echo "✗ Service is NOT running"

# Check if configuration was modified
echo ""
echo "=== Configuration integrity ==="
if [ -f /usr/local/etc/xray/config.json.original ]; then
    if diff -q /usr/local/etc/xray/config.json /usr/local/etc/xray/config.json.original > /dev/null 2>&1; then
        echo "✓ Configuration unchanged since installation"
    else
        echo "⚠️ Configuration was modified since installation"
    fi
else
    echo "  Original configuration backup not found"
fi

echo ""
echo "===== Security audit complete ====="
EOF

    chmod +x /root/xray_security_check.sh
    
    # Create backup of original configuration
    cp /usr/local/etc/xray/config.json /usr/local/etc/xray/config.json.original
    chmod 400 /usr/local/etc/xray/config.json.original
    
    print_status "Security check script created: /root/xray_security_check.sh"
    print_status "Run: /root/xray_security_check.sh to audit security"
    print_status "Original configuration backed up for integrity checking"
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
                          SECURITY HARDENED v2.0
================================================================================

Server successfully configured and running with enhanced security!

🔒 SECURITY FEATURES:
- ✓ SMTP ports blocked (25, 465, 587) - prevents spam abuse
- ✓ BitTorrent protocol blocked - prevents torrent abuse
- ✓ Private IP ranges blocked - prevents network scanning
- ✓ Advertising domains blocked - additional protection
- ✓ Comprehensive logging enabled - for security monitoring
- ✓ Configuration files protected (chmod 600)
- ✓ Log rotation configured (7 days retention)

SERVER DATA:
- IP address: $EXTERNAL_IP
- Port: 443
- Protocol: VLESS
- Transport: TCP
- Security: REALITY

KEYS (CONFIDENTIAL - NEVER SHARE PUBLICLY):
- UUID: $UUID
- Private Key: $PRIVATE_KEY
- Public Key: $PUBLIC_KEY
- Short ID: $SHORT_ID

⚠️ CRITICAL SECURITY WARNING:
═══════════════════════════════════════════════════════════════════════
NEVER SHARE UUID AND KEYS IN:
- ✗ Public GitHub repositories
- ✗ Forums or discussion boards
- ✗ Chat groups or messengers
- ✗ Social media posts
- ✗ Any public place

UUID = PASSWORD to your VPN server!
Anyone with UUID can use your server and potentially abuse it.

SAFE STORAGE OPTIONS:
- ✓ Password manager (1Password, Bitwarden, KeePass)
- ✓ Encrypted notes (offline)
- ✓ Secure cloud storage with encryption
═══════════════════════════════════════════════════════════════════════

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
- Real-time logs: journalctl -u xray -f
- Access logs: tail -f /var/log/xray/access.log
- Error logs: tail -f /var/log/xray/error.log
- Active connections: ss -tnp | grep :443
- Port check: ss -tlnp | grep :443

SECURITY MONITORING:
- Traffic monitor: /root/check_xray_traffic.sh
- Security audit: /root/xray_security_check.sh
- View blocked attempts: grep "blocked" /var/log/xray/access.log

OPERATION CHECK:
Open 2ip.ru or whatismyipaddress.com
Should display IP: $EXTERNAL_IP

TROUBLESHOOTING:
If X-Ray is not listening on port 443:
1. systemctl restart xray
2. journalctl -u xray -n 20
3. ss -tlnp | grep xray
4. /root/xray_security_check.sh

REGULAR MAINTENANCE:
1. Check logs weekly: /root/check_xray_traffic.sh
2. Run security audit: /root/xray_security_check.sh
3. Update X-Ray monthly:
   bash -c "\$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
   systemctl restart xray

BLOCKED SERVICES (by design):
- SMTP (ports 25, 465, 587) - email sending
- BitTorrent - torrent downloads
- Private IP ranges - internal network access
- Advertising domains - ad networks

Configuration saved to file: $CONFIG_FILE

🔒 This file contains sensitive data! Protect it with chmod 600.

================================================================================
EOF

    # Secure configuration file
    chmod 600 "$CONFIG_FILE"
    chown root:root "$CONFIG_FILE"
    
    print_status "Configurations saved to file: $CONFIG_FILE"
    print_security "Configuration file protected (chmod 600)"
    print_security "Only root can read this file"
}

# Final check
final_check() {
    print_header "FINAL CHECK"
    
    print_status "Checking service status..."
    systemctl status xray --no-pager -l
    
    print_status "Checking ports..."
    ss -tlnp | grep ":443"
    
    print_status "Checking firewall status..."
    ufw status numbered
    
    print_status "Checking logs..."
    journalctl -u xray -n 5 --no-pager
    
    print_status "Running security audit..."
    /root/xray_security_check.sh
}

# Main function
main() {
    print_header "X-RAY VLESS + REALITY VPN AUTO-INSTALLER v2.0 (SECURE)"
    print_status "Automated installation of X-Ray VLESS + REALITY VPN server"
    print_security "Version 2.0 includes enhanced security features"
    print_warning "Make sure you're running this script on a clean Ubuntu 24.04 server"
    print_status "Repository: https://github.com/rootcraft-tech/-X-Ray-VLESS-Reality-Installer"
    
    echo
    print_security "Security improvements in v2.0:"
    print_security "  ✓ SMTP ports blocked (prevents spam abuse)"
    print_security "  ✓ BitTorrent blocked (prevents torrent abuse)"
    print_security "  ✓ Private IPs blocked (prevents network scanning)"
    print_security "  ✓ Enhanced logging and monitoring"
    print_security "  ✓ Configuration file protection"
    print_security "  ✓ Security audit tools included"
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
    setup_log_rotation
    start_xray_service
    create_monitoring_script
    create_security_check_script
    create_client_configs
    final_check
    
    print_header "INSTALLATION COMPLETED SUCCESSFULLY!"
    print_status "X-Ray VLESS + REALITY VPN server is ready to use!"
    print_security "Security hardened configuration applied"
    print_status "Client configurations: /root/xray_client_configs.txt"
    echo
    print_status "VLESS URL for client import:"
    echo -e "${GREEN}$VLESS_URL${NC}"
    echo
    print_status "Management commands:"
    echo "  cat /root/xray_client_configs.txt  # View configurations"
    echo "  systemctl status xray              # Service status"
    echo "  journalctl -u xray -f              # Real-time logs"
    echo "  tail -f /var/log/xray/access.log   # Access logs"
    echo "  ss -tlnp | grep :443               # Port check"
    echo "  ufw status                         # Firewall status"
    echo
    print_status "Security monitoring:"
    echo "  /root/check_xray_traffic.sh        # Traffic monitor"
    echo "  /root/xray_security_check.sh       # Security audit"
    echo
    print_warning "⚠️ CRITICAL SECURITY REMINDERS:"
    print_warning "1. NEVER share UUID publicly (GitHub, forums, chats)"
    print_warning "2. Store credentials in password manager"
    print_warning "3. Run security audit weekly: /root/xray_security_check.sh"
    print_warning "4. Check logs regularly: /root/check_xray_traffic.sh"
    print_warning "5. Update X-Ray monthly for security patches"
    echo
    print_header "VPN SERVER IS READY TO USE! 🚀"
    print_security "Server is protected against spam, torrents, and abuse! 🔒"
}

# Signal handling
trap 'print_error "Installation interrupted by user"; exit 1' INT TERM

# Run main function
main "$@"
