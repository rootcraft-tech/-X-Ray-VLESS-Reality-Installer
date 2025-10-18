#!/bin/bash

# X-Ray VLESS + REALITY VPN Automated Installation Script (SECURE VERSION)
# Based on the guide: "Creating VPN Server with X-Ray VLESS + REALITY"
# Compatible with Ubuntu 24.04 LTS
# Version: 2.0 (Security Hardened)
# Author: ViT
# Repository: https://github.com/rootcraft-tech/-X-Ray-VLESS-Reality-Installer
#
# SECURITY IMPROVEMENTS v2.0:
# ✓ Blocks SMTP ports (25, 465, 587) - prevents spam relay
# ✓ Blocks BitTorrent protocol - prevents torrent abuse
# ✓ Blocks private IP ranges - prevents internal network scanning
# ✓ Blocks advertising domains - prevents ad network abuse
# ✓ Comprehensive logging with rotation (access.log + error.log)
# ✓ Security monitoring scripts included
# ✓ Protected configuration files (chmod 640, chown root:nogroup)
# ✓ Non-interactive installation mode
#
# IMPORTANT: This script allows connections from ANY IP address.
# Security is enforced through routing rules, not IP whitelisting.

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
    
    print_status "Firewall configured successfully"
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

# Create X-Ray configuration with SECURITY HARDENING
create_xray_config() {
    print_header "X-RAY CONFIGURATION CREATION"
    
    print_status "Creating log directory..."
    mkdir -p /var/log/xray
    chmod 755 /var/log/xray
    chown nobody:nogroup /var/log/xray
    
    print_status "Creating secure configuration file..."
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
    
    # Secure configuration file - 640 allows nobody (xray service) to read
    print_status "Securing configuration file..."
    chmod 640 /usr/local/etc/xray/config.json
    chown root:nogroup /usr/local/etc/xray/config.json
    
    print_status "Configuration file secured (chmod 640, owner: root:nogroup)"
}

# Setup log rotation
setup_log_rotation() {
    print_header "LOG ROTATION SETUP"
    
    print_status "Configuring log rotation..."
    cat > /etc/logrotate.d/xray << 'EOF'
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
    
    print_status "Log rotation configured (7 days retention)"
}

# Create monitoring scripts
create_monitoring_scripts() {
    print_header "CREATING MONITORING SCRIPTS"
    
    # Traffic monitoring script
    print_status "Creating traffic monitoring script..."
    cat > /usr/local/bin/check_xray_traffic.sh << 'EOF'
#!/bin/bash
# X-Ray Traffic Monitor

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

# Check errors in last hour
echo ""
echo "=== Errors in last hour ==="
if [ -f /var/log/xray/error.log ]; then
    grep "$(date -d '1 hour ago' '+%Y/%m/%d %H' 2>/dev/null || date '+%Y/%m/%d %H')" /var/log/xray/error.log 2>/dev/null | tail -10 || echo "No recent errors"
else
    echo "No error log found"
fi

# Check SMTP connection attempts (should be 0)
echo ""
echo "=== SMTP connection attempts (should be 0) ==="
if [ -f /var/log/xray/access.log ]; then
    SMTP_COUNT=$(grep -E ":(25|465|587)" /var/log/xray/access.log 2>/dev/null | wc -l)
    echo "$SMTP_COUNT attempts"
else
    echo "No access log found"
fi

# Top 10 destination IPs
echo ""
echo "=== Top 10 destination IPs ==="
if [ -f /var/log/xray/access.log ]; then
    grep "accepted" /var/log/xray/access.log 2>/dev/null | awk '{print $NF}' | sort | uniq -c | sort -rn | head -10 || echo "No data available"
else
    echo "No access log found"
fi

echo ""
echo "===== Monitor complete ====="
EOF
    chmod +x /usr/local/bin/check_xray_traffic.sh
    print_status "Traffic monitoring script created: /usr/local/bin/check_xray_traffic.sh"
    
    # Security check script
    print_status "Creating security check script..."
    cat > /usr/local/bin/xray_security_check.sh << 'EOF'
#!/bin/bash
# X-Ray Security Check Script

echo "===== X-Ray Security Check ====="
echo "Date: $(date)"
echo ""

# Check if service is running
echo "=== Service Status ==="
if systemctl is-active --quiet xray; then
    echo "✓ X-Ray service is running"
else
    echo "✗ X-Ray service is NOT running"
fi

# Check configuration file permissions
echo ""
echo "=== Configuration Security ==="
ls -l /usr/local/etc/xray/config.json
PERMS=$(stat -c "%a" /usr/local/etc/xray/config.json 2>/dev/null)
if [ "$PERMS" = "640" ]; then
    echo "✓ Configuration file permissions correct (640)"
else
    echo "✗ WARNING: Configuration file permissions incorrect (should be 640, is $PERMS)"
fi

# Check for suspicious activity
echo ""
echo "=== Checking for suspicious activity ==="

if [ -f /var/log/xray/access.log ]; then
    # Check for SMTP attempts
    SMTP_ATTEMPTS=$(grep -E ":(25|465|587)" /var/log/xray/access.log 2>/dev/null | wc -l)
    echo "SMTP connection attempts (blocked): $SMTP_ATTEMPTS"
    
    # Check for private IP access attempts
    PRIVATE_IP_ATTEMPTS=$(grep -E "10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\." /var/log/xray/access.log 2>/dev/null | wc -l)
    echo "Private IP access attempts (blocked): $PRIVATE_IP_ATTEMPTS"
    
    # Check for high connection rate from single IP
    echo ""
    echo "Top 10 connecting source IPs:"
    awk '{print $3}' /var/log/xray/access.log 2>/dev/null | sort | uniq -c | sort -rn | head -10 || echo "No data available"
else
    echo "Access log not found: /var/log/xray/access.log"
fi

if [ -f /var/log/xray/error.log ]; then
    ERRORS=$(wc -l < /var/log/xray/error.log 2>/dev/null || echo 0)
    echo ""
    echo "Total errors logged: $ERRORS"
    if [ "$ERRORS" -gt 0 ]; then
        echo "Recent errors:"
        tail -5 /var/log/xray/error.log
    fi
else
    echo "Error log not found: /var/log/xray/error.log"
fi

# Firewall status
echo ""
echo "=== Firewall Status ==="
ufw status numbered | head -15

echo ""
echo "===== Security Check Complete ====="
EOF
    chmod +x /usr/local/bin/xray_security_check.sh
    print_status "Security check script created: /usr/local/bin/xray_security_check.sh"
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
              X-RAY VLESS + REALITY VPN CONFIGURATION (v2.0 SECURE)
================================================================================

Server successfully configured and running with ENHANCED SECURITY!

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

================================================================================
                           SECURITY FEATURES ENABLED
================================================================================

✓ SMTP ports blocked (25, 465, 587) - prevents spam relay
✓ BitTorrent protocol blocked - prevents torrent abuse
✓ Private IP ranges blocked - prevents internal network scanning
✓ Advertising domains blocked - prevents ad network abuse
✓ Comprehensive logging enabled (access.log + error.log)
✓ Log rotation configured (7 days retention)
✓ Configuration file secured (chmod 640)
✓ Monitoring scripts installed

================================================================================
                              CLIENT SETUP
================================================================================

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

================================================================================
                           MANAGEMENT COMMANDS
================================================================================

Service Management:
  systemctl status xray              # Service status
  systemctl restart xray             # Restart service
  systemctl stop xray                # Stop service
  journalctl -u xray -f              # Real-time logs

Log Monitoring:
  tail -f /var/log/xray/access.log   # Monitor access logs
  tail -f /var/log/xray/error.log    # Monitor error logs

Security Monitoring:
  /usr/local/bin/xray_security_check.sh    # Run security check
  /usr/local/bin/check_xray_traffic.sh     # Check traffic stats

Network Diagnostics:
  ss -tlnp | grep :443               # Check port 443
  ss -tnp | grep :443                # Active connections
  ufw status                         # Firewall status

================================================================================
                              OPERATION CHECK
================================================================================

After connecting to VPN:
1. Open 2ip.ru or whatismyipaddress.com
2. Should display IP: $EXTERNAL_IP
3. Check DNS leak: https://dnsleaktest.com/

================================================================================
                            TROUBLESHOOTING
================================================================================

If X-Ray is not listening on port 443:
1. systemctl restart xray
2. journalctl -u xray -n 20
3. ss -tlnp | grep xray

If connection fails:
1. Check firewall: ufw status
2. Verify port is open: ss -tlnp | grep :443
3. Check logs: tail -50 /var/log/xray/error.log

If experiencing high latency:
1. Check traffic: /usr/local/bin/check_xray_traffic.sh
2. Monitor connections: ss -tnp | grep :443
3. Check system load: top

================================================================================
                          SECURITY RECOMMENDATIONS
================================================================================

⚠️  CRITICAL SECURITY WARNINGS:

1. NEVER share your UUID publicly!
   - UUID is the password to your VPN server
   - Anyone with UUID can use your server

2. NEVER commit this file to public repositories!
   - Contains all your secret keys
   - Store in secure location (password manager)

3. Regularly monitor logs for suspicious activity:
   - Run: /usr/local/bin/xray_security_check.sh
   - Check for SMTP attempts (should be 0)
   - Review destination IPs

4. Keep X-Ray updated:
   - Check for updates: xray version
   - Update: bash -c "\$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
   - Restart: systemctl restart xray

5. Backup this configuration:
   - Store securely offline
   - Never email or share via insecure channels

Configuration saved to file: $CONFIG_FILE
File permissions: 600 (root only)

================================================================================
EOF

    # Secure the configuration file
    chmod 600 "$CONFIG_FILE"
    chown root:root "$CONFIG_FILE"
    
    print_status "Configuration file created and secured: $CONFIG_FILE"
    print_warning "File permissions set to 600 (root only access)"
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
    
    print_status "Checking configuration file permissions..."
    ls -l /usr/local/etc/xray/config.json
    ls -l /root/xray_client_configs.txt
}

# Main function
main() {
    print_header "X-RAY VLESS + REALITY VPN AUTO-INSTALLER v2.0 (SECURE)"
    print_status "Automated installation of SECURE X-Ray VLESS + REALITY VPN server"
    print_warning "Make sure you're running this script on a clean Ubuntu 24.04 server"
    print_status "Repository: https://github.com/rootcraft-tech/-X-Ray-VLESS-Reality-Installer"
    
    echo
    print_status "SECURITY FEATURES:"
    echo "  ✓ Blocks SMTP ports (prevents spam relay)"
    echo "  ✓ Blocks BitTorrent (prevents torrent abuse)"
    echo "  ✓ Blocks private IPs (prevents network scanning)"
    echo "  ✓ Comprehensive logging with rotation"
    echo "  ✓ Security monitoring scripts"
    echo "  ✓ Protected configuration files"
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
    create_monitoring_scripts
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
    echo "  cat /root/xray_client_configs.txt             # View configurations"
    echo "  systemctl status xray                         # Service status"
    echo "  tail -f /var/log/xray/access.log             # Monitor access logs"
    echo "  /usr/local/bin/xray_security_check.sh        # Run security check"
    echo "  /usr/local/bin/check_xray_traffic.sh         # Check traffic stats"
    
    echo
    print_warning "SECURITY REMINDERS:"
    echo "  ⚠️  NEVER share your UUID publicly!"
    echo "  ⚠️  NEVER commit /root/xray_client_configs.txt to public repos!"
    echo "  ⚠️  Regularly run: /usr/local/bin/xray_security_check.sh"
    echo "  ⚠️  Keep X-Ray updated for latest security patches"
    
    print_header "VPN SERVER IS READY TO USE! 🚀"
}

# Signal handling
trap 'print_error "Installation interrupted by user"; exit 1' INT TERM

# Run main function
main "$@"
