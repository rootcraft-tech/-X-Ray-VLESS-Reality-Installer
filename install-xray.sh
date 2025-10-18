#!/bin/bash

# ============================================================
# X-Ray VLESS+REALITY Automated Installer (SECURE VERSION)
# ============================================================
# Version: 2.0.2
# Last Update: 2025-10-18
# 
# FIX v2.0.2: Corrected group name from 'nobody' to 'nogroup' for Ubuntu compatibility
# FIX v2.0.1: Fixed configuration file permissions (chmod 640, chown root:nogroup)
# FIX v2.0.0: Added comprehensive security hardening against proxy abuse
#
# SECURITY FEATURES:
# ✓ Blocks SMTP ports (25, 465, 587) - prevents spam relay
# ✓ Blocks BitTorrent protocol - prevents torrent abuse
# ✓ Blocks private IP ranges - prevents internal network scanning
# ✓ Blocks advertising domains - prevents ad network abuse
# ✓ Comprehensive logging with rotation
# ✓ Security monitoring scripts included
# 
# IMPORTANT: This script allows connections from ANY IP address.
# Security is enforced through routing rules, not IP whitelisting.
# ============================================================

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root"
   exit 1
fi

# Detect system architecture
ARCH=$(uname -m)
case $ARCH in
    x86_64)
        ARCH="64"
        ;;
    aarch64|arm64)
        ARCH="arm64-v8a"
        ;;
    armv7l)
        ARCH="arm32-v7a"
        ;;
    *)
        print_error "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

print_status "Detected architecture: $ARCH"

# Update system
print_status "Updating system packages..."
apt-get update -qq
apt-get upgrade -y -qq
apt-get install -y -qq curl wget unzip jq ufw

# Configure firewall
print_status "Configuring firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH'
ufw allow 443/tcp comment 'HTTPS (X-Ray)'
ufw --force enable

print_success "Firewall configured"

# Get latest X-Ray version
print_status "Fetching latest X-Ray version..."
XRAY_VERSION=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r .tag_name)
if [ -z "$XRAY_VERSION" ]; then
    print_error "Failed to fetch X-Ray version"
    exit 1
fi
print_status "Latest X-Ray version: $XRAY_VERSION"

# Download and install X-Ray
print_status "Downloading X-Ray..."
DOWNLOAD_URL="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-${ARCH}.zip"
wget -q --show-progress "$DOWNLOAD_URL" -O /tmp/xray.zip

print_status "Installing X-Ray..."
unzip -q -o /tmp/xray.zip -d /tmp/xray
install -m 755 /tmp/xray/xray /usr/local/bin/xray
rm -rf /tmp/xray /tmp/xray.zip

print_success "X-Ray installed successfully"

# Generate UUID and keys
print_status "Generating UUID and keys..."
UUID=$(cat /proc/sys/kernel/random/uuid)
KEYS=$(/usr/local/bin/xray x25519)
PRIVATE_KEY=$(echo "$KEYS" | grep "Private key:" | awk '{print $3}')
PUBLIC_KEY=$(echo "$KEYS" | grep "Public key:" | awk '{print $3}')

print_status "UUID: $UUID"
print_status "Private Key: $PRIVATE_KEY"
print_status "Public Key: $PUBLIC_KEY"

# Detect server public IP
print_status "Detecting server public IP..."
SERVER_IP=$(curl -s https://api.ipify.org)
if [ -z "$SERVER_IP" ]; then
    SERVER_IP=$(curl -s https://ifconfig.me)
fi
print_status "Server IP: $SERVER_IP"

# Get SNI domain
print_status "Enter SNI domain for REALITY (e.g., www.microsoft.com):"
read -r SNI
if [ -z "$SNI" ]; then
    SNI="www.microsoft.com"
    print_warning "Using default SNI: $SNI"
fi

# Get short IDs
print_status "Enter short IDs (comma-separated, leave empty for random):"
read -r SHORT_IDS_INPUT
if [ -z "$SHORT_IDS_INPUT" ]; then
    SHORT_ID1=$(openssl rand -hex 8)
    SHORT_ID2=$(openssl rand -hex 8)
    SHORT_IDS="\"$SHORT_ID1\", \"$SHORT_ID2\""
    print_warning "Generated random short IDs: $SHORT_ID1, $SHORT_ID2"
else
    IFS=',' read -ra IDS <<< "$SHORT_IDS_INPUT"
    SHORT_IDS=""
    for id in "${IDS[@]}"; do
        id=$(echo "$id" | xargs) # Trim whitespace
        SHORT_IDS+="\"$id\", "
    done
    SHORT_IDS=${SHORT_IDS%, } # Remove trailing comma
fi

# Create X-Ray configuration directory
print_status "Creating X-Ray configuration..."
mkdir -p /usr/local/etc/xray
mkdir -p /var/log/xray
chmod 755 /var/log/xray
chown nobody:nogroup /var/log/xray

# Create X-Ray configuration with SECURITY HARDENING
cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
  },
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "outboundTag": "block",
        "protocol": ["bittorrent"],
        "comment": "Block BitTorrent protocol to prevent torrent abuse"
      },
      {
        "type": "field",
        "outboundTag": "block",
        "port": "25,465,587",
        "comment": "Block SMTP ports to prevent spam relay"
      },
      {
        "type": "field",
        "outboundTag": "block",
        "ip": ["geoip:private"],
        "comment": "Block private IP ranges to prevent internal network scanning"
      },
      {
        "type": "field",
        "outboundTag": "block",
        "domain": ["geosite:category-ads-all"],
        "comment": "Block advertising domains"
      },
      {
        "type": "field",
        "outboundTag": "direct",
        "network": "tcp,udp"
      }
    ]
  },
  "inbounds": [
    {
      "listen": "0.0.0.0",
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
          "dest": "$SNI:443",
          "xver": 0,
          "serverNames": [
            "$SNI"
          ],
          "privateKey": "$PRIVATE_KEY",
          "shortIds": [
            $SHORT_IDS
          ]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "tag": "block",
      "settings": {}
    }
  ]
}
EOF

print_success "Configuration file created"

# Validate configuration
print_status "Validating configuration..."
if /usr/local/bin/xray -test -config /usr/local/etc/xray/config.json; then
    print_success "Configuration is valid"
else
    print_error "Configuration validation failed"
    exit 1
fi

# Secure configuration file - 640 allows nobody (xray service) to read
print_status "Securing configuration file..."
chmod 640 /usr/local/etc/xray/config.json
chown root:nogroup /usr/local/etc/xray/config.json

# Create systemd service
print_status "Creating systemd service..."
cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=X-Ray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

# Setup log rotation
print_status "Configuring log rotation..."
cat > /etc/logrotate.d/xray <<EOF
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

# Create traffic monitoring script
print_status "Creating monitoring scripts..."
cat > /usr/local/bin/check_xray_traffic.sh <<'EOF'
#!/bin/bash
# X-Ray Traffic Monitor
LOG_FILE="/var/log/xray/access.log"
ALERT_THRESHOLD_MB=1000
TIME_WINDOW_MINUTES=60

if [ ! -f "$LOG_FILE" ]; then
    echo "Log file not found: $LOG_FILE"
    exit 1
fi

# Calculate traffic in last hour
SINCE=$(date -d "$TIME_WINDOW_MINUTES minutes ago" "+%Y/%m/%d %H:%M:%S")
TRAFFIC=$(awk -v since="$SINCE" '$1" "$2 > since' "$LOG_FILE" | wc -l)
TRAFFIC_MB=$((TRAFFIC / 1024))

echo "Traffic in last $TIME_WINDOW_MINUTES minutes: ${TRAFFIC_MB}MB"

if [ $TRAFFIC_MB -gt $ALERT_THRESHOLD_MB ]; then
    echo "WARNING: High traffic detected!"
    # Add notification logic here (email, webhook, etc.)
fi
EOF
chmod +x /usr/local/bin/check_xray_traffic.sh

# Create security check script
cat > /usr/local/bin/xray_security_check.sh <<'EOF'
#!/bin/bash
# X-Ray Security Check Script
LOG_FILE="/var/log/xray/access.log"
ERROR_LOG="/var/log/xray/error.log"

echo "=== X-Ray Security Check ==="
echo "Date: $(date)"
echo ""

# Check if service is running
if systemctl is-active --quiet xray; then
    echo "✓ X-Ray service is running"
else
    echo "✗ X-Ray service is NOT running"
fi

# Check for suspicious patterns
echo ""
echo "=== Checking for suspicious activity ==="

if [ -f "$LOG_FILE" ]; then
    # Check for SMTP attempts
    SMTP_ATTEMPTS=$(grep -E ":(25|465|587)" "$LOG_FILE" | wc -l)
    echo "SMTP connection attempts (blocked): $SMTP_ATTEMPTS"
    
    # Check for private IP access attempts
    PRIVATE_IP_ATTEMPTS=$(grep -E "10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\." "$LOG_FILE" | wc -l)
    echo "Private IP access attempts (blocked): $PRIVATE_IP_ATTEMPTS"
    
    # Check for high connection rate from single IP
    echo ""
    echo "Top 10 connecting IPs:"
    awk '{print $3}' "$LOG_FILE" | sort | uniq -c | sort -rn | head -10
else
    echo "Access log not found: $LOG_FILE"
fi

if [ -f "$ERROR_LOG" ]; then
    ERRORS=$(wc -l < "$ERROR_LOG")
    echo ""
    echo "Total errors logged: $ERRORS"
    if [ $ERRORS -gt 0 ]; then
        echo "Recent errors:"
        tail -5 "$ERROR_LOG"
    fi
fi

echo ""
echo "=== Configuration Security ==="
ls -l /usr/local/etc/xray/config.json
echo ""
echo "=== Firewall Status ==="
ufw status | head -10
EOF
chmod +x /usr/local/bin/xray_security_check.sh

# Enable and start service
print_status "Enabling and starting X-Ray service..."
systemctl daemon-reload
systemctl enable xray
systemctl start xray

# Check service status
sleep 2
if systemctl is-active --quiet xray; then
    print_success "X-Ray service is running"
else
    print_error "X-Ray service failed to start"
    systemctl status xray --no-pager
    exit 1
fi

# Display connection information
print_success "Installation completed successfully!"
echo ""
echo "================================================"
echo "           CONNECTION INFORMATION"
echo "================================================"
echo ""
echo "Server Address: $SERVER_IP"
echo "Port: 443"
echo "UUID: $UUID"
echo "Flow: xtls-rprx-vision"
echo "Network: tcp"
echo "Security: reality"
echo "SNI: $SNI"
echo "Fingerprint: chrome"
echo "Public Key: $PUBLIC_KEY"
echo "Short IDs: $SHORT_IDS_INPUT"
echo ""
echo "================================================"
echo "           SECURITY FEATURES ENABLED"
echo "================================================"
echo ""
echo "✓ SMTP ports blocked (25, 465, 587)"
echo "✓ BitTorrent protocol blocked"
echo "✓ Private IP ranges blocked"
echo "✓ Ad domains blocked"
echo "✓ Comprehensive logging enabled"
echo "✓ Log rotation configured (7 days)"
echo ""
echo "================================================"
echo "           MONITORING COMMANDS"
echo "================================================"
echo ""
echo "Check service status:"
echo "  systemctl status xray"
echo ""
echo "View real-time logs:"
echo "  tail -f /var/log/xray/access.log"
echo "  tail -f /var/log/xray/error.log"
echo ""
echo "Run security check:"
echo "  /usr/local/bin/xray_security_check.sh"
echo ""
echo "Check traffic:"
echo "  /usr/local/bin/check_xray_traffic.sh"
echo ""
echo "================================================"
echo "           CLIENT CONFIGURATION"
echo "================================================"
echo ""
echo "For v2rayN/v2rayNG/Nekoray:"
echo "Use the manual configuration with the values above"
echo ""
echo "For JSON configuration:"
cat > /root/xray_client_config.json <<CLIENTEOF
{
  "log": {
    "loglevel": "warning"
  },
  "routing": {
    "rules": [
      {
        "type": "field",
        "domain": ["geosite:category-ads-all"],
        "outboundTag": "block"
      }
    ]
  },
  "inbounds": [
    {
      "port": 1080,
      "listen": "127.0.0.1",
      "protocol": "socks",
      "settings": {
        "udp": true
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "$SERVER_IP",
            "port": 443,
            "users": [
              {
                "id": "$UUID",
                "encryption": "none",
                "flow": "xtls-rprx-vision"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "fingerprint": "chrome",
          "serverName": "$SNI",
          "publicKey": "$PUBLIC_KEY",
          "shortId": "$(echo $SHORT_IDS_INPUT | cut -d',' -f1 | xargs)",
          "spiderX": ""
        }
      }
    },
    {
      "protocol": "blackhole",
      "tag": "block"
    }
  ]
}
CLIENTEOF

echo "Client configuration saved to: /root/xray_client_config.json"
echo ""
echo "================================================"
echo "           IMPORTANT NOTES"
echo "================================================"
echo ""
echo "1. This VPN allows connections from ANY IP address"
echo "2. Security is enforced through routing rules"
echo "3. Monitor logs regularly for suspicious activity"
echo "4. Run security checks periodically"
echo "5. Keep X-Ray updated for latest security patches"
echo ""
echo "Installation log: /var/log/xray/"
echo "================================================"
