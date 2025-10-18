# 🚀 X-Ray VLESS + REALITY VPN Installer

**Languages:** [English](README.md) | [Русский](README.ru.md)

Automated installation script for X-Ray VLESS + REALITY VPN server on Ubuntu 24.04 with advanced DPI bypass technology and comprehensive security features

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Ubuntu 24.04](https://img.shields.io/badge/Ubuntu-24.04%20LTS-orange.svg)](https://ubuntu.com/)
[![X-Ray Latest](https://img.shields.io/badge/X--Ray-Latest-blue.svg)](https://github.com/XTLS/Xray-core)
[![Security: Hardened](https://img.shields.io/badge/Security-Hardened-green.svg)]()

## 🚀 Quick Installation

⚡ **Recommended:** Tested and optimized for VPS servers [MyHosti.pro](https://myhosti.pro/services/vds)

⚡ **One-command installation on clean Ubuntu 24.04 server:**

```bash
curl -fsSL https://raw.githubusercontent.com/rootcraft-tech/-X-Ray-VLESS-Reality-Installer/main/install-xray.sh | sudo bash
```

## 🌟 What is VLESS + REALITY?

- **VLESS** - Modern protocol for bypassing internet censorship
- **REALITY** - Camouflages traffic as regular HTTPS connections  
- **Uses real website certificates** - Undetectable by DPI systems
- **High performance** - Optimized for speed and stability
- **Enterprise-grade security** - Built-in protection against abuse

## ✨ Features

### Core Functionality
- **🔒 DPI Bypass** - Advanced Deep Packet Inspection evasion
- **⚡ One-Click Install** - Complete automation, no manual configuration
- **🛡️ Security First** - Military-grade encryption with REALITY protocol
- **🌍 Universal Compatibility** - Works on all devices and platforms
- **🔧 Easy Management** - systemd service with automatic startup
- **📱 Ready-to-use Configs** - Automatic client configuration generation

### Security & Protection
- **🚫 Spam Prevention** - SMTP ports (25, 465, 587) blocked by default
- **🛡️ Network Scanning Protection** - Private IP ranges blocked
- **⚡ BitTorrent Blocking** - P2P protocols automatically filtered
- **📊 Comprehensive Logging** - Access and error logs with rotation
- **🔍 Security Monitoring** - Built-in traffic analysis tools
- **🔐 Protected Configuration** - Secure file permissions and ownership

## 📋 System Requirements

- **Operating System:** Ubuntu 24.04 LTS
- **RAM:** Minimum 512 MB, recommended 1+ GB
- **CPU:** Any modern processor
- **Disk Space:** Minimum 1 GB free space
- **Network:** Clean IP address (not blocked by ISPs)
- **Privileges:** Root access or sudo privileges

## 🛠️ What Gets Installed

- **X-Ray Core** - Latest stable version from official repository
- **VLESS Protocol** - Modern VPN protocol with enhanced security
- **REALITY Transport** - Traffic camouflage technology
- **Automatic Keys Generation** - UUID, Private/Public keys, Short ID
- **Firewall Configuration** - UFW rules for secure operation
- **systemd Service** - Automatic startup and process management
- **Log Rotation** - Automatic log management (7-day retention)
- **Security Monitoring Scripts** - Traffic analysis and security check tools

## 📱 Supported Clients

### iOS
- **Streisand** - Available on App Store
- Easy VLESS URL import

### macOS  
- **V2rayU** - Free, open-source client
- **FoXray** - Premium client with advanced features

### Android
- **v2rayNG** - Most popular Android client
- QR code and URL import support

### Windows
- **v2rayN** - Feature-rich Windows client
- **Qv2ray** - Cross-platform GUI client

## 🚀 Installation Process

The script automatically performs these steps:

1. **System Update** - Updates Ubuntu packages (non-interactive mode)
2. **Firewall Setup** - Configures UFW security rules  
3. **X-Ray Installation** - Downloads and installs latest X-Ray
4. **Key Generation** - Creates unique UUID and REALITY keys
5. **Configuration** - Sets up server with security hardening
6. **Log Setup** - Configures access/error logging with rotation
7. **Monitoring Tools** - Installs security check and traffic monitor scripts
8. **Service Start** - Enables and starts X-Ray service
9. **Client Configs** - Generates ready-to-use client configurations

## 🔧 Post-Installation Management

### View Configuration
```bash
# View client configurations (secure - root only)
cat /root/xray_client_configs.txt

# View server configuration
cat /usr/local/etc/xray/config.json
```

### Service Management
```bash
# Check service status
systemctl status xray

# Restart service
systemctl restart xray

# Stop service
systemctl stop xray

# View real-time service logs
journalctl -u xray -f
```

### Log Monitoring
```bash
# View access logs (client connections)
tail -f /var/log/xray/access.log

# View error logs
tail -f /var/log/xray/error.log

# Check last 50 log entries
tail -50 /var/log/xray/access.log
```

### Security Monitoring
```bash
# Run comprehensive security check
/usr/local/bin/xray_security_check.sh

# Monitor traffic statistics
/usr/local/bin/check_xray_traffic.sh

# Check active connections
ss -tnp | grep :443

# Verify port status
ss -tlnp | grep :443
```

### Firewall Management
```bash
# Check firewall status
ufw status numbered

# View detailed firewall rules
ufw status verbose
```

## 🛡️ Security Features

### Protocol Security
- **REALITY Protocol** - Undetectable traffic camouflage
- **Certificate Hijacking** - Uses real Microsoft.com certificates
- **XTLS Encryption** - Enhanced transport layer security  
- **Port 443** - Standard HTTPS port for maximum compatibility

### Traffic Filtering
- **SMTP Blocking** - Ports 25, 465, 587 blocked (prevents spam relay)
- **BitTorrent Blocking** - P2P protocols filtered automatically
- **Private IP Protection** - Internal network scanning prevented
- **Ad Domain Blocking** - Advertising networks filtered

### System Security
- **Firewall Integration** - Automatic UFW configuration (ports 22, 443 only)
- **Secure File Permissions** - Configuration files protected (chmod 640)
- **Log Rotation** - Automatic log management (7-day retention)
- **Access Logging** - Comprehensive connection tracking
- **Error Logging** - Detailed error reporting for troubleshooting

### Monitoring & Alerts
- **Traffic Monitor** - Built-in script for connection analysis
- **Security Checker** - Automated security validation tool
- **SMTP Attempt Tracking** - Monitors blocked spam attempts
- **Connection Statistics** - Real-time client connection tracking

## 🌐 Network Compatibility

**✅ Tested and Working:**
- Residential ISPs in restricted regions
- Mobile networks (4G/5G)
- Corporate networks with DPI
- Public WiFi with restrictions

**⚠️ Provider Recommendations:**
- Use small European VPS providers
- Avoid major providers (Vultr, Hetzner, OVH) - often blocked
- Clean IP addresses work best
- Test connection before committing

## 🚨 Troubleshooting

### Service Issues
```bash
# Restart X-Ray service
sudo systemctl restart xray

# Check detailed logs  
sudo journalctl -u xray -n 50

# Verify port binding
sudo ss -tlnp | grep :443

# Check X-Ray process
ps aux | grep xray
```

### Connection Problems
```bash
# Check server IP
curl -4 ifconfig.me

# Test port accessibility from client
telnet YOUR_SERVER_IP 443

# Verify firewall rules
sudo ufw status verbose

# Check for port conflicts
sudo netstat -tlnp | grep :443
```

### Configuration Verification
```bash
# Test X-Ray configuration
/usr/local/bin/xray -test -config /usr/local/etc/xray/config.json

# View current configuration
cat /usr/local/etc/xray/config.json

# Check client configs
cat /root/xray_client_configs.txt
```

### Security Checks
```bash
# Run security audit
/usr/local/bin/xray_security_check.sh

# Check for SMTP attempts (should be 0)
grep -E ":(25|465|587)" /var/log/xray/access.log | wc -l

# View blocked connections
grep "blocked" /var/log/xray/access.log

# Check configuration file permissions
ls -l /usr/local/etc/xray/config.json
```

### Log Analysis
```bash
# View recent access logs
tail -100 /var/log/xray/access.log

# Search for errors
grep -i error /var/log/xray/error.log

# Monitor real-time activity
tail -f /var/log/xray/access.log

# Check traffic statistics
/usr/local/bin/check_xray_traffic.sh
```

## 📊 Monitoring Best Practices

### Daily Checks
```bash
# Quick security check
/usr/local/bin/xray_security_check.sh

# Verify service is running
systemctl status xray
```

### Weekly Checks
```bash
# Review access logs for anomalies
tail -500 /var/log/xray/access.log

# Check traffic patterns
/usr/local/bin/check_xray_traffic.sh

# Verify no SMTP attempts
grep -E ":(25|465|587)" /var/log/xray/access.log
```

### Monthly Maintenance
```bash
# Update X-Ray to latest version
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
systemctl restart xray

# Backup configuration
cp /usr/local/etc/xray/config.json /root/xray_backup_$(date +%Y%m%d).json

# Review firewall rules
ufw status numbered
```

## 🔐 Security Best Practices

### Configuration Protection
- ⚠️ **NEVER share your UUID publicly** - It's the password to your VPN
- ⚠️ **NEVER commit `/root/xray_client_configs.txt` to public repos**
- ✅ Store configurations in secure password manager
- ✅ Keep backups in encrypted storage

### Server Hardening
- ✅ Use strong SSH keys, disable password authentication
- ✅ Enable automatic security updates: `dpkg-reconfigure -plow unattended-upgrades`
- ✅ Change SSH port from default 22 (update UFW rules accordingly)
- ✅ Install fail2ban for SSH protection: `apt install fail2ban`

### Monitoring
- ✅ Run security checks weekly: `/usr/local/bin/xray_security_check.sh`
- ✅ Monitor logs for suspicious activity
- ✅ Check SMTP attempt counter (should always be 0)
- ✅ Review destination IP patterns regularly

### Updates
- ✅ Keep X-Ray updated to latest version
- ✅ Update system packages regularly: `apt update && apt upgrade`
- ✅ Subscribe to X-Ray security announcements
- ✅ Test updates on non-production server first

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⭐ Support

If this project helped you bypass internet censorship, please give it a ⭐ on GitHub!

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check [issues page](https://github.com/rootcraft-tech/-X-Ray-VLESS-Reality-Installer/issues).

## 🔗 Useful Links

- [X-Ray Official Documentation](https://xtls.github.io/)
- [VLESS Protocol Specification](https://github.com/XTLS/Xray-core)
- [Ubuntu 24.04 LTS](https://ubuntu.com/download/server)
- [REALITY Protocol Details](https://github.com/XTLS/REALITY)
- [Security Best Practices](https://xtls.github.io/en/config/)

## 📈 Changelog

### Version 2.0 - Enhanced Security
- Enhanced security with traffic filtering rules
- SMTP port blocking (prevents spam relay abuse)
- Private IP range blocking (prevents network scanning)
- Comprehensive logging system (access + error logs)
- Log rotation with 7-day retention
- Security monitoring scripts included
- Protected configuration files (secure permissions)
- Non-interactive installation mode

### Version 1.3 - Stable Release
- Initial public release
- One-command installation
- Automatic configuration generation
- Basic firewall setup
- BitTorrent blocking

---

**⚠️ Legal Notice:** This software is intended for educational purposes and legitimate privacy protection. Users are responsible for compliance with local laws and regulations. The developers assume no liability for misuse of this software.

**🔒 Privacy Notice:** This script does not collect any user data, telemetry, or analytics. All configuration and logs remain local to your server.
