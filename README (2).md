# 🚀 X-Ray VLESS + REALITY VPN Installer

**Languages:** [English](README.md) | [Русский](README.ru.md)

Automated installation script for X-Ray VLESS + REALITY VPN server on Ubuntu 24.04 with advanced DPI bypass technology

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Ubuntu 24.04](https://img.shields.io/badge/Ubuntu-24.04%20LTS-orange.svg)](https://ubuntu.com/)
[![X-Ray Latest](https://img.shields.io/badge/X--Ray-Latest-blue.svg)](https://github.com/XTLS/Xray-core)

## 🚀 Quick Installation

⚡ **One-command installation on clean Ubuntu 24.04 server:**

```bash
curl -fsSL https://raw.githubusercontent.com/your-username/xray-vless-reality-installer/main/install-xray.sh | sudo bash
```

## 🌟 What is VLESS + REALITY?

- **VLESS** - Modern protocol for bypassing internet censorship
- **REALITY** - Camouflages traffic as regular HTTPS connections  
- **Uses real website certificates** - Undetectable by DPI systems
- **High performance** - Optimized for speed and stability

## ✨ Features

- **🔒 DPI Bypass** - Advanced Deep Packet Inspection evasion
- **⚡ One-Click Install** - Complete automation, no manual configuration
- **🛡️ Security First** - Military-grade encryption with REALITY protocol
- **🌍 Universal Compatibility** - Works on all devices and platforms
- **🔧 Easy Management** - systemd service with automatic startup
- **📱 Ready-to-use Configs** - Automatic client configuration generation

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

1. **System Update** - Updates Ubuntu packages
2. **Firewall Setup** - Configures UFW security rules  
3. **X-Ray Installation** - Downloads and installs latest X-Ray
4. **Key Generation** - Creates unique UUID and REALITY keys
5. **Configuration** - Sets up server configuration
6. **Service Start** - Enables and starts X-Ray service
7. **Client Configs** - Generates ready-to-use client configurations

## 🔧 Post-Installation

After successful installation, you'll get:

```bash
# View client configurations
cat /root/xray_client_configs.txt

# Manage X-Ray service
systemctl status xray          # Check status
systemctl restart xray         # Restart service
systemctl stop xray            # Stop service

# Monitor logs
journalctl -u xray -f           # Real-time logs
ss -tlnp | grep :443           # Check port status
```

## 🛡️ Security Features

- **REALITY Protocol** - Undetectable traffic camouflage
- **Certificate Hijacking** - Uses real Microsoft.com certificates
- **XTLS Encryption** - Enhanced transport layer security  
- **Port 443** - Standard HTTPS port for maximum compatibility
- **Firewall Integration** - Automatic UFW configuration
- **BitTorrent Blocking** - Prevents P2P traffic

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

## 🚨 Troubleshooting

### Service Issues
```bash
# Restart X-Ray service
sudo systemctl restart xray

# Check detailed logs  
sudo journalctl -u xray -n 50

# Verify port binding
sudo ss -tlnp | grep :443
```

### Connection Problems
```bash
# Check server IP
curl -4 ifconfig.me

# Test port accessibility
telnet YOUR_SERVER_IP 443

# Verify firewall rules
sudo ufw status verbose
```

### Key Verification
```bash
# View server configuration
cat /usr/local/etc/xray/config.json

# Check client configs
cat /root/xray_client_configs.txt
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⭐ Support

If this project helped you bypass internet censorship, please give it a ⭐ on GitHub!

## 🔗 Useful Links

- [X-Ray Official Documentation](https://xtls.github.io/)
- [VLESS Protocol Specification](https://github.com/XTLS/Xray-core)
- [Ubuntu 24.04 LTS](https://ubuntu.com/download/server)
- [REALITY Protocol Details](https://github.com/XTLS/REALITY)

---

**⚠️ Legal Notice:** This software is intended for educational purposes and legitimate privacy protection. Users are responsible for compliance with local laws and regulations.