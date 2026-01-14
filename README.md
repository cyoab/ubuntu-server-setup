# Ubuntu Server Setup

Automated setup script for Ubuntu Server with security hardening and common utilities.

## Quick Install

```bash
curl -LsSf https://raw.githubusercontent.com/cyoab/ubuntu-server-setup/main/vm-setup.sh | sudo bash
```

Or skip AIDE initialization (faster):

```bash
curl -LsSf https://raw.githubusercontent.com/cyoab/ubuntu-server-setup/main/vm-setup.sh | sudo SKIP_AIDE=true bash
```

## What's Included

### System Updates
- Full system update, upgrade, and dist-upgrade
- Automatic cleanup with autoremove and autoclean

### Essential Packages
- **Build tools**: build-essential, git
- **Network**: curl, wget, net-tools, nmap, mtr, traceroute, dnsutils
- **Monitoring**: htop, btop, iotop, ncdu, sysstat
- **Utilities**: tmux, screen, jq, yq, vim, nano
- **Archives**: zip, unzip, tar, p7zip-full

### Python with uv
- Python 3 + pip + venv
- [uv](https://github.com/astral-sh/uv) package manager

### Security Hardening

| Component | Description |
|-----------|-------------|
| **UFW Firewall** | Default deny incoming, allow outgoing, SSH allowed |
| **Fail2Ban** | 3 SSH failures = 1 hour ban |
| **AppArmor** | Mandatory access control enabled |
| **SSH Hardening** | Disabled root login, strong ciphers, rate limiting |
| **Kernel Hardening** | Sysctl params for network and memory protection |
| **Auto Updates** | Unattended security updates |
| **Chrony** | NTP time synchronization |
| **Auditd** | System auditing for passwd, sudoers, SSH changes |
| **AIDE** | File integrity checking |
| **rkhunter/chkrootkit** | Rootkit detection tools |

### Convenience Features
- Bash aliases for common commands
- `sysinfo` command for quick system overview
- Docker installation (commented out, easy to enable)

## Manual Installation

```bash
git clone https://github.com/cyoab/ubuntu-server-setup.git
cd ubuntu-server-setup
sudo ./vm-setup.sh
```

## Post-Installation

1. **SSH keys**: After setting up SSH keys, disable password auth:
   ```bash
   sudo sed -i 's/# PasswordAuthentication no/PasswordAuthentication no/' /etc/ssh/sshd_config.d/hardening.conf
   sudo systemctl restart sshd
   ```

2. **Open additional ports**:
   ```bash
   sudo ufw allow 80/tcp   # HTTP
   sudo ufw allow 443/tcp  # HTTPS
   ```

3. **Enable Docker** (edit script and uncomment `install_docker` call, or run manually)

4. **Reboot** to apply all changes:
   ```bash
   sudo reboot
   ```

## Tested On
- Ubuntu 22.04 LTS
- Ubuntu 24.04 LTS

## License
MIT
