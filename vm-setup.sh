#!/bin/bash
#===============================================================================
# Ubuntu Server Setup Script
# Version: 1.0.0
# Description: Automated setup script for Ubuntu Server with security hardening
#              and common utilities installation
# Tested on: Ubuntu 22.04 LTS, Ubuntu 24.04 LTS
#===============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Get the actual user (even when running with sudo)
get_actual_user() {
    if [[ -n "${SUDO_USER:-}" ]]; then
        echo "$SUDO_USER"
    else
        echo "$USER"
    fi
}

ACTUAL_USER=$(get_actual_user)
ACTUAL_USER_HOME=$(eval echo "~$ACTUAL_USER")

#===============================================================================
# System Update and Upgrade
#===============================================================================
system_update() {
    log_info "Updating system packages..."
    
    # Configure apt for non-interactive mode
    export DEBIAN_FRONTEND=noninteractive
    
    # Update package lists
    apt-get update -y
    
    # Upgrade installed packages
    apt-get upgrade -y
    
    # Perform distribution upgrade
    apt-get dist-upgrade -y
    
    # Clean up
    apt-get autoremove -y
    apt-get autoclean -y
    
    log_success "System update completed"
}

#===============================================================================
# Install Essential Packages
#===============================================================================
install_essentials() {
    log_info "Installing essential packages..."
    
    local packages=(
        # Build essentials
        build-essential
        software-properties-common
        
        # Version control
        git
        
        # Network utilities
        curl
        wget
        net-tools
        dnsutils
        iputils-ping
        traceroute
        mtr-tiny
        nmap
        netcat-openbsd
        
        # System utilities
        htop
        btop
        iotop
        iftop
        ncdu
        tree
        jq
        yq
        
        # Text editors
        vim
        nano
        
        # Archive utilities
        zip
        unzip
        tar
        gzip
        bzip2
        xz-utils
        p7zip-full
        
        # Process management
        tmux
        screen
        
        # System monitoring
        sysstat
        lsof
        strace
        
        # Disk utilities
        parted
        fdisk
        
        # SSL/TLS
        openssl
        ca-certificates
        gnupg
        
        # Time synchronization
        chrony
        
        # Misc utilities
        rsync
        socat
        pv
        pigz
        rename
        bc
        whois
        
        # Security
        ufw
        fail2ban
        apparmor
        apparmor-utils
        rkhunter
        chkrootkit
        aide
        auditd
        
        # Log management
        logrotate
        
        # Automation
        cron
        at
    )
    
    apt-get install -y "${packages[@]}"
    
    log_success "Essential packages installed"
}

#===============================================================================
# Install Python with uv
#===============================================================================
install_python_uv() {
    log_info "Installing Python and uv package manager..."
    
    # Install Python
    apt-get install -y python3 python3-pip python3-venv python3-dev
    
    # Install uv for the actual user
    log_info "Installing uv package manager..."
    sudo -u "$ACTUAL_USER" bash -c 'curl -LsSf https://astral.sh/uv/install.sh | sh'
    
    # Add uv to PATH in user's shell config
    local shell_rc="$ACTUAL_USER_HOME/.bashrc"
    if [[ -f "$ACTUAL_USER_HOME/.zshrc" ]]; then
        shell_rc="$ACTUAL_USER_HOME/.zshrc"
    fi
    
    # Check if uv PATH is already added
    if ! grep -q 'cargo/bin' "$shell_rc" 2>/dev/null; then
        echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> "$shell_rc"
        chown "$ACTUAL_USER:$ACTUAL_USER" "$shell_rc"
    fi
    
    log_success "Python and uv installed"
}

#===============================================================================
# Install Docker (Optional)
#===============================================================================
install_docker() {
    log_info "Installing Docker..."
    
    # Remove old versions
    apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
    
    # Install dependencies
    apt-get install -y \
        apt-transport-https \
        ca-certificates \
        curl \
        gnupg \
        lsb-release
    
    # Add Docker's official GPG key
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    
    # Add the repository
    echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
        $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
        tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    # Install Docker
    apt-get update -y
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    
    # Add user to docker group
    usermod -aG docker "$ACTUAL_USER"
    
    # Enable and start Docker
    systemctl enable docker
    systemctl start docker
    
    log_success "Docker installed"
}

#===============================================================================
# Configure Firewall (UFW)
#===============================================================================
configure_firewall() {
    log_info "Configuring UFW firewall..."
    
    # Reset UFW to default
    ufw --force reset
    
    # Set default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH (important: do this before enabling!)
    ufw allow ssh
    
    # Allow common services (commented out - uncomment as needed)
    # ufw allow http
    # ufw allow https
    # ufw allow 8080/tcp
    
    # Enable UFW
    ufw --force enable
    
    # Show status
    ufw status verbose
    
    log_success "UFW firewall configured"
}

#===============================================================================
# Configure Fail2Ban
#===============================================================================
configure_fail2ban() {
    log_info "Configuring Fail2Ban..."
    
    # Create local configuration
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
# Ban duration (10 minutes)
bantime = 10m

# Time window for counting failures
findtime = 10m

# Number of failures before ban
maxretry = 5

# Ignore localhost
ignoreip = 127.0.0.1/8 ::1

# Use systemd backend
backend = systemd

# Action to perform
banaction = ufw

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 1h

[sshd-ddos]
enabled = true
port = ssh
filter = sshd-ddos
logpath = /var/log/auth.log
maxretry = 10
findtime = 10m
bantime = 1h
EOF

    # Restart Fail2Ban
    systemctl enable fail2ban
    systemctl restart fail2ban
    
    log_success "Fail2Ban configured"
}

#===============================================================================
# Configure AppArmor
#===============================================================================
configure_apparmor() {
    log_info "Configuring AppArmor..."
    
    # Enable and start AppArmor
    systemctl enable apparmor
    systemctl start apparmor
    
    # Enforce all profiles
    aa-enforce /etc/apparmor.d/* 2>/dev/null || true
    
    # Show status
    aa-status
    
    log_success "AppArmor configured"
}

#===============================================================================
# SSH Hardening
#===============================================================================
harden_ssh() {
    log_info "Hardening SSH configuration..."
    
    # Backup original config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    # Create hardened SSH config
    cat > /etc/ssh/sshd_config.d/hardening.conf << 'EOF'
# SSH Hardening Configuration

# Disable root login
PermitRootLogin no

# Disable password authentication (enable after setting up SSH keys)
# PasswordAuthentication no

# Use only SSH Protocol 2
Protocol 2

# Limit authentication attempts
MaxAuthTries 3

# Set login grace time
LoginGraceTime 30

# Disable empty passwords
PermitEmptyPasswords no

# Disable X11 forwarding
X11Forwarding no

# Disable TCP forwarding (enable if needed)
AllowTcpForwarding no

# Disable agent forwarding
AllowAgentForwarding no

# Set client alive interval
ClientAliveInterval 300
ClientAliveCountMax 2

# Use strong ciphers
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

# Use strong MACs
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256

# Use strong key exchange algorithms
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512

# Log level
LogLevel VERBOSE

# Disable unused authentication methods
ChallengeResponseAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no
EOF

    # Test SSH config
    if sshd -t; then
        systemctl restart sshd
        log_success "SSH hardening applied"
    else
        log_error "SSH configuration test failed. Reverting..."
        rm /etc/ssh/sshd_config.d/hardening.conf
        exit 1
    fi
}

#===============================================================================
# System Hardening
#===============================================================================
system_hardening() {
    log_info "Applying system hardening..."
    
    # Secure shared memory
    if ! grep -q '/run/shm' /etc/fstab; then
        echo 'tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0' >> /etc/fstab
    fi
    
    # Disable core dumps
    cat > /etc/security/limits.d/disable-core-dumps.conf << 'EOF'
* hard core 0
* soft core 0
EOF

    # Sysctl security settings
    cat > /etc/sysctl.d/99-security.conf << 'EOF'
# Network security settings

# Disable IP forwarding (enable if using as router)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Enable TCP SYN cookies
net.ipv4.tcp_syncookies = 1

# Enable reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Log martian packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP errors
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Disable IPv6 if not needed (uncomment to disable)
# net.ipv6.conf.all.disable_ipv6 = 1
# net.ipv6.conf.default.disable_ipv6 = 1

# Kernel hardening
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1

# File system hardening
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
EOF

    # Apply sysctl settings
    sysctl --system
    
    log_success "System hardening applied"
}

#===============================================================================
# Configure Automatic Security Updates
#===============================================================================
configure_auto_updates() {
    log_info "Configuring automatic security updates..."
    
    apt-get install -y unattended-upgrades apt-listchanges
    
    # Configure unattended upgrades
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};

Unattended-Upgrade::Package-Blacklist {
};

Unattended-Upgrade::DevRelease "auto";
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";
EOF

    # Enable automatic updates
    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

    systemctl enable unattended-upgrades
    systemctl start unattended-upgrades
    
    log_success "Automatic security updates configured"
}

#===============================================================================
# Configure Time Synchronization
#===============================================================================
configure_time_sync() {
    log_info "Configuring time synchronization..."
    
    # Configure chrony
    cat > /etc/chrony/chrony.conf << 'EOF'
# NTP servers
pool ntp.ubuntu.com        iburst maxsources 4
pool 0.ubuntu.pool.ntp.org iburst maxsources 1
pool 1.ubuntu.pool.ntp.org iburst maxsources 1
pool 2.ubuntu.pool.ntp.org iburst maxsources 2

# Record the rate at which the system clock gains/losses time
driftfile /var/lib/chrony/chrony.drift

# Allow the system clock to be stepped in the first three updates
makestep 1.0 3

# Enable kernel synchronization of the real-time clock (RTC)
rtcsync

# Specify directory for log files
logdir /var/log/chrony
EOF

    systemctl enable chrony
    systemctl restart chrony
    
    # Set timezone to UTC (change as needed)
    timedatectl set-timezone UTC
    
    log_success "Time synchronization configured"
}

#===============================================================================
# Configure Audit System
#===============================================================================
configure_audit() {
    log_info "Configuring audit system..."
    
    # Configure auditd rules
    cat > /etc/audit/rules.d/hardening.rules << 'EOF'
# Delete all existing rules
-D

# Set buffer size
-b 8192

# Failure mode
-f 1

# Monitor user/group changes
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Monitor sudoers changes
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Monitor SSH config changes
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd

# Monitor cron changes
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron

# Monitor kernel modules
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules

# Monitor network config
-w /etc/hosts -p wa -k network
-w /etc/network/ -p wa -k network

# Make the configuration immutable
-e 2
EOF

    systemctl enable auditd
    systemctl restart auditd
    
    log_success "Audit system configured"
}

#===============================================================================
# Configure AIDE (Advanced Intrusion Detection Environment)
#===============================================================================
configure_aide() {
    log_info "Configuring AIDE..."
    
    # Initialize AIDE database (this can take a while)
    aideinit
    
    # Move the new database to the expected location
    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    
    # Create daily AIDE check cron job
    cat > /etc/cron.daily/aide-check << 'EOF'
#!/bin/bash
/usr/bin/aide --check | /usr/bin/mail -s "AIDE Integrity Check - $(hostname)" root
EOF
    chmod +x /etc/cron.daily/aide-check
    
    log_success "AIDE configured"
}

#===============================================================================
# Setup Bash Aliases and Convenience Functions
#===============================================================================
setup_aliases() {
    log_info "Setting up bash aliases..."
    
    cat > "$ACTUAL_USER_HOME/.bash_aliases" << 'EOF'
# System aliases
alias update='sudo apt update && sudo apt upgrade -y && sudo apt autoremove -y'
alias ports='sudo netstat -tulpn'
alias myip='curl -s ifconfig.me'
alias meminfo='free -h'
alias diskinfo='df -h'
alias cpuinfo='lscpu'

# Safety aliases
alias rm='rm -i'
alias cp='cp -i'
alias mv='mv -i'

# Navigation aliases
alias ..='cd ..'
alias ...='cd ../..'
alias ....='cd ../../..'

# List aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'

# Grep with color
alias grep='grep --color=auto'
alias fgrep='fgrep --color=auto'
alias egrep='egrep --color=auto'

# Docker aliases (if Docker is installed)
alias dps='docker ps'
alias dpsa='docker ps -a'
alias di='docker images'
alias dex='docker exec -it'
alias dlogs='docker logs -f'

# Git aliases
alias gs='git status'
alias ga='git add'
alias gc='git commit'
alias gp='git push'
alias gl='git log --oneline -10'
alias gd='git diff'

# System monitoring
alias top='htop'
alias watch='watch -n 1'

# Quick edit configs
alias sshconfig='sudo vim /etc/ssh/sshd_config'
alias ufwstatus='sudo ufw status verbose'
EOF

    chown "$ACTUAL_USER:$ACTUAL_USER" "$ACTUAL_USER_HOME/.bash_aliases"
    
    # Source aliases in bashrc if not already done
    if ! grep -q 'bash_aliases' "$ACTUAL_USER_HOME/.bashrc"; then
        echo '
# Load aliases
if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi' >> "$ACTUAL_USER_HOME/.bashrc"
    fi
    
    log_success "Bash aliases configured"
}

#===============================================================================
# Create System Info Script
#===============================================================================
create_sysinfo_script() {
    log_info "Creating system info script..."
    
    cat > /usr/local/bin/sysinfo << 'EOF'
#!/bin/bash
#===============================================================================
# System Information Script
#===============================================================================

echo "=============================================="
echo "          SYSTEM INFORMATION"
echo "=============================================="
echo ""
echo "Hostname:        $(hostname)"
echo "OS:              $(lsb_release -d | cut -f2)"
echo "Kernel:          $(uname -r)"
echo "Uptime:          $(uptime -p)"
echo "Current Time:    $(date)"
echo ""
echo "=============================================="
echo "          RESOURCE USAGE"
echo "=============================================="
echo ""
echo "CPU Usage:       $(top -bn1 | grep "Cpu(s)" | awk '{print $2}')%"
echo "Memory Usage:    $(free -h | awk '/^Mem:/ {print $3 "/" $2}')"
echo "Swap Usage:      $(free -h | awk '/^Swap:/ {print $3 "/" $2}')"
echo ""
echo "Disk Usage:"
df -h --output=source,size,used,avail,pcent,target | grep -E '^/dev'
echo ""
echo "=============================================="
echo "          NETWORK INFORMATION"
echo "=============================================="
echo ""
echo "IP Addresses:"
ip -4 addr show | grep inet | awk '{print "  " $NF ": " $2}'
echo ""
echo "Listening Ports:"
ss -tulpn | grep LISTEN | head -10
echo ""
echo "=============================================="
echo "          SECURITY STATUS"
echo "=============================================="
echo ""
echo "UFW Status:      $(sudo ufw status | head -1)"
echo "Fail2Ban:        $(systemctl is-active fail2ban)"
echo "AppArmor:        $(systemctl is-active apparmor)"
echo ""
echo "Last 5 Login Attempts:"
last -5
echo ""
EOF

    chmod +x /usr/local/bin/sysinfo
    
    log_success "System info script created"
}

#===============================================================================
# Display Summary
#===============================================================================
display_summary() {
    echo ""
    echo "=============================================="
    echo -e "${GREEN}    VM SETUP COMPLETED SUCCESSFULLY!${NC}"
    echo "=============================================="
    echo ""
    echo "The following components have been configured:"
    echo ""
    echo "  ✓ System updated and upgraded"
    echo "  ✓ Essential packages installed"
    echo "  ✓ Python with uv package manager"
    echo "  ✓ UFW Firewall (SSH allowed)"
    echo "  ✓ Fail2Ban intrusion prevention"
    echo "  ✓ AppArmor mandatory access control"
    echo "  ✓ SSH hardening"
    echo "  ✓ Kernel security parameters"
    echo "  ✓ Automatic security updates"
    echo "  ✓ Time synchronization (chrony)"
    echo "  ✓ Audit system (auditd)"
    echo "  ✓ AIDE integrity checking"
    echo "  ✓ Convenience aliases and scripts"
    echo ""
    echo "=============================================="
    echo "           IMPORTANT NOTES"
    echo "=============================================="
    echo ""
    echo "1. SSH root login has been DISABLED"
    echo "2. Password authentication is still enabled"
    echo "   (Disable after setting up SSH keys)"
    echo "3. To allow additional ports through firewall:"
    echo "   sudo ufw allow <port>/tcp"
    echo "4. Run 'sysinfo' to see system status"
    echo "5. Log out and back in for all changes to take effect"
    echo ""
    echo "=============================================="
    log_warning "A REBOOT is recommended to apply all changes"
    echo "=============================================="
    echo ""
}

#===============================================================================
# Main Function
#===============================================================================
main() {
    echo ""
    echo "=============================================="
    echo "     Ubuntu Server Setup Script v1.0.0"
    echo "=============================================="
    echo ""
    
    check_root
    
    log_info "Starting VM setup for user: $ACTUAL_USER"
    echo ""
    
    # Core setup
    system_update
    install_essentials
    install_python_uv
    
    # Security hardening
    configure_firewall
    configure_fail2ban
    configure_apparmor
    harden_ssh
    system_hardening
    configure_auto_updates
    configure_time_sync
    configure_audit
    
    # AIDE can take a long time, making it optional
    if [[ "${SKIP_AIDE:-}" != "true" ]]; then
        configure_aide
    else
        log_warning "Skipping AIDE configuration (SKIP_AIDE=true)"
    fi
    
    # Convenience
    setup_aliases
    create_sysinfo_script
    
    # Optional: Docker (uncomment to enable)
    # install_docker
    
    display_summary
}

# Run main function
main "$@"
