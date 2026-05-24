#!/usr/bin/env bash
set -uo pipefail

# Set secure PATH
export PATH="/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin"

# Initialize global variables for strict execution
RUNTIMES_FOUND=""
FAIL2BAN_INSTALLED=""
CROWDSEC_INSTALLED=""
CPU_INFO=""
PUBLIC_IFACE=""
PUBLIC_IP=""
ID=""
PRETTY_NAME=""
ID_LIKE=""
LOAD_AVG1=""
LOAD_AVG5=""
LOAD_AVG15=""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
GRAY='\033[0;90m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Parse command line options
VERBOSE=false
FAILED_TESTS_SUMMARY=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [-v|--verbose] [-h|--help]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [-v|--verbose] [-h|--help]"
            exit 1
            ;;
    esac
done

# Get current timestamp for the report filename
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
if [ "$EUID" -eq 0 ]; then
    mkdir -p /var/log/vps-audit
    REPORT_FILE="/var/log/vps-audit/vps-audit-report-${TIMESTAMP}.txt"
else
    REPORT_FILE="vps-audit-report-${TIMESTAMP}.txt"
fi

# Detect OS and distribution family
DISTRO_FAMILY="unknown"
ADMIN_GROUP="sudo"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    case "$ID" in
        ubuntu|debian)
            DISTRO_FAMILY="debian"
            ADMIN_GROUP="sudo"
            ;;
        centos|rhel|fedora)
            DISTRO_FAMILY="redhat"
            ADMIN_GROUP="wheel"
            ;;
        alpine)
            DISTRO_FAMILY="alpine"
            ADMIN_GROUP="wheel"
            ;;
        *)
            if [[ "${ID_LIKE:-}" =~ "debian" ]]; then
                DISTRO_FAMILY="debian"
                ADMIN_GROUP="sudo"
            elif [[ "${ID_LIKE:-}" =~ "rhel" || "${ID_LIKE:-}" =~ "fedora" ]]; then
                DISTRO_FAMILY="redhat"
                ADMIN_GROUP="wheel"
            fi
            ;;
    esac
fi

print_header() {
    local header="$1"
    echo -e "\n${BLUE}${BOLD}$header${NC}"
    echo -e "\n$header" >> "$REPORT_FILE"
    echo "================================" >> "$REPORT_FILE"
}

print_info() {
    local label="$1"
    local value="$2"
    echo -e "${BOLD}$label:${NC} $value"
    echo "$label: $value" >> "$REPORT_FILE"
}

# Function to check command existence
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Start the audit
echo -e "${BLUE}${BOLD}VPS Security Audit Tool${NC}"
echo -e "${GRAY}https://github.com/vernu/vps-audit${NC}"
echo -e "${GRAY}Starting audit at $(date)${NC}\n"

echo "VPS Security Audit Tool" > "$REPORT_FILE"
echo "https://github.com/vernu/vps-audit" >> "$REPORT_FILE"
echo "Starting audit at $(date)" >> "$REPORT_FILE"
echo "================================" >> "$REPORT_FILE"

# System Information Section
print_header "System Information"

# Get system information
OS_INFO=${PRETTY_NAME:-$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2)}
KERNEL_VERSION=$(uname -r)
HOSTNAME=$HOSTNAME
UPTIME=$(uptime -p)
UPTIME_SINCE=$(uptime -s)

# Get CPU Core Count
if command_exists nproc; then
    CPU_CORES=$(nproc)
else
    CPU_CORES=$(grep -c "^processor" /proc/cpuinfo)
fi

# Get CPU Model Name with count (to support multi-model/heterogeneous layouts and avoid newlines)
if grep -q "^model name" /proc/cpuinfo; then
    CPU_INFO=$(grep "^model name" /proc/cpuinfo | cut -d: -f2- | sed -e 's/^ *//' | sort | uniq -c | awk '{count=$1; $1=""; model=substr($0,2); printf "%dx %s, ", count, model}' | sed 's/, $//')
else
    # Check if CPU part entries exist in /proc/cpuinfo to count cores of each model on ARM
    if grep -q -i "^CPU part" /proc/cpuinfo; then
        CPU_INFO=$(awk -F: '
        function get_arm_name(part) {
            gsub(/^[ \t]+|[ \t]+$/, "", part)
            if (part == "0xd03") return "Cortex-A53"
            if (part == "0xd04") return "Cortex-A35"
            if (part == "0xd05") return "Cortex-A55"
            if (part == "0xd07") return "Cortex-A57"
            if (part == "0xd08") return "Cortex-A72"
            if (part == "0xd09") return "Cortex-A73"
            if (part == "0xd0a") return "Cortex-A75"
            if (part == "0xd0b") return "Cortex-A76"
            if (part == "0xd0c") return "Neoverse-N1"
            if (part == "0xd40") return "Cortex-A76"
            if (part == "0xd41") return "Cortex-A78"
            if (part == "0xd49") return "Neoverse-N2"
            if (part == "0xd4a") return "Neoverse-V2"
            return "ARM (Part " part ")"
        }
        /^[Cc][Pp][Uu] part/ {
            part=$2
            cpu = get_arm_name(part)
            models[cpu]++
        }
        END {
            for (m in models) {
                printf "%dx %s, ", models[m], m
            }
        }' /proc/cpuinfo | sed 's/, $//')
    fi

    if [ -z "$CPU_INFO" ] && command_exists lscpu; then
        CPU_INFO=$(lscpu | grep "Model name:" | cut -d: -f2- | sed -e 's/^ *//' | sort | uniq -c | awk '{count=$1; $1=""; model=substr($0,2); printf "%dx %s, ", count, model}' | sed 's/, $//')
    fi
    
    if [ -z "$CPU_INFO" ] && [ -f /proc/device-tree/model ]; then
        CPU_INFO=$(tr -d '\0' < /proc/device-tree/model)
    fi
    
    if [ -z "$CPU_INFO" ]; then
        CPU_INFO=$(uname -m)
    fi
fi

read TOTAL_MEM USED_MEM FREE_MEM <<< "$(free -m | awk '/^Mem:/ {print $2" "$3" "$7}')"
read TOTAL_DISK USED_DISK FREE_DISK <<< "$(df -BG / | sed 's/G//g' | awk 'NR==2 {print $2" "$3" "$4}')"
read PUBLIC_IFACE PUBLIC_IP <<< "$(ip route get 1 | grep -o "dev.*" | awk '{print $2" "$4}')"
read LOAD_AVG1 LOAD_AVG5 LOAD_AVG15 <<< "$(cut -f1-3 -d " " /proc/loadavg)"

# Detect active container runtimes
RUNTIMES_FOUND=""
if pgrep -x lxd >/dev/null 2>&1 || (command_exists systemctl && systemctl is-active --quiet lxd 2>/dev/null); then
    RUNTIMES_FOUND="$RUNTIMES_FOUND LXD"
fi
if pgrep -f "lxc-start" >/dev/null 2>&1 || (command_exists systemctl && systemctl is-active --quiet lxc 2>/dev/null); then
    RUNTIMES_FOUND="$RUNTIMES_FOUND LXC"
fi
if pgrep -x dockerd >/dev/null 2>&1 || (command_exists systemctl && systemctl is-active --quiet docker 2>/dev/null); then
    RUNTIMES_FOUND="$RUNTIMES_FOUND Docker"
fi
if pgrep -x containerd >/dev/null 2>&1 || (command_exists systemctl && systemctl is-active --quiet containerd 2>/dev/null); then
    RUNTIMES_FOUND="$RUNTIMES_FOUND containerd"
fi
if pgrep -x conmon >/dev/null 2>&1 || (command_exists systemctl && systemctl is-active --quiet podman 2>/dev/null); then
    RUNTIMES_FOUND="$RUNTIMES_FOUND Podman"
fi
RUNTIMES_FOUND=$(echo "$RUNTIMES_FOUND" | xargs)

# Print system information
print_info "Hostname" "$HOSTNAME"
print_info "Operating System" "$OS_INFO"
print_info "Kernel Version" "$KERNEL_VERSION"
print_info "Uptime" "$UPTIME (since $UPTIME_SINCE)"
print_info "CPU Model" "$CPU_INFO"
print_info "CPU Cores" "$CPU_CORES"
print_info "Memory" "Total: ${TOTAL_MEM}M Used: ${USED_MEM}M Free: ${FREE_MEM}M"
print_info "Disk Space" "Total: ${TOTAL_DISK}G, Used: ${USED_DISK}G, Free: ${FREE_DISK}G"
print_info "Container Runtimes" "${RUNTIMES_FOUND:-None detected}"
print_info "Public IP" "$PUBLIC_IP"/"$PUBLIC_IFACE"
print_info "Load Average" "$LOAD_AVG1 $LOAD_AVG5 $LOAD_AVG15"

echo "" >> "$REPORT_FILE"

# Security Audit Section
print_header "Security Audit Results"

# Function to check and report with four states
check_security() {
    local test_name="$1"
    local status="$2"
    local message="$3"
    local file_path="${4:-}"
    local specific_test="${5:-}"
    
    case $status in
        "PASS")
            echo -e "${GREEN}[PASS]${NC} $test_name ${GRAY}- $message${NC}"
            echo "[PASS] $test_name - $message" >> "$REPORT_FILE"
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $test_name ${GRAY}- $message${NC}"
            echo "[WARN] $test_name - $message" >> "$REPORT_FILE"
            if [ -n "$file_path" ] && [ -n "$specific_test" ]; then
                FAILED_TESTS_SUMMARY="${FAILED_TESTS_SUMMARY}${file_path}|WARN|${specific_test}
"
            fi
            ;;
        "FAIL")
            echo -e "${RED}[FAIL]${NC} $test_name ${GRAY}- $message${NC}"
            echo "[FAIL] $test_name - $message" >> "$REPORT_FILE"
            if [ -n "$file_path" ] && [ -n "$specific_test" ]; then
                FAILED_TESTS_SUMMARY="${FAILED_TESTS_SUMMARY}${file_path}|FAIL|${specific_test}
"
            fi
            ;;
        "INFO")
            echo -e "${BLUE}[INFO]${NC} $test_name ${GRAY}- $message${NC}"
            echo "[INFO] $test_name - $message" >> "$REPORT_FILE"
            ;;
    esac
    echo "" >> "$REPORT_FILE"
}

# Check system uptime
UPTIME=$(uptime -p)
UPTIME_SINCE=$(uptime -s)
echo -e "\nSystem Uptime Information:" >> "$REPORT_FILE"
echo "Current uptime: $UPTIME" >> "$REPORT_FILE"
echo "System up since: $UPTIME_SINCE" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo -e "System Uptime: $UPTIME (since $UPTIME_SINCE)"

# Check if system requires restart
if [ -f /var/run/reboot-required ]; then
    check_security "System Restart" "WARN" "System requires a restart to apply updates" "/var/run/reboot-required" "reboot_required"
else
    check_security "System Restart" "PASS" "No restart required"
fi

# Check Kernel Security and Modules
print_header "Kernel and Modules Security"

# 1. Tainted Kernel
if [ -f /proc/sys/kernel/tainted ]; then
    TAINTED=$(cat /proc/sys/kernel/tainted)
    if [ "$TAINTED" -eq 0 ]; then
        check_security "Kernel Taint" "PASS" "Kernel is not tainted"
    else
        TAINTED_MSG=$(dmesg 2>/dev/null | grep -i "taint" | tail -n 5)
        if [ -n "$TAINTED_MSG" ]; then
            check_security "Kernel Taint" "WARN" "Kernel is tainted (taint code: $TAINTED) - logs:\n$TAINTED_MSG" "/proc/sys/kernel/tainted" "kernel_taint"
        else
            check_security "Kernel Taint" "WARN" "Kernel is tainted (taint code: $TAINTED) - check dmesg for details" "/proc/sys/kernel/tainted" "kernel_taint"
        fi
    fi
fi

# 2. Runtime Module Loading status
if [ -f /proc/sys/kernel/modules_disabled ]; then
    MOD_DISABLED=$(cat /proc/sys/kernel/modules_disabled)
    if [ "$MOD_DISABLED" -eq 1 ]; then
        check_security "Runtime Module Loading" "PASS" "Runtime kernel module loading is disabled"
    else
        check_security "Runtime Module Loading" "WARN" "Runtime kernel module loading is enabled" "/proc/sys/kernel/modules_disabled" "modules_disabled"
    fi
fi

# 3. Kernel Module Signature Verification
SGN_FORCE=$(sysctl -n kernel.modules_sgn_force 2>/dev/null)
if [ -n "$SGN_FORCE" ]; then
    if [ "$SGN_FORCE" -eq 1 ]; then
        check_security "Module Signatures" "PASS" "Forced module signature verification is active"
    else
        check_security "Module Signatures" "WARN" "Forced module signature verification is inactive" "/proc/sys/kernel/modules_sgn_force" "modules_sgn_force"
    fi
fi

# Query active SSH configuration using sshd -T if available
SSHD_CONFIG=""
if command_exists sshd; then
    SSHD_CONFIG=$(sshd -T 2>/dev/null)
elif [ -x /usr/sbin/sshd ]; then
    SSHD_CONFIG=$(/usr/sbin/sshd -T 2>/dev/null)
fi

# Fallback to manual parsing if sshd -T is not available or failed
if [ -z "$SSHD_CONFIG" ]; then
    ssh_include_pattern='^[[:space:]]*Include'
    while IFS= read -r line; do
        if [[ "$line" =~ $ssh_include_pattern ]]; then
            INCLUDE=$(echo $line | awk '{print $2}')
            SSHD_CONFIG="$SSHD_CONFIG### Included from $INCLUDE\n"
            if [ -f "$INCLUDE" ]; then
                while IFS= read -r iline; do
                    SSHD_CONFIG="$SSHD_CONFIG$iline\n"
                done <<< "$(grep -v -e "^ *#" -e "^$" "$INCLUDE")"
            elif [ -d "$INCLUDE" ]; then
                for file in "$INCLUDE"/*; do
                    if [ -f "$file" ]; then
                        while IFS= read -r iline; do
                            SSHD_CONFIG="$SSHD_CONFIG$iline\n"
                        done <<< "$(grep -v -e "^ *#" -e "^$" "$file")"
                    fi
                done
            fi
            SSHD_CONFIG="$SSHD_CONFIG### End include from $INCLUDE\n"
        else
            SSHD_CONFIG="$SSHD_CONFIG$line\n"
        fi
        done <<< "$(grep -v -e "^ *#" -e "^$" /etc/ssh/sshd_config)"
fi

# function to check on SSH configuration values (case-insensitive grep)
sshd_config() { 
    echo "$SSHD_CONFIG" | grep -i -e "^ *$1" 2>/dev/null | head -1 | awk '{print $2}'
}

# Check SSH root login (handle both main config and overrides if they exist)
SSH_ROOT=$(sshd_config "PermitRootLogin")
if [ "$SSH_ROOT" = "no" ]; then
    check_security "SSH Root Login" "PASS" "Root login is properly disabled in SSH configuration"
else
    check_security "SSH Root Login" "FAIL" "Root login is currently allowed - this is a security risk. Disable it in /etc/ssh/sshd_config" "/etc/ssh/sshd_config" "PermitRootLogin"
fi

# Check SSH password authentication (handle both main config and overrides if they exist)
SSH_PASSWORD=$(sshd_config "PasswordAuthentication")
if [ "$SSH_PASSWORD" = "no" ]; then
    check_security "SSH Password Auth" "PASS" "Password authentication is disabled, key-based auth only"
else
    check_security "SSH Password Auth" "FAIL" "Password authentication is enabled - consider using key-based authentication only" "/etc/ssh/sshd_config" "PasswordAuthentication"
fi


# Check for default/unsecure SSH ports 
UNPRIVILEGED_PORT_START=$(cat /proc/sys/net/ipv4/ip_unprivileged_port_start)
SSH_PORT=$(sshd_config "Port")
if [ -z "$SSH_PORT" ]; then
    SSH_PORT="22"
fi

if [ "$SSH_PORT" = "22" ]; then
    check_security "SSH Port" "WARN" "Using default port 22 - consider changing to a non-standard port for security by obscurity" "/etc/ssh/sshd_config" "Port"
elif [ "$SSH_PORT" -ge "$UNPRIVILEGED_PORT_START" ]; then
    check_security "SSH Port" "FAIL" "Using unprivileged port $SSH_PORT -  use a port below $UNPRIVILEGED_PORT_START for better security" "/etc/ssh/sshd_config" "Port"
else
    check_security "SSH Port" "PASS" "Using non-default port $SSH_PORT which helps prevent automated attacks"
fi

# Check SSH Agent Forwarding
SSH_AGENT_FWD=$(sshd_config "AllowAgentForwarding")
if [ "$SSH_AGENT_FWD" = "no" ]; then
    check_security "SSH Agent Forwarding" "PASS" "SSH Agent Forwarding is disabled"
else
    check_security "SSH Agent Forwarding" "WARN" "SSH Agent Forwarding is enabled or default" "/etc/ssh/sshd_config" "AllowAgentForwarding"
fi

# Check SSH X11 Forwarding
SSH_X11_FWD=$(sshd_config "X11Forwarding")
if [ "$SSH_X11_FWD" = "no" ] || [ -z "$SSH_X11_FWD" ]; then
    check_security "SSH X11 Forwarding" "PASS" "SSH X11 Forwarding is disabled"
else
    check_security "SSH X11 Forwarding" "WARN" "SSH X11 Forwarding is enabled" "/etc/ssh/sshd_config" "X11Forwarding"
fi

# Check Firewall Status
check_firewall_status() {
    if [ "$EUID" -ne 0 ]; then
        check_security "Firewall Status" "INFO" "Script is not running as root - some checks may be skipped"
    else
        if command_exists ufw; then
            if ufw status | grep -qw "active"; then
                check_security "Firewall Status (UFW)" "PASS" "UFW firewall is active and protecting your system"
            else
                check_security "Firewall Status (UFW)" "FAIL" "UFW firewall is not active - your system is exposed to network attacks"
            fi
        elif command_exists firewall-cmd; then
            if firewall-cmd --state 2>/dev/null | grep -q "running"; then
                check_security "Firewall Status (firewalld)" "PASS" "Firewalld is active and protecting your system"
            else
                check_security "Firewall Status (firewalld)" "FAIL" "Firewalld is not active - your system is exposed to network attacks"
            fi
        elif command_exists iptables; then
            if iptables -L -n | grep -q "Chain INPUT"; then
                check_security "Firewall Status (iptables)" "PASS" "iptables rules are active and protecting your system"
            else
                check_security "Firewall Status (iptables)" "FAIL" "No active iptables rules found - your system may be exposed"
            fi
        elif command_exists nft; then
            if nft list ruleset | grep -q "table"; then
                check_security "Firewall Status (nftables)" "PASS" "nftables rules are active and protecting your system"
            else
                check_security "Firewall Status (nftables)" "FAIL" "No active nftables rules found - your system may be exposed"
            fi
        else
            check_security "Firewall Status" "FAIL" "No recognized firewall tool is installed on this system"
        fi
    fi
}

# Firewall check
check_firewall_status

# Check for unattended upgrades
if dpkg -l | grep -q "unattended-upgrades"; then
    check_security "Unattended Upgrades" "PASS" "Automatic security updates are configured"
else
    check_security "Unattended Upgrades" "FAIL" "Automatic security updates are not configured - system may miss critical updates"
fi

# Check Intrusion Prevention Systems (Fail2ban or CrowdSec)
IPS_INSTALLED=0
IPS_ACTIVE=0
dpkg-query -l fail2ban >/dev/null 2>&1 && {
    IPS_INSTALLED=1
    FAIL2BAN_INSTALLED=1
    systemctl is-active fail2ban >/dev/null 2>&1 && IPS_ACTIVE=1
}

dpkg-query -l crowdsec >/dev/null 2>&1 && {
    IPS_INSTALLED=1
    CROWDSEC_INSTALLED=1
    systemctl is-active crowdsec >/dev/null 2>&1 && IPS_ACTIVE=1
}

if [ -z "$FAIL2BAN_INSTALLED" ] && [ -z "$CROWDSEC_INSTALLED" ]; then
    check_security "Intrusion Prevention" "FAIL" "No intrusion prevention system (Fail2ban or CrowdSec) is installed"
fi

case "$IPS_INSTALLED$IPS_ACTIVE" in
    "11") check_security "Intrusion Prevention" "PASS" "Fail2ban or CrowdSec is installed and running" ;;
    "10") check_security "Intrusion Prevention" "WARN" "Fail2ban or CrowdSec is installed but not running" ;;
esac

# Check failed login attempts
LOG_FILE="/var/log/auth.log"

if [ -f "$LOG_FILE" ]; then
    FAILED_LOGINS=$(grep -c "Failed password" "$LOG_FILE" 2>/dev/null || echo 0)
else
    FAILED_LOGINS=0
    echo "Warning: Log file $LOG_FILE not found or unreadable. Assuming 0 failed login attempts."
fi

# Ensure FAILED_LOGINS is numeric and strip whitespace
FAILED_LOGINS=$(echo "$FAILED_LOGINS" | tr -d '[:space:]')
# Remove leading zeros (if any)
FAILED_LOGINS=$((10#$FAILED_LOGINS)) # Use arithmetic evaluation to ensure it's numeric and format correctly.

if [ "$FAILED_LOGINS" -lt 10 ]; then
    check_security "Failed Logins" "PASS" "Only $FAILED_LOGINS failed login attempts detected - this is within normal range"
elif [ "$FAILED_LOGINS" -lt 50 ]; then
    check_security "Failed Logins" "WARN" "$FAILED_LOGINS failed login attempts detected - might indicate breach attempts" "$LOG_FILE" "failed_logins"
else
    check_security "Failed Logins" "FAIL" "$FAILED_LOGINS failed login attempts detected - possible brute force attack in progress" "$LOG_FILE" "failed_logins"
fi

# Check system updates
UPDATES=$(apt-get -s upgrade 2>/dev/null | grep -P '^\d+ upgraded' | cut -d" " -f1)
if [ -z "$UPDATES" ]; then
    UPDATES=0
fi
if [ "$UPDATES" -eq 0 ]; then
    check_security "System Updates" "PASS" "All system packages are up to date"
else
    check_security "System Updates" "FAIL" "$UPDATES security updates available - system is vulnerable to known exploits"
fi

# Check running services
SERVICES=$(systemctl list-units --type=service --state=running | grep -c "loaded active running")
if [ "$SERVICES" -lt 20 ]; then
    check_security "Running Services" "PASS" "Running minimal services ($SERVICES) - good for security"
elif [ "$SERVICES" -lt 40 ]; then
    check_security "Running Services" "WARN" "$SERVICES services running - consider reducing attack surface"
else
    check_security "Running Services" "FAIL" "Too many services running ($SERVICES) - increases attack surface"
fi

# Check ports using ss or netstat
if command -v ss >/dev/null 2>&1; then
    LISTENING_PORTS=$(ss -tuln | grep LISTEN | awk '{print $5}')
elif command -v netstat >/dev/null 2>&1; then
    LISTENING_PORTS=$(netstat -tuln | grep LISTEN | awk '{print $4}')
else
    check_security "Port Scanning" "FAIL" "Neither 'ss' nor 'netstat' is available on this system."
    LISTENING_PORTS=""
fi

# Process LISTENING_PORTS to extract unique public ports
if [ -n "$LISTENING_PORTS" ]; then
    PUBLIC_PORTS=$(echo "$LISTENING_PORTS" | awk -F':' '{print $NF}' | sort -n | uniq | tr '\n' ',' | sed 's/,$//')
    PORT_COUNT=$(echo "$PUBLIC_PORTS" | tr ',' '\n' | wc -w)
    INTERNET_PORTS=$(echo "$PUBLIC_PORTS" | tr ',' '\n' | wc -w)

    if [ "$PORT_COUNT" -lt 10 ] && [ "$INTERNET_PORTS" -lt 3 ]; then
        check_security "Port Security" "PASS" "Good configuration (Total: $PORT_COUNT, Public: $INTERNET_PORTS accessible ports): $PUBLIC_PORTS"
    elif [ "$PORT_COUNT" -lt 20 ] && [ "$INTERNET_PORTS" -lt 5 ]; then
        check_security "Port Security" "WARN" "Review recommended (Total: $PORT_COUNT, Public: $INTERNET_PORTS accessible ports): $PUBLIC_PORTS"
    else
        check_security "Port Security" "FAIL" "High exposure (Total: $PORT_COUNT, Public: $INTERNET_PORTS accessible ports): $PUBLIC_PORTS"
    fi
else
    check_security "Port Scanning" "WARN" "Port scanning failed due to missing tools. Ensure 'ss' or 'netstat' is installed."
fi

# Function to format the message with proper indentation for the report file
format_for_report() {
    local message="$1"
    echo "$message" >> "$REPORT_FILE"
}

# Check disk space usage
if [ "${TOTAL_DISK:-0}" -gt 0 ] 2>/dev/null; then
    DISK_USAGE=$(( USED_DISK * 100 / TOTAL_DISK ))
else
    DISK_USAGE=0
fi

if [ "$DISK_USAGE" -lt 50 ]; then
    check_security "Disk Usage" "PASS" "Healthy disk space available (${DISK_USAGE}% used - Used: ${USED_DISK} of ${TOTAL_DISK}, Available: ${FREE_DISK})"
elif [ "$DISK_USAGE" -lt 80 ]; then
    check_security "Disk Usage" "WARN" "Disk space usage is moderate (${DISK_USAGE}% used - Used: ${USED_DISK} of ${TOTAL_DISK}, Available: ${FREE_DISK})" "/" "disk_space"
else
    check_security "Disk Usage" "FAIL" "Critical disk space usage (${DISK_USAGE}% used - Used: ${USED_DISK} of ${TOTAL_DISK}, Available: ${FREE_DISK})" "/" "disk_space"
fi

# Check memory usage
if [ "${TOTAL_MEM:-0}" -gt 0 ] 2>/dev/null; then
    MEM_USAGE=$(( USED_MEM * 100 / TOTAL_MEM ))
else
    MEM_USAGE=0
fi

if [ "$MEM_USAGE" -lt 50 ]; then
    check_security "Memory Usage" "PASS" "Healthy memory usage (${MEM_USAGE}% used - Used: ${USED_MEM}M of ${TOTAL_MEM}M, Available: ${FREE_MEM}M)"
elif [ "$MEM_USAGE" -lt 80 ]; then
    check_security "Memory Usage" "WARN" "Moderate memory usage (${MEM_USAGE}% used - Used: ${USED_MEM}M of ${TOTAL_MEM}M, Available: ${FREE_MEM}M)"
else
    check_security "Memory Usage" "FAIL" "Critical memory usage (${MEM_USAGE}% used - Used: ${USED_MEM}M of ${TOTAL_MEM}M, Available: ${FREE_MEM}M)"
fi

# Check CPU usage
if [ -f /proc/stat ]; then
    read -r _ user nice system idle iowait irq softirq steal _ < /proc/stat
    prev_idle=$((idle + iowait))
    prev_total=$((user + nice + system + idle + iowait + irq + softirq + steal))

    sleep 0.5

    read -r _ user nice system idle iowait irq softirq steal _ < /proc/stat
    idle=$((idle + iowait))
    total=$((user + nice + system + idle + iowait + irq + softirq + steal))

    diff_idle=$((idle - prev_idle))
    diff_total=$((total - prev_total))

    if [ "$diff_total" -gt 0 ]; then
        CPU_USAGE=$(( (diff_total - diff_idle) * 100 / diff_total ))
        CPU_IDLE=$(( diff_idle * 100 / diff_total ))
    else
        CPU_USAGE=0
        CPU_IDLE=100
    fi
else
    CPU_USAGE=$(top -bn1 | grep -i "cpu" | head -1 | awk '{print int($2)}')
    if [ -z "$CPU_USAGE" ]; then CPU_USAGE=0; fi
    CPU_IDLE=$((100 - CPU_USAGE))
fi

CPU_LOAD="${LOAD_AVG1:-$(uptime | awk -F'load average:' '{ print $2 }' | awk -F',' '{ print $1 }' | tr -d ' ' || echo 'unknown')}"

if [ "$CPU_USAGE" -lt 50 ]; then
    check_security "CPU Usage" "PASS" "Healthy CPU usage (${CPU_USAGE}% used - Active: ${CPU_USAGE}%, Idle: ${CPU_IDLE}%, Load: ${CPU_LOAD}, Cores: ${CPU_CORES})"
   elif [ "$CPU_USAGE" -lt 80 ]; then
    check_security "CPU Usage" "WARN" "Moderate CPU usage (${CPU_USAGE}% used - Active: ${CPU_USAGE}%, Idle: ${CPU_IDLE}%, Load: ${CPU_LOAD}, Cores: ${CPU_CORES})"
   else
    check_security "CPU Usage" "FAIL" "Critical CPU usage (${CPU_USAGE}% used - Active: ${CPU_USAGE}%, Idle: ${CPU_IDLE}%, Load: ${CPU_LOAD}, Cores: ${CPU_CORES})"
   fi

# # Check sudo configuration - if we're root that is
if [ "$EUID" -ne 0 ]; then
    check_security "Sudo Users" "INFO" "Script is not running as root - some checks may be skipped"
else
    # Check if sudo logging is enabled (either via custom logfile, or standard syslog/journald which is the default)
    if grep -q "^Defaults.*logfile" /etc/sudoers 2>/dev/null || grep -q "^Defaults.*logfile" /etc/sudoers.d/* 2>/dev/null; then
        check_security "Sudo Logging" "PASS" "Sudo commands are logged to a custom file"
    elif grep -q "Defaults.*!syslog" /etc/sudoers 2>/dev/null || grep -q "Defaults.*!syslog" /etc/sudoers.d/* 2>/dev/null; then
        check_security "Sudo Logging" "FAIL" "Sudo commands are not being logged (syslog logging is disabled)" "/etc/sudoers" "syslog_logging"
    else
        check_security "Sudo Logging" "PASS" "Sudo commands are logged to syslog/journalctl by default"
    fi
fi

# Check password policy
if [ -f "/etc/security/pwquality.conf" ]; then
    if grep -q "minlen.*12" /etc/security/pwquality.conf; then
        check_security "Password Policy" "PASS" "Strong password policy is enforced"
    else
        check_security "Password Policy" "FAIL" "Weak password policy - passwords may be too simple" "/etc/security/pwquality.conf" "minlen"
    fi
else
    check_security "Password Policy" "WARN" "No password policy configured - system accepts weak passwords" "/etc/security/pwquality.conf" "minlen"
fi


# check for sudo users
SUDO_USERS=$(grep -Po "^${ADMIN_GROUP}.+:\K.*$" /etc/group | tr ',' ' ')

if [ -z "$SUDO_USERS" ]; then
    check_security "Sudo Users" "FAIL" "No users in the $ADMIN_GROUP group - no users with root access" "/etc/group" "sudo_group_members"
else
    check_security "Sudo Users" "PASS" "$ADMIN_GROUP group members: $SUDO_USERS"
fi

# Check for ssh keys in authorized_keys
for user in $SUDO_USERS; do
    AUTH_KEYS="/home/$user/.ssh/authorized_keys"
    if [ -f "$AUTH_KEYS" ]; then
        SSH_KEYS=$(wc -l "$AUTH_KEYS" | awk '{print $1}')
        if [ "$SSH_KEYS" -gt 0 ]; then
            check_security "SSH Keys" "PASS" "Found $SSH_KEYS SSH keys in for user $user"
        else
            check_security "SSH Keys" "WARN" "No SSH keys found for user $user - consider using key-based authentication" "$AUTH_KEYS" "authorized_keys"
        fi
    else
        check_security "SSH Keys" "WARN" "No SSH keys found for user $user - consider using key-based authentication" "$AUTH_KEYS" "authorized_keys"
    fi
done

if [ "$EUID" -eq 0 ]; then
    # Check for empty passwords in /etc/shadow
    if [ -f /etc/shadow ]; then
        EMPTY_PASSWD_ACCOUNTS=$(awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null | tr '\n' ' ' | xargs)
        if [ -z "$EMPTY_PASSWD_ACCOUNTS" ]; then
            check_security "Empty Passwords" "PASS" "No accounts with empty passwords found"
        else
            check_security "Empty Passwords" "FAIL" "Accounts with empty passwords found: $EMPTY_PASSWD_ACCOUNTS" "/etc/shadow" "empty_password"
        fi
    fi

    # Check for multiple UID 0 accounts
    UID_ZERO_ACCOUNTS=$(awk -F: '$3 == 0 {print $1}' /etc/passwd 2>/dev/null | tr '\n' ' ' | xargs)
    if [ "$UID_ZERO_ACCOUNTS" = "root" ]; then
        check_security "UID 0 Accounts" "PASS" "Only root has UID 0"
    else
        check_security "UID 0 Accounts" "FAIL" "Multiple accounts found with UID 0: $UID_ZERO_ACCOUNTS" "/etc/passwd" "uid_zero"
    fi
fi

# Check for SUID files, and check their md5 checksums against the ones in the dpkg database
# Exclude active container runtime directories from SUID scan
FIND_OPTS=( / )
if [ -n "$RUNTIMES_FOUND" ]; then
    FIND_OPTS=( / \( )
    first=1
    if [[ "$RUNTIMES_FOUND" =~ "LXC" ]]; then
        [ $first -ne 1 ] && FIND_OPTS+=( -o )
        FIND_OPTS+=( -path /var/lib/lxc )
        first=0
    fi
    if [[ "$RUNTIMES_FOUND" =~ "LXD" ]]; then
        [ $first -ne 1 ] && FIND_OPTS+=( -o )
        FIND_OPTS+=( -path /var/lib/lxd -o -path /var/snap/lxd )
        first=0
    fi
    if [[ "$RUNTIMES_FOUND" =~ "Docker" ]]; then
        [ $first -ne 1 ] && FIND_OPTS+=( -o )
        FIND_OPTS+=( -path /var/lib/docker )
        first=0
    fi
    if [[ "$RUNTIMES_FOUND" =~ "containerd" ]]; then
        [ $first -ne 1 ] && FIND_OPTS+=( -o )
        FIND_OPTS+=( -path /var/lib/containerd )
        first=0
    fi
    if [[ "$RUNTIMES_FOUND" =~ "Podman" ]]; then
        [ $first -ne 1 ] && FIND_OPTS+=( -o )
        FIND_OPTS+=( -path /var/lib/containers )
        first=0
    fi
    FIND_OPTS+=( \) -prune -o )
    check_security "SUID Scan Exclusion" "INFO" "Excluded active container runtime directories: $RUNTIMES_FOUND"
fi

FIND_OPTS+=( -type f -perm -4000 -xdev -print )
SUID_SUSPECT=""
while IFS= read -r file; do
    [ -z "$file" ] && continue
    [ -f "$file" ] || continue
    BIN_FILE=""
    file_inode=""
    binfile_inode=""
    DEB_MATCH=""
    DEB_HASH=""
    FILE_HASH=$(md5sum "$file" | awk '{print $1}')
    DEB_PKG=$(dpkg -S "$file" 2>/dev/null | cut -d: -f1)
    if [ -z "$DEB_PKG" ]; then
        if [[ "$file" == /usr/* ]]; then
            BIN_FILE=$(echo "$file" | sed 's/^\/usr//')
            if [ -f "$BIN_FILE" ]; then
		file_inode=$(ls -i "$file" | cut -f1 -d " ")
		binfile_inode=$(ls -i "$BIN_FILE" | cut -f1 -d " ")
		if [[ "$file_inode" == "$binfile_inode" ]]; then
                    check_security "SUID Files" "INFO" "Couldn't find $file in installed packages, checking hardlinked $BIN_FILE"
                    DEB_PKG=$(dpkg -S "$BIN_FILE" 2>/dev/null | cut -d: -f1)
                    file=$BIN_FILE
		fi
            fi
        fi
    fi
    if [ -z "$DEB_PKG" ]; then
        check_security "SUID Files" "WARN" "Found SUID binary not in installed packages: $file" "$file" "package_ownership"
        SUID_SUSPECT="${SUID_SUSPECT}\n${file}"
    else
        DEB_MATCH=$(echo "$file" | cut -c2-)
        DEB_HASH=$(grep -e ${DEB_MATCH}$ /var/lib/dpkg/info/$DEB_PKG.md5sums 2>/dev/null | cut -d" " -f1)
        if [ "$FILE_HASH" != "$DEB_HASH" ]; then
            check_security "SUID Files" "FAIL" "Found SUID binary with mismatched checksum: $file" "$file" "md5sum"
            SUID_SUSPECT="${SUID_SUSPECT}\n${file}"
        fi
    fi
done <<< "$(find "${FIND_OPTS[@]}" 2>/dev/null)"

if [ "$SUID_SUSPECT" = "" ]; then
    check_security "SUID Files" "PASS" "No suspicious SUID files found - good security practice"
fi

# Print verbose failure/warning details if enabled
if [ "$VERBOSE" = "true" ] && [ -n "$FAILED_TESTS_SUMMARY" ]; then
    echo -e "\n${BLUE}${BOLD}Verbose Failure/Warning Details:${NC}"
    echo -e "\nVerbose Failure/Warning Details:" >> "$REPORT_FILE"
    echo "=================================" >> "$REPORT_FILE"
    
    current_file=""
    echo "$FAILED_TESTS_SUMMARY" | grep -v '^$' | sort -t'|' -k1,1 | while IFS='|' read -r file_path status specific_test; do
        if [ "$file_path" != "$current_file" ]; then
            current_file="$file_path"
            echo -e "\n${BOLD}File: $current_file${NC}"
            echo -e "\nFile: $current_file" >> "$REPORT_FILE"
        fi
        case "$status" in
            "FAIL")
                echo -e "  - ${RED}[FAIL]${NC} $specific_test"
                echo "  - [FAIL] $specific_test" >> "$REPORT_FILE"
                ;;
            "WARN")
                echo -e "  - ${YELLOW}[WARN]${NC} $specific_test"
                echo "  - [WARN] $specific_test" >> "$REPORT_FILE"
                ;;
        esac
    done
    echo "" >> "$REPORT_FILE"
fi

# Add system information summary to report
echo "================================" >> "$REPORT_FILE"
echo "System Information Summary:" >> "$REPORT_FILE"
echo "Hostname: $(hostname)" >> "$REPORT_FILE"
echo "Kernel: $(uname -r)" >> "$REPORT_FILE"
echo "OS: $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)" >> "$REPORT_FILE"
echo "CPU Cores: $(nproc)" >> "$REPORT_FILE"
echo "Total Memory: $(free -h | awk '/^Mem:/ {print $2}')" >> "$REPORT_FILE"
echo "Total Disk Space: $(df -h / | awk 'NR==2 {print $2}')" >> "$REPORT_FILE"
echo "================================" >> "$REPORT_FILE"

echo -e "\nVPS audit complete. Full report saved to $REPORT_FILE"
echo -e "Review $REPORT_FILE for detailed recommendations."

# Add summary to report
echo "================================" >> "$REPORT_FILE"
echo "End of VPS Audit Report" >> "$REPORT_FILE"
echo "Please review all failed checks and implement the recommended fixes." >> "$REPORT_FILE"
