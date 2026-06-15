using System;

namespace Shared.ShellOperations
{
    /// <summary>
    /// Shell script generator class for DDoS mitigation and kernel provisioning layer.
    /// Sanitized for OSS export: no proprietary business logic, credentials, or internal database connections.
    /// </summary>
    public static class GameNodeShelloperations
    {
        public const string DDOS_PROTECTION        = "ddos_protection.sh";
        public const string DELETE_DDOS_PROTECTION = "delete_ddos_protection.sh";
        public const string GARBAGE_COLLECT_NFT    = "garbage_collect_nft.sh";
        public const string UTILITY_SCRIPTS        = "/home/utility-scripts";

        /// <summary>
        /// Generates the shell command script to deploy the root nftables configuration, 
        /// including raw_checks, volumetric drops, state checks, and loopback/Docker/WireGuard allow-lists.
        /// </summary>
        /// <returns>A string containing the bash script to configure root nftables.</returns>
        public static string BaseDDoSConfiguration()
        {
            return """
NFT_DIR="/etc/nftables.d"
mkdir -p "$NFT_DIR"

MAIN_CONF="/etc/nftables.conf"

cat >"$MAIN_CONF" <<EOF
#!/usr/sbin/nft -f

# [CRITICAL] Docker Safety: Never flush 'ruleset' — that kills Docker NAT.
add table inet filter
delete table inet filter

include "/etc/nftables.d/*.nft"
EOF

BASE_FILE="$NFT_DIR/00-base.nft"

cat <<'EOF' > "$BASE_FILE"
table inet filter {
    counter ddos_blacklist_drops {
        packets 0 bytes 0
    }

    set blacklist {
        type ipv4_addr
        flags dynamic, timeout
        size 65535
        timeout 300s
    }

    set blacklist6 {
        type ipv6_addr
        flags dynamic, timeout
        size 65535
        timeout 300s
    }

    chain raw_checks {
        type filter hook prerouting priority -150; policy accept;

        # PHASE 1: DROP BLACKLISTED IPs
        ip saddr @blacklist counter name ddos_blacklist_drops drop
        ip6 saddr @blacklist6 counter name ddos_blacklist_drops drop

        # Allow loopback, WireGuard, Docker internal
        iif "lo" accept
        iifname "wg0" accept
        iifname "docker*" accept
        iifname "br-*" accept
        iifname "veth*" accept
        iifname "vx-*" accept
        iifname "docker_gwbridge" accept

        # PHASE 1.5: HEAVY TCP VALIDATION
        tcp flags & (fin|syn|rst|psh|ack|urg) == 0 counter drop
        tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|syn|rst|psh|ack|urg) counter drop
        tcp flags & (fin|syn) == (fin|syn) counter drop
        tcp flags & (syn|rst) == (syn|rst) counter drop
        tcp flags & (fin|rst) == (fin|rst) counter drop
        tcp flags & (fin|ack) == fin counter drop
        tcp flags & (psh|ack) == psh counter drop
        tcp flags & (urg|ack) == urg counter drop
        tcp flags syn tcp option maxseg size 1-536 counter drop

        # PHASE 2: Outbound DNS/Web responses (before invalid-state check)
        udp sport 53 counter accept
        tcp sport { 53, 80, 443 } counter accept

        # PHASE 3: State Sanity
        ct state invalid counter drop
        tcp flags != syn ct state new counter drop
        ct state established,related accept

        # PHASE 4: Infrastructure Allow-list
        udp dport 51820 limit rate 80000/second burst 10000 packets counter accept
        tcp dport 22 limit rate 10/minute burst 5 packets counter accept
        icmp type echo-request limit rate 5/second accept
        icmpv6 type echo-request limit rate 5/second accept
    }
}
EOF

sed -i 's/@blacklist_table\.blacklist/@blacklist/g' "$NFT_DIR"/*.nft 2>/dev/null || true

nft -f /etc/nftables.conf
echo "[i] Base nftables ruleset applied."
""".Replace("\r\n", "\n");
        }

        /// <summary>
        /// Returns the command line to execute the port-specific DDoS protection script.
        /// </summary>
        /// <param name="Protocol">tcp or udp</param>
        /// <param name="Port">target port number</param>
        /// <param name="Rate_Limit">packets/second allowed per IP</param>
        /// <param name="Burst">burst headroom</param>
        /// <param name="Blacklist_Duration">seconds before ban expires</param>
        /// <param name="Max_Connections">max concurrent TCP sockets per IP before ban</param>
        /// <param name="Udp_Multiplier">volumetric ban threshold = Rate_Limit × this</param>
        /// <returns>A command string to run the DDoS protection script.</returns>
        public static string AddDDosProtection(
            string Protocol,
            string Port,
            int Rate_Limit,
            int Burst,
            int Blacklist_Duration,
            int Max_Connections,
            int Udp_Multiplier)
        {
            return $"{UTILITY_SCRIPTS}/{DDOS_PROTECTION} {Port} {Protocol} {Rate_Limit} {Burst} {Blacklist_Duration} {Max_Connections} {Udp_Multiplier}";
        }

        /// <summary>
        /// Installs ddos_protection.sh on the node.
        /// TCP strategy: hard-ban on socket exhaustion OR volumetric flood; soft-drop on normal overage.
        /// UDP strategy: hard-ban only on extreme volumetric threshold (Rate_Limit × UDP_MULTIPLIER);
        ///               soft-drop on normal overage (prevents false-positive bans due to IP spoofing).
        /// </summary>
        /// <returns>A string containing the ddos_protection.sh bash script.</returns>
        public static string DDosProtectionRulesScript()
        {
            return $$"""
cat <<'DDOS_EOF' > {{UTILITY_SCRIPTS}}/{{DDOS_PROTECTION}}
#!/bin/bash
set -eu

# Usage: ./ddos_protection.sh <port> <tcp|udp> <limit> <burst>
#                             <blacklist_seconds> <max_conns> <udp_multiplier>

PORT="$1"
PROTOCOL="$2"
LIMIT="$3"
BURST="$4"
BLACKLIST_SECONDS="$5"
MAX_CONNS="$6"
UDP_MULTIPLIER="$7"

if [[ -z "$PORT" || -z "$PROTOCOL" || -z "$LIMIT" || -z "$BURST" || -z "$BLACKLIST_SECONDS" || -z "$MAX_CONNS" || -z "$UDP_MULTIPLIER" ]]; then
    echo "Usage: $0 <port> <tcp|udp> <limit> <burst> <blacklist_seconds> <max_conns> <udp_multiplier>"
    exit 1
fi

LOCK_FILE="/var/lock/nftables.lock"
exec 200>"$LOCK_FILE"
flock -x -w 10 200 || { echo "Could not acquire lock, exiting"; exit 1; }

NFT_DIR="/etc/nftables.d"
mkdir -p "$NFT_DIR"
PORT_FILE="$NFT_DIR/10-ddos-${PROTOCOL}-${PORT}.nft"
CHAIN_NAME="game_port_${PROTOCOL}_${PORT}"

if [ "$PROTOCOL" == "tcp" ]; then
    TCP_BAN_LIMIT=$((LIMIT * 10))
    TCP_BAN_BURST=$((BURST * 5))

    read -r -d '' RULES <<EOF || true
        # 1. HARD BAN: Socket Exhaustion (Anti-Bot)
        meta nfproto ipv4 tcp dport ${PORT} ct state new ct count over ${MAX_CONNS} log prefix "[DDoS-TCP-MaxConn] " counter add @blacklist { ip saddr } drop
        meta nfproto ipv6 tcp dport ${PORT} ct state new ct count over ${MAX_CONNS} log prefix "[DDoS-TCP-MaxConn] " counter add @blacklist6 { ip6 saddr } drop

        # 2. HARD BAN: Volumetric Flood (Anti-SynFlood)
        meta nfproto ipv4 tcp dport ${PORT} ct state new limit rate over ${TCP_BAN_LIMIT}/second burst ${TCP_BAN_BURST} packets log prefix "[DDoS-TCP-Flood] " counter add @blacklist { ip saddr } drop
        meta nfproto ipv6 tcp dport ${PORT} ct state new limit rate over ${TCP_BAN_LIMIT}/second burst ${TCP_BAN_BURST} packets log prefix "[DDoS-TCP-Flood] " counter add @blacklist6 { ip6 saddr } drop

        # 3. SOFT THROTTLE: Normal limit (drop excess, never ban — players can reconnect)
        tcp dport ${PORT} ct state new limit rate over ${LIMIT}/second burst ${BURST} packets counter drop
EOF
else
    EXTREME_LIMIT=$((LIMIT * UDP_MULTIPLIER))
    EXTREME_BURST=$((BURST * UDP_MULTIPLIER))

    read -r -d '' RULES <<EOF || true
        # 1. HARD BAN: Extreme volumetric flood
        meta nfproto ipv4 udp dport ${PORT} limit rate over ${EXTREME_LIMIT}/second burst ${EXTREME_BURST} packets log prefix "[DDoS-UDP-Flood] " counter add @blacklist { ip saddr } drop
        meta nfproto ipv6 udp dport ${PORT} limit rate over ${EXTREME_LIMIT}/second burst ${EXTREME_BURST} packets log prefix "[DDoS-UDP-Flood] " counter add @blacklist6 { ip6 saddr } drop

        # 2. SOFT THROTTLE: Normal rate limit
        udp dport ${PORT} limit rate over ${LIMIT}/second burst ${BURST} packets counter drop
EOF
fi

read -r -d '' MAIN_CONFIG <<EOF || true
table inet filter {
    chain ${CHAIN_NAME} {
    }
}

flush chain inet filter ${CHAIN_NAME}

table inet filter {
    chain ${CHAIN_NAME} {
${RULES}
    }
}
EOF

read -r -d '' JUMP_CONFIG <<EOF || true
table inet filter {
    chain raw_checks {
        iifname "eth0" ${PROTOCOL} dport ${PORT} jump ${CHAIN_NAME}
    }
}
EOF

echo "$MAIN_CONFIG" > "$PORT_FILE"
echo "$JUMP_CONFIG" >> "$PORT_FILE"

JUMP_RULE="iifname \"eth0\" ${PROTOCOL} dport ${PORT} jump ${CHAIN_NAME}"

if nft list chain inet filter raw_checks | grep -qF "$JUMP_RULE"; then
    echo "$MAIN_CONFIG" | nft -f -
    echo "[✓] Updated ${PROTOCOL^^} rules for ${PORT} (jump already exists)"
else
    nft -f "$PORT_FILE"
    echo "[✓] Created ${PROTOCOL^^} rules and jump for ${PORT}"
fi

DDOS_EOF
chmod +x {{UTILITY_SCRIPTS}}/{{DDOS_PROTECTION}}
""".Replace("\r\n", "\n");
        }

        /// <summary>
        /// Returns the command line to execute the port-specific DDoS protection rules deletion script.
        /// </summary>
        /// <param name="Ports">The space-separated list of ports to remove protection from.</param>
        /// <returns>A command string to run the teardown script.</returns>
        public static string DeleteDDosProtection(string Ports)
        {
            return $"{UTILITY_SCRIPTS}/{DELETE_DDOS_PROTECTION} {Ports}";
        }

        /// <summary>
        /// Generates the shell script that tears down the DDoS rules and nftables chains for the specified ports.
        /// </summary>
        /// <returns>A string containing the cleanup script.</returns>
        public static string DeleteDDosProtectionRulesScript()
        {
            return $$"""
cat <<'EOF' > {{UTILITY_SCRIPTS}}/{{DELETE_DDOS_PROTECTION}}
#!/bin/bash
set -eu

# Usage: ./delete_ddos_protection.sh <port1> <port2> ...

LOCK_FILE="/var/lock/nftables.lock"
exec 200>"$LOCK_FILE"
flock -x -w 10 200 || { echo "Could not acquire lock on nftables, exiting"; exit 1; }

NFT_DIR="/etc/nftables.d"

if [ "$#" -eq 0 ]; then
    echo "Usage: $0 <port1> [port2] ..."
    exit 1
fi

echo "[i] Starting cleanup for ports: $*"

for PORT in "$@"; do
    for PROTO in tcp udp; do
        CHAIN_NAME="game_port_${PROTO}_${PORT}"
        FILE_NAME="$NFT_DIR/10-ddos-${PROTO}-${PORT}.nft"

        # 1. Remove Jump Rule
        HANDLE=$(nft -a list chain inet filter raw_checks \
            | grep "jump ${CHAIN_NAME}" \
            | grep -Po 'handle \K[0-9]+' || true)

        if [ ! -z "$HANDLE" ]; then
            for h in $HANDLE; do
                nft delete rule inet filter raw_checks handle "$h"
                echo "[+] Removed jump rule for ${PROTO}/${PORT} (Handle $h)"
            done
        fi

        # 2. Remove Chain
        nft flush chain inet filter $CHAIN_NAME 2>/dev/null || true
        nft delete chain inet filter $CHAIN_NAME 2>/dev/null || true

        # 3. Remove File
        if [ -f "$FILE_NAME" ]; then
            rm -f "$FILE_NAME"
            echo "[✓] Deleted config file: $FILE_NAME"
        fi
    done
done

echo "[✓] Cleanup complete."
EOF

chmod +x {{UTILITY_SCRIPTS}}/{{DELETE_DDOS_PROTECTION}}
""".Replace("\r\n", "\n");
        }

        /// <summary>
        /// Deploys ray-xdp-sync.sh as a systemd service (2-second loop).
        ///
        /// Ban/Unban pipeline:
        ///   nftables @blacklist set has built-in 300s timeout (entries auto-expire).
        ///   This daemon reads the live set every 2s and:
        ///     - ADDs new banned IPs to the XDP hardware map  (xdp-filter ip -m src $ip)
        ///     - REMOVEs expired IPs from XDP hardware map    (xdp-filter ip -r -m src $ip)
        /// </summary>
        /// <returns>A string containing the bash command to deploy the daemon and systemd service.</returns>
        public static string DeployTelemetryAndDdosDaemon()
        {
            return $$"""
echo "[i] Deploying Real-Time XDP Sync Daemon..."

DAEMON_SCRIPT="/usr/local/bin/ray-xdp-sync.sh"
cat << 'EOF' > "$DAEMON_SCRIPT"
#!/bin/bash
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

while true; do
    # STEP 1: READ SOFTWARE BLACKLIST
    NFT_IPS=$(nft list set inet filter blacklist 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || echo "")
    NFT_IPS6=$(nft list set inet filter blacklist6 2>/dev/null \
        | awk '{for(i=1;i<=NF;i++) if ($i ~ /^[0-9a-fA-F:]+:[0-9a-fA-F:]+$/) print $i}' \
        | grep -v '^:' || echo "")

    ALL_NFT_IPS=$(printf '%s\n%s' "$NFT_IPS" "$NFT_IPS6" | grep -v '^$')

    # STEP 2: HARDWARE SYNC
    if command -v xdp-loader >/dev/null 2>&1 && xdp-loader status eth0 2>/dev/null | grep -q "xdp_dispatcher"; then
        XDP_RAW=$(xdp-filter status 2>/dev/null | awk '/Filtered IP/{y=1;next}y')
        XDP_IPS=$(echo "$XDP_RAW"  | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || echo "")
        XDP_IPS6=$(echo "$XDP_RAW" | awk '{for(i=1;i<=NF;i++) if ($i ~ /^[0-9a-fA-F:]+:[0-9a-fA-F:]+$/) print $i}' \
            | grep -v '^:' || echo "")
        ALL_XDP_IPS=$(printf '%s\n%s' "$XDP_IPS" "$XDP_IPS6" | grep -v '^$')

        # BAN: in nftables but not yet in XDP hardware
        for ip in $ALL_NFT_IPS; do
            if ! echo "$ALL_XDP_IPS" | grep -qF "$ip"; then
                xdp-filter ip -m src "$ip" >/dev/null 2>&1 || true
            fi
        done

        # UNBAN: expired from nftables (300s timeout), still in XDP hardware
        for ip in $ALL_XDP_IPS; do
            if ! echo "$ALL_NFT_IPS" | grep -qF "$ip"; then
                xdp-filter ip -r -m src "$ip" >/dev/null 2>&1 || true
            fi
        done
    fi

    sleep 2
done
EOF

chmod +x "$DAEMON_SCRIPT"

cat << 'EOF' > /etc/systemd/system/ray-xdp-sync.service
[Unit]
Description=Real-Time XDP Sync
After=network.target nftables.service docker.service

[Service]
Type=simple
ExecStart=/usr/local/bin/ray-xdp-sync.sh
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ray-xdp-sync.service
systemctl restart ray-xdp-sync.service

echo "[✓] Real-Time XDP Sync Daemon deployed and running."
""".Replace("\r\n", "\n");
        }

        /// <summary>
        /// Generates the command script to load or unload the eBPF/XDP filter on the eth0 interface, falling back to SKB/generic mode if native is unsupported.
        /// </summary>
        /// <param name="useXdp">true = load xdp-filter, false = unload</param>
        /// <returns>A string containing the script to configure XDP protection.</returns>
        public static string ConfigureXdpProtection(bool useXdp)
        {
            if (useXdp)
            {
                return $$"""
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

echo "[i] Configuring eBPF/XDP DDoS Protection..."

HELP_OUTPUT="$(xdp-filter load -h 2>&1 || xdp-filter --help 2>&1)"

if echo "$HELP_OUTPUT" | grep -qE '\bskb\b'; then
    GENERIC_MODE="skb"
else
    GENERIC_MODE="generic"
fi

echo "[i] Detected fallback mode: $GENERIC_MODE"

if xdp-loader status eth0 2>/dev/null | grep -q "xdp_dispatcher"; then
    echo "[✓] xdp-filter already running."
    exit 0
fi

echo "[i] Attempting Native XDP (driver-level)..."

if xdp-filter load eth0 -f ipv4,ipv6 --mode native; then
    echo "[✓] Attached Native XDP filter."
    exit 0
fi

echo "[!] Native attach failed. Falling back to $GENERIC_MODE..."
xdp-filter unload eth0 2>/dev/null || true

if xdp-filter load eth0 -f ipv4,ipv6 --mode "$GENERIC_MODE"; then
    echo "[✓] Attached $GENERIC_MODE XDP filter (kernel-level fallback)."
    exit 0
fi

echo "[✗] CRITICAL: Failed to attach XDP in both native and $GENERIC_MODE modes."
exit 1
""".Replace("\r\n", "\n");
            }
            else
            {
                return $$"""
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
echo "[i] Disabling eBPF/XDP DDoS Protection..."

if xdp-loader status eth0 2>/dev/null | grep -q "xdp_dispatcher"; then
    echo "[i] Unloading xdp-filter from eth0..."
    xdp-loader unload eth0 --all || true
    echo "[✓] eBPF/XDP filter unloaded."
else
    echo "[i] xdp-filter was not loaded."
fi
""".Replace("\r\n", "\n");
            }
        }

        /// <summary>
        /// Returns the command line to execute the passive firewall garbage collection script.
        /// </summary>
        /// <param name="authorizedPairs">A space-separated list of proto:port pairs that are currently authorized.</param>
        /// <returns>A command string to execute the GC script.</returns>
        public static string GarbageCollectNft(string authorizedPairs)
        {
            return $"{UTILITY_SCRIPTS}/{GARBAGE_COLLECT_NFT} {authorizedPairs}";
        }

        /// <summary>
        /// Generates the script that scans and purges orphaned DDoS protection chains/files for ports no longer in use.
        /// </summary>
        /// <returns>A string containing the garbage collection script.</returns>
        public static string GarbageCollectNftRulesScript()
        {
            return $$"""
cat <<'EOF' > {{UTILITY_SCRIPTS}}/{{GARBAGE_COLLECT_NFT}}
#!/bin/bash
set -eu

# Usage: ./garbage_collect_nft.sh <proto:port1> <proto:port2> ...
# Purges orphaned DDoS protection chains for ports no longer in use.

AUTHORIZED_PAIRS=("${@}")
NFT_DIR="/etc/nftables.d"
LOCK_FILE="/var/lock/nftables.lock"

exec 200>"$LOCK_FILE"
flock -x -w 10 200 || { echo "Could not acquire lock, exiting"; exit 1; }

cd "$NFT_DIR" || exit 0

echo "[i] Starting Firewall Garbage Collection (Artifact Purge)..."

for file in 10-ddos-*.nft; do
    [[ -e "$file" ]] || continue

    PROTO=$(echo "$file" | cut -d'-' -f3)
    PORT=$(echo "$file" | cut -d'-' -f4 | cut -d'.' -f1)
    PAIR="${PROTO}:${PORT}"
    is_authorized=false

    for authorized in "${AUTHORIZED_PAIRS[@]}"; do
        if [[ "$PAIR" == "$authorized" ]]; then
            is_authorized=true
            break
        fi
    done

    if [ "$is_authorized" = false ]; then
        echo "[!] Purging orphaned firewall artifact: $file"

        CHAIN_NAME="game_port_${PROTO}_${PORT}"

        HANDLE=$(nft -a list chain inet filter raw_checks \
            | grep "jump ${CHAIN_NAME}" \
            | grep -Po 'handle \K[0-9]+' || true)

        if [ ! -z "$HANDLE" ]; then
            for h in $HANDLE; do
                nft delete rule inet filter raw_checks handle "$h"
                echo "[+] Removed orphaned jump rule for ${PAIR} (Handle $h)"
            done
        fi

        nft flush chain inet filter "$CHAIN_NAME" 2>/dev/null || true
        nft delete chain inet filter "$CHAIN_NAME" 2>/dev/null || true

        rm -f "$file"
    fi
done

echo "[✓] Cleanup complete."
EOF

chmod +x {{UTILITY_SCRIPTS}}/{{GARBAGE_COLLECT_NFT}}
""".Replace("\r\n", "\n");
        }

        /// <summary>
        /// Generates the comprehensive kernel provisioning and software installation script, including UFW eradication, Docker setup, Node.js installation, xdp-tools deployment, and kernel hardening (sysctl configuration).
        /// </summary>
        /// <param name="isInternalTask">true = web/API node (skip heavy UDP buffers)</param>
        /// <returns>A string containing the provisioning script.</returns>
        public static string BaseConfigurationAndPackages(bool isInternalTask)
        {
            return $$$"""
export DEBIAN_FRONTEND=noninteractive && \
sudo apt-get update -yq && \
sudo apt-get install -yq \
    apt-transport-https ca-certificates curl software-properties-common bc \
    nodejs npm net-tools certbot python3-certbot-dns-cloudflare rsnapshot \
    wireguard nftables jq apache2-utils fireqos ipset unattended-upgrades && \

# Install Docker
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor --batch --yes -o /usr/share/keyrings/docker-archive-keyring.gpg && \
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null && \
sudo apt-get update -yq && \
sudo apt-get install -yq docker-ce docker-ce-cli containerd.io docker-compose docker-compose-plugin && \

# Install yq (Idempotent)
if [ ! -f /usr/bin/yq ]; then
    wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -O /usr/bin/yq && \
    sudo chmod +x /usr/bin/yq
fi

# Node.js Stable via 'n'
sudo npm install -g n && \
sudo n stable && \
sudo npm i -g gamedig && \

# ============================================================
# FIREWALL: UFW ERADICATION
# UFW is purged to protect native nftables hooks.
#
# Why: (1) Kernel hook collisions with Docker Swarm prerouting.
#      (2) UFW service restarts silently flush the DDoS @blacklist
#          sets — destroying the stateful ban list in memory.
# ============================================================
echo "[i] Purging UFW..."

[ -f /etc/default/ufw ] && sudo sed -i 's/DEFAULT_FORWARD_POLICY="ACCEPT"/DEFAULT_FORWARD_POLICY="DROP"/' /etc/default/ufw || true
command -v ufw >/dev/null 2>&1 && sudo ufw --force disable || true
sudo systemctl stop ufw    2>/dev/null || true
sudo systemctl disable ufw 2>/dev/null || true
sudo systemctl mask ufw    2>/dev/null || true
sudo systemctl enable nftables 2>/dev/null || true

echo "[✓] UFW neutralized. Active nftables ruleset preserved in memory."

# ============================================================
# eBPF / XDP INSTALLATION (OS-Agnostic & Idempotent)
# Fast path : apt        (Ubuntu 24.04+)
# Fallback  : compile v1.4.2 from source (Ubuntu 22.04)
# ============================================================
if ! command -v xdp-filter >/dev/null 2>&1; then
    echo "[i] Checking for native xdp-tools package (Ubuntu 24.04+)..."
    sudo add-apt-repository universe -y >/dev/null 2>&1 || true
    sudo apt-get update -yq

    if sudo apt-get install -yq xdp-tools; then
        echo "[✓] xdp-tools installed via apt (Modern OS detected)."
    else
        echo "[i] Native package unavailable (Ubuntu 22.04). Compiling from source..."

        sudo apt-get install -yq \
            build-essential pkg-config m4 clang llvm gcc-multilib \
            libelf-dev libpcap-dev zlib1g-dev linux-headers-$(uname -r) \
            git linux-tools-common linux-tools-$(uname -r)

        sudo apt-get remove -yq libbpf-dev || true

        cd /tmp
        rm -rf xdp-tools
        git clone -b v1.4.2 --recurse-submodules https://github.com/xdp-project/xdp-tools.git
        cd xdp-tools
        ./configure
        make
        sudo make install

        cd /tmp && rm -rf xdp-tools
        echo "[✓] xdp-tools compiled and installed from source."
    fi
else
    echo "[✓] xdp-tools already installed."
fi

# ============================================================
# KERNEL HARDENING — sysctl.d/99-zz-node.conf
# Written (not appended) for idempotency — no config drift.
# ============================================================
sudo mkdir -p /etc/sysctl.d && \
sudo cat <<EOF | sudo tee /etc/sysctl.d/99-zz-node.conf

# TCP Handshake Hardening
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 10000
net.ipv4.tcp_synack_retries = 3
net.ipv4.tcp_syn_retries = 3
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Connection Tracking (The Memory Shield)
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 600
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 10
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 10

# Network Performance
net.core.somaxconn = 32768
net.ipv4.ip_local_port_range = 1024 65535

# BBR Congestion Control
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF

# Fix boot race: load nf_conntrack BEFORE sysctl applies
grep -qxF "nf_conntrack" /etc/modules || echo "nf_conntrack" | sudo tee -a /etc/modules

IS_INTERNAL_TASK={{{isInternalTask.ToString().ToLower()}}}

if [ "$IS_INTERNAL_TASK" != "true" ]; then
    echo "Game Node detected. Appending heavy UDP/TCP kernel buffers..."
    sudo cat <<EOF | sudo tee -a /etc/sysctl.d/99-zz-node.conf

# UDP/TCP Buffer Expansion (Game Server Payload Protection)
net.core.rmem_max     = 16777216
net.core.wmem_max     = 16777216
net.core.rmem_default = 16777216
net.core.wmem_default = 16777216
EOF
else
    echo "Web/API Node detected. Skipping heavy game buffer allocation."
fi

sudo sysctl --system && \

# ============================================================
# SYSTEM TWEAKS
# ============================================================
grep -qxF "alias rm='rm --preserve-root'" ~/.bashrc || echo "alias rm='rm --preserve-root'" >> ~/.bashrc && \
docker info --format '{{.Swarm.LocalNodeState}}' | grep -q inactive && sudo docker swarm init || true && \
echo 'unattended-upgrades unattended-upgrades/enable_auto_updates boolean true' | sudo debconf-set-selections && \

echo "[✓] Base configuration complete (nftables + eBPF active)."
""".Replace("\r\n", "\n");
        }
    }
}