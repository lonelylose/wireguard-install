#!/bin/bash

# ---------------------------------------------------------
# WireGuard Install Script (Multi-Interface + Hybrid OS Fix)
# 
# Features:
# 1. Fix for Debian Testing/Unstable/Hybrid empty VERSION_ID
# 2. Support for creating multiple WireGuard interfaces (wg0, wg1...)
# 3. Independent MTU/Port/Subnet settings per interface
# ---------------------------------------------------------

RED='\033[0;31m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

function is_root() {
	if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		exit 1
	fi
}

function check_virt() {
	if [ "$(systemd-detect-virt)" == "openvz" ]; then
		echo "OpenVZ is not supported"
		exit 1
	fi
	if [ "$(systemd-detect-virt)" == "lxc" ]; then
		echo "LXC is not supported (yet)."
		exit 1
	fi
}

function check_os() {
	if [[ -e /etc/os-release ]]; then
		source /etc/os-release
	else
		echo "Error: /etc/os-release not found."
		exit 1
	fi

	if [[ "$ID" == "debian" || "$ID_LIKE" == "debian" ]]; then
		os="debian"
		if [[ -n "$VERSION_ID" ]]; then
			os_version="$VERSION_ID"
		else
			if [[ -e /etc/debian_version ]]; then
				raw_ver=$(head -n1 /etc/debian_version)
				if [[ "$raw_ver" =~ ^[0-9]+ ]]; then
					os_version=$(echo "$raw_ver" | cut -d. -f1)
				elif [[ "$raw_ver" == *"sid"* || "$raw_ver" == *"testing"* ]]; then
					echo -e "${ORANGE}Detected Debian Testing/Unstable/Hybrid. Forcing version compatibility.${NC}"
					os_version=12 
				else
					os_version=12 
				fi
			else
				os_version=12 
			fi
		fi
	elif [[ "$ID" == "ubuntu" ]]; then
		os="ubuntu"
		os_version="$VERSION_ID"
	elif [[ "$ID" == "fedora" ]]; then
		os="fedora"
		os_version="$VERSION_ID"
	elif [[ "$ID" == "centos" ]] || [[ "$ID" == "almalinux" ]] || [[ "$ID" == "rocky" ]]; then
		os="centos"
		os_version="$VERSION_ID"
	elif [[ "$ID" == "arch" ]] || [[ "$ID" == "archarm" ]]; then
		os="arch"
	else
		echo "This script does not support the OS detected: $ID"
		exit 1
	fi

	if [[ "$os" == "ubuntu" && "$os_version" < 18.04 ]]; then
		echo "Ubuntu 18.04 or higher is required."
		exit 1
	fi

	if [[ "$os" == "debian" ]]; then
        safe_version=${os_version%%.*} 
        if [[ -z "$safe_version" ]] || ! [[ "$safe_version" =~ ^[0-9]+$ ]]; then
            echo -e "${ORANGE}Warning: Rolling/Sid detected. Assuming compatible.${NC}"
        elif [[ "$safe_version" -lt 10 ]]; then
            echo "Debian 10 or higher is required."
            exit 1
        fi
	fi

	if [[ "$os" == "fedora" && "$os_version" < 32 ]]; then
		echo "Fedora 32 or higher is required."
		exit 1
	fi

	if [[ "$os" == "centos" && "$os_version" < 7 ]]; then
		echo "CentOS 7 or higher is required."
		exit 1
	fi
}

function install_packages() {
    # Only install if not present to save time
    if ! command -v wg &> /dev/null; then
        echo "Installing WireGuard tools..."
        if [ "$os" == "centos" ]; then
            yum install -y epel-release
            yum install -y wireguard-tools iptables
        elif [ "$os" == "fedora" ]; then
            dnf install -y wireguard-tools iptables
        elif [ "$os" == "debian" ] || [ "$os" == "ubuntu" ]; then
            apt-get update
            apt-get install -y wireguard iptables
        elif [ "$os" == "arch" ]; then
            pacman -S --noconfirm wireguard-tools iptables
        fi
    fi
    
    # Ensure directory exists
	mkdir -p /etc/wireguard >/dev/null 2>&1
    chmod 600 -R /etc/wireguard/
}

function get_public_ip() {
	ip=$(curl -s https://api.ipify.org || curl -s https://ipv4.icanhazip.com)
    if [[ -z "$ip" ]]; then
        ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
    fi
}

function get_next_interface_name() {
    local i=0
    while [[ -e "/etc/wireguard/wg${i}.conf" ]]; do
        ((i++))
    done
    echo "wg${i}"
}

function setup_new_interface() {
    echo ""
    echo -e "${GREEN}Setup New WireGuard Interface${NC}"
    echo ""

    # Auto-detect next available interface name
    DEFAULT_WG_NIC=$(get_next_interface_name)
    
    # Heuristics for default values to avoid collisions
    # Extract number from wgX
    local nic_num=${DEFAULT_WG_NIC//wg/}
    local default_port=$((51820 + nic_num))
    local default_subnet=$((66 + nic_num))
    local default_ipv6_subnet=$((42 + nic_num))

	SERVER_PUB_IP=$ip
	read -p "IPv4 or IPv6 public address: " -e -i "$SERVER_PUB_IP" SERVER_PUB_IP

	SERVER_PUB_NIC="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
	until [[ ${SERVER_PUB_NIC} != "" ]]; do
		echo "I couldn't detect your public network interface."
		read -p "Public interface: " -e SERVER_PUB_NIC
	done
	read -p "Public interface: " -e -i "$SERVER_PUB_NIC" SERVER_PUB_NIC

	read -p "WireGuard interface name: " -e -i "$DEFAULT_WG_NIC" SERVER_WG_NIC

	SERVER_WG_IPV4="10.66.${default_subnet}.1"
	read -p "Server's WireGuard IPv4: " -e -i "$SERVER_WG_IPV4" SERVER_WG_IPV4

	SERVER_WG_IPV6="fd42:42:${default_ipv6_subnet}::1"
	read -p "Server's WireGuard IPv6: " -e -i "$SERVER_WG_IPV6" SERVER_WG_IPV6

	read -p "Server's WireGuard port: " -e -i "$default_port" SERVER_PORT
    
    # MTU Selection
    DEFAULT_MTU=1420
    read -p "Interface MTU (Default 1420): " -e -i "$DEFAULT_MTU" SERVER_MTU

	CLIENT_DNS_1="8.8.8.8"
	read -p "First DNS resolver to use for the clients: " -e -i "$CLIENT_DNS_1" CLIENT_DNS_1

	CLIENT_DNS_2="8.8.4.4"
	read -p "Second DNS resolver to use for the clients: " -e -i "$CLIENT_DNS_2" CLIENT_DNS_2

	# Generate key pair for the server
	SERVER_PRIV_KEY=$(wg genkey)
	SERVER_PUB_KEY=$(echo "$SERVER_PRIV_KEY" | wg pubkey)

	# Save WireGuard settings
	echo "Saving config to /etc/wireguard/$SERVER_WG_NIC.conf..."
	cat > "/etc/wireguard/$SERVER_WG_NIC.conf" <<EOF
[Interface]
Address = $SERVER_WG_IPV4/24,$SERVER_WG_IPV6/64
ListenPort = $SERVER_PORT
PrivateKey = $SERVER_PRIV_KEY
MTU = $SERVER_MTU
PostUp = iptables -A FORWARD -i $SERVER_WG_NIC -j ACCEPT; iptables -t nat -A POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE; ip6tables -A FORWARD -i $SERVER_WG_NIC -j ACCEPT; ip6tables -t nat -A POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE
PostDown = iptables -D FORWARD -i $SERVER_WG_NIC -j ACCEPT; iptables -t nat -D POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE; ip6tables -D FORWARD -i $SERVER_WG_NIC -j ACCEPT; ip6tables -t nat -D POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE

EOF

	# Enable routing (Idempotent)
	echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/wg.conf
	echo "net.ipv6.conf.all.forwarding = 1" >> /etc/sysctl.d/wg.conf
	sysctl --system &> /dev/null

	systemctl start "wg-quick@$SERVER_WG_NIC"
	systemctl enable "wg-quick@$SERVER_WG_NIC"

    echo ""
    echo -e "${GREEN}Interface $SERVER_WG_NIC created successfully!${NC}"
    
    # Ask to add a client immediately
    read -p "Do you want to add a client to $SERVER_WG_NIC now? [y/n]: " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        add_client_to_interface "$SERVER_WG_NIC"
    fi
}

function add_client_to_interface() {
    local WG_NIC="$1"
    local CONF_FILE="/etc/wireguard/${WG_NIC}.conf"

    if [[ ! -f "$CONF_FILE" ]]; then
        echo "Error: Config file for $WG_NIC not found!"
        return
    fi

    echo ""
    echo -e "Adding new user to ${GREEN}${WG_NIC}${NC}"

    # Extract Server Info from Config
    # We need: Server Public Key (calculated from Private), Server Port, Server Internal IP structure
    
    local PRIV_KEY=$(grep 'PrivateKey' "$CONF_FILE" | awk '{print $3}')
    if [[ -z "$PRIV_KEY" ]]; then
        echo "Error: Could not find PrivateKey in $CONF_FILE"
        return
    fi
    local SERVER_PUB_KEY=$(echo "$PRIV_KEY" | wg pubkey)
    
    local SERVER_PORT=$(grep 'ListenPort' "$CONF_FILE" | awk '{print $3}')
    
    # Detect Server IP/IPv6 Subnet base to calculate next client IP
    # This is tricky with grep. We assume the standard format generated by this script.
    # Format: Address = 10.66.66.1/24,fd42:42:42::1/64
    # Get the IPv4 part:
    local BASE_IP_LINE=$(grep 'Address' "$CONF_FILE" | head -n 1)
    # Regex to find the IPv4 base (first 3 octets)
    if [[ $BASE_IP_LINE =~ ([0-9]+\.[0-9]+\.[0-9]+)\. ]]; then
        local IPV4_BASE="${BASH_REMATCH[1]}"
    else
        echo "Error: Could not parse IPv4 base from config. Please edit manually."
        return
    fi
    
    # Regex to find IPv6 base (up to the ::)
    # Assumes format fd42:42:42::1 or fd42:42:42:1::1 etc. 
    # A simplified approach for the script generated configs:
    local IPV6_BASE="fd42:42:42" # Fallback
    if [[ $BASE_IP_LINE =~ (fd[0-9a-f:]+)::[0-9]+ ]]; then
        IPV6_BASE="${BASH_REMATCH[1]}"
    fi

	CLIENT_NAME="client"
	read -p "Client name: " -e -i "$CLIENT_NAME" CLIENT_NAME

	CLIENT_PRIV_KEY=$(wg genkey)
	CLIENT_PUB_KEY=$(echo "$CLIENT_PRIV_KEY" | wg pubkey)
	CLIENT_PRE_SHARED_KEY=$(wg genpsk)

	# Calculate next available IP octet
	OCTET=2
    while grep -q "${IPV4_BASE}.${OCTET}" "$CONF_FILE"; do
        ((OCTET++))
    done
    
    CLIENT_WG_IPV4="${IPV4_BASE}.${OCTET}"
    CLIENT_WG_IPV6="${IPV6_BASE}::${OCTET}"

	# Append peer to server config
	cat >> "$CONF_FILE" <<EOF

[Peer]
PublicKey = $CLIENT_PUB_KEY
PresharedKey = $CLIENT_PRE_SHARED_KEY
AllowedIPs = $CLIENT_WG_IPV4/32,$CLIENT_WG_IPV6/128
EOF

	# Restart wireguard interface to apply changes
	systemctl restart "wg-quick@$WG_NIC"

    # Detect Endpoint IP
    # If we have run this script before in this session, we might have SERVER_PUB_IP.
    # If not, we need to detect it.
    if [[ -z "$SERVER_PUB_IP" ]]; then
        get_public_ip
        SERVER_PUB_IP=$ip
    fi

    # Ask user to confirm Endpoint IP (in case of multiple IPs or NAT)
    read -p "Endpoint IP/Domain for client config: " -e -i "$SERVER_PUB_IP" CONFIRM_ENDPOINT

	# Create client file
    CLIENT_FILE="${HOME}/${WG_NIC}-client-${CLIENT_NAME}.conf"
	echo "[Interface]
PrivateKey = $CLIENT_PRIV_KEY
Address = $CLIENT_WG_IPV4/24,$CLIENT_WG_IPV6/64
DNS = 8.8.8.8,8.8.4.4

[Peer]
PublicKey = $SERVER_PUB_KEY
PresharedKey = $CLIENT_PRE_SHARED_KEY
Endpoint = $CONFIRM_ENDPOINT:$SERVER_PORT
AllowedIPs = 0.0.0.0/0,::/0" > "$CLIENT_FILE"

    # Qrencode if available
    if command -v qrencode &> /dev/null; then
        echo ""
        qrencode -t ansiutf8 < "$CLIENT_FILE"
        echo ""
    fi

	echo "Client config saved to: $CLIENT_FILE"
}

function select_interface_menu() {
    # Find all conf files
    mapfile -t configs < <(ls /etc/wireguard/*.conf 2>/dev/null)
    
    if [ ${#configs[@]} -eq 0 ]; then
        echo "No WireGuard interfaces found. Please create one first."
        return 1
    elif [ ${#configs[@]} -eq 1 ]; then
        # Only one, return it
        basename "${configs[0]}" .conf
    else
        echo "Multiple WireGuard interfaces detected:"
        local i=0
        for conf in "${configs[@]}"; do
            echo "$i) $(basename "$conf" .conf)"
            ((i++))
        done
        echo ""
        read -p "Select interface [0-$((i-1))]: " selection
        if [[ "$selection" =~ ^[0-9]+$ ]] && [ "$selection" -ge 0 ] && [ "$selection" -lt "$i" ]; then
            basename "${configs[$selection]}" .conf
        else
            echo "Invalid selection."
            return 1
        fi
    fi
}

# --- Main Logic ---

is_root
check_virt
check_os

# Check if any wireguard config exists
if ls /etc/wireguard/*.conf >/dev/null 2>&1; then
    # Menu Mode
	while :
	do
		clear
		echo "WireGuard Manager (Multi-Interface)"
        echo "OS: $os $os_version"
		echo ""
        echo -e "${ORANGE}0) Add a new wg tunnel (wg1, wg2...)${NC}"
		echo "1) Add a new user to an existing tunnel"
		echo "2) Revoke existing user (Manual)"
		echo "3) Remove WireGuard (Uninstall all)"
		echo "4) Exit"
		echo ""
		read -p "Select an option [0-4]: " option
		case $option in
            0)
                install_packages
                setup_new_interface
                read -p "Press any key to continue..."
                ;;
			1) 
                SELECTED_NIC=$(select_interface_menu)
                if [ $? -eq 0 ]; then
                    add_client_to_interface "$SELECTED_NIC"
                fi
                read -p "Press any key to continue..."
                ;;
			3) 
                read -p "Are you sure you want to remove WireGuard and ALL configs? [y/N]: " -n 1 -r
                echo ""
                if [[ $REPLY =~ ^[Yy]$ ]]; then
                    apt-get remove -y wireguard wireguard-tools
                    rm -rf /etc/wireguard
                    echo "WireGuard removed."
                    exit
                fi
                ;;
			4) exit;;
		esac
	done
else
    # First time setup
    echo "No existing WireGuard configuration found. Starting initial setup..."
    get_public_ip
    install_packages
	setup_new_interface
fi
```

### 新增功能说明：

1.  **菜单选项 0**:
    * 选择后，脚本会扫描 `/etc/wireguard/` 目录。
    * 如果已有 `wg0.conf`，它会建议创建 `wg1`。
    * 它会建议使用 **51821** 端口（如果是 wg2 则是 51822）。
    * 它会建议使用 **10.66.67.1** 网段（如果是 wg0 是 10.66.66.1）。
    * **增加了 MTU 设置**：在创建新隧道时，会询问你想要的 MTU（默认 1420），这样你就可以为 wg1 设置 1280 或其他数值来适应特定网络环境。

2.  **菜单选项 1 (Add User)**:
    * 如果你的系统里只有 `wg0`，它像以前一样直接添加。
    * 如果你有 `wg0` 和 `wg1`，它会列出列表让你选择：
        ```
        Multiple WireGuard interfaces detected:
        0) wg0
        1) wg1
        Select interface [0-1]:
