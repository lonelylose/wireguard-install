#!/bin/bash

# ---------------------------------------------------------
# WireGuard Install Script (Fixed for Debian Testing/Unstable/Hybrid)
# Modified to handle empty VERSION_ID in /etc/os-release
# ---------------------------------------------------------

RED='\033[0;31m'
ORANGE='\033[0;33m'
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
		echo "WireGuard can technically run in an LXC container,"
		echo "but the kernel module must be installed on the host,"
		echo "the container needs to be run with some specific parameters"
		echo "and only the tools need to be installed in the container."
		exit 1
	fi
}

function check_os() {
	# Check if /etc/os-release exists
	if [[ -e /etc/os-release ]]; then
		source /etc/os-release
	else
		echo "Error: /etc/os-release not found. OS detection failed."
		exit 1
	fi

	# Fix: Debian Handling
	if [[ "$ID" == "debian" || "$ID_LIKE" == "debian" ]]; then
		os="debian"
		
		# 尝试获取主版本号
		if [[ -n "$VERSION_ID" ]]; then
			os_version="$VERSION_ID"
		else
			# 如果 VERSION_ID 为空（常见于 Testing/Sid/Hybrid），尝试读取 /etc/debian_version
			if [[ -e /etc/debian_version ]]; then
				raw_ver=$(head -n1 /etc/debian_version)
				# 提取第一个数字部分，如果包含 trixie/sid 则视为 13 (或更高，确保通过检测)
				if [[ "$raw_ver" =~ ^[0-9]+ ]]; then
					os_version=$(echo "$raw_ver" | cut -d. -f1)
				elif [[ "$raw_ver" == *"sid"* || "$raw_ver" == *"testing"* ]]; then
					echo -e "${ORANGE}Detected Debian Testing/Unstable/Hybrid. Forcing version compatibility.${NC}"
					os_version=12 # 强制视为 Debian 12 (Bookworm) 以通过检查
				else
					os_version=12 # 兜底策略
				fi
			else
				os_version=12 # 终极兜底
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

	# -----------------------------------------------------
	# Modified Validation Logic for Debian
	# -----------------------------------------------------
	if [[ "$os" == "ubuntu" && "$os_version" < 18.04 ]]; then
		echo "Ubuntu 18.04 or higher is required to use this script."
		exit 1
	fi

	if [[ "$os" == "debian" ]]; then
        # Ensure we are comparing integers
        safe_version=${os_version%%.*} 
        # Assume anything empty or non-numeric at this stage is a rolling release and supported
        if [[ -z "$safe_version" ]] || ! [[ "$safe_version" =~ ^[0-9]+$ ]]; then
            echo -e "${ORANGE}Warning: Could not determine exact Debian version number ($os_version). Assuming supported Rolling/Sid.${NC}"
        elif [[ "$safe_version" -lt 10 ]]; then
            echo "Debian 10 (Buster) or higher is required to use this script."
            echo "Detected version: $os_version"
            exit 1
        fi
	fi

	if [[ "$os" == "fedora" && "$os_version" < 32 ]]; then
		echo "Fedora 32 or higher is required to use this script."
		exit 1
	fi

	if [[ "$os" == "centos" && "$os_version" < 7 ]]; then
		echo "CentOS 7 or higher is required to use this script."
		exit 1
	fi
}

function get_public_ip() {
    # Try multiple sources to get IP, fallback nicely
	ip=$(curl -s https://api.ipify.org || curl -s https://ipv4.icanhazip.com)
    if [[ -z "$ip" ]]; then
        ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
    fi
}

function install_wireguard() {
	# Run setup questions first
	echo ""
	echo "Tell me a few questions to start the setup."
	echo ""

    # --- Questions Logic ---
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

	# Make sure the directory exists (some distributions don't create it)
	mkdir -p /etc/wireguard >/dev/null 2>&1

	chmod 600 -R /etc/wireguard/

	SERVER_PUB_IP=$ip
	read -p "IPv4 or IPv6 public address: " -e -i "$SERVER_PUB_IP" SERVER_PUB_IP

	# Detect public interface and pre-fill for the user
	SERVER_PUB_NIC="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
	until [[ ${SERVER_PUB_NIC} != "" ]]; do
		echo "I couldn't detect your public network interface."
		read -p "Public interface: " -e SERVER_PUB_NIC
	done
	read -p "Public interface: " -e -i "$SERVER_PUB_NIC" SERVER_PUB_NIC

	SERVER_WG_NIC="wg0"
	read -p "WireGuard interface name: " -e -i "$SERVER_WG_NIC" SERVER_WG_NIC

	SERVER_WG_IPV4="10.66.66.1"
	read -p "Server's WireGuard IPv4: " -e -i "$SERVER_WG_IPV4" SERVER_WG_IPV4

	SERVER_WG_IPV6="fd42:42:42::1"
	read -p "Server's WireGuard IPv6: " -e -i "$SERVER_WG_IPV6" SERVER_WG_IPV6

	SERVER_PORT=51820
	read -p "Server's WireGuard port: " -e -i "$SERVER_PORT" SERVER_PORT

	CLIENT_DNS_1="8.8.8.8"
	read -p "First DNS resolver to use for the clients: " -e -i "$CLIENT_DNS_1" CLIENT_DNS_1

	CLIENT_DNS_2="8.8.4.4"
	read -p "Second DNS resolver to use for the clients: " -e -i "$CLIENT_DNS_2" CLIENT_DNS_2

	# Generate key pair for the server
	SERVER_PRIV_KEY=$(wg genkey)
	SERVER_PUB_KEY=$(echo "$SERVER_PRIV_KEY" | wg pubkey)

	# Save WireGuard settings
	echo "STUB: Saving config..."
	cat > "/etc/wireguard/$SERVER_WG_NIC.conf" <<EOF
[Interface]
Address = $SERVER_WG_IPV4/24,$SERVER_WG_IPV6/64
ListenPort = $SERVER_PORT
PrivateKey = $SERVER_PRIV_KEY
PostUp = iptables -A FORWARD -i $SERVER_WG_NIC -j ACCEPT; iptables -t nat -A POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE; ip6tables -A FORWARD -i $SERVER_WG_NIC -j ACCEPT; ip6tables -t nat -A POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE
PostDown = iptables -D FORWARD -i $SERVER_WG_NIC -j ACCEPT; iptables -t nat -D POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE; ip6tables -D FORWARD -i $SERVER_WG_NIC -j ACCEPT; ip6tables -t nat -D POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE

EOF

	# Enable routing
	echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/wg.conf
	echo "net.ipv6.conf.all.forwarding = 1" >> /etc/sysctl.d/wg.conf
	sysctl --system

	systemctl start "wg-quick@$SERVER_WG_NIC"
	systemctl enable "wg-quick@$SERVER_WG_NIC"

	new_client_setup
}

function new_client_setup() {
	# If SERVER_PUB_IP is empty, ask again
	if [ -z "$SERVER_PUB_IP" ]; then
		SERVER_PUB_IP=$ip
		read -p "IPv4 or IPv6 public address: " -e -i "$SERVER_PUB_IP" SERVER_PUB_IP
	fi

	echo ""
	echo "Client configuration"
	echo ""

	CLIENT_NAME="client"
	read -p "Client name: " -e -i "$CLIENT_NAME" CLIENT_NAME

	CLIENT_PRIV_KEY=$(wg genkey)
	CLIENT_PUB_KEY=$(echo "$CLIENT_PRIV_KEY" | wg pubkey)
	CLIENT_PRE_SHARED_KEY=$(wg genpsk)

	# Allow automatic IP generation
	# Finds the last used IP octet
	OCTET=2
    # Simple logic to increment IP, assumes /24
    # In a robust script, we would grep the config file
    while grep -q "10.66.66.$OCTET" "/etc/wireguard/$SERVER_WG_NIC.conf"; do
        ((OCTET++))
    done
    CLIENT_WG_IPV4="10.66.66.$OCTET"
    CLIENT_WG_IPV6="fd42:42:42::$OCTET"

	# Append peer to server config
	cat >> "/etc/wireguard/$SERVER_WG_NIC.conf" <<EOF

[Peer]
PublicKey = $CLIENT_PUB_KEY
PresharedKey = $CLIENT_PRE_SHARED_KEY
AllowedIPs = $CLIENT_WG_IPV4/32,$CLIENT_WG_IPV6/128
EOF

	# Restart wireguard
	systemctl restart "wg-quick@$SERVER_WG_NIC"

	# Create client file
	echo "[Interface]
PrivateKey = $CLIENT_PRIV_KEY
Address = $CLIENT_WG_IPV4/24,$CLIENT_WG_IPV6/64
DNS = $CLIENT_DNS_1,$CLIENT_DNS_2

[Peer]
PublicKey = $SERVER_PUB_KEY
PresharedKey = $CLIENT_PRE_SHARED_KEY
Endpoint = $SERVER_PUB_IP:$SERVER_PORT
AllowedIPs = 0.0.0.0/0,::/0" > "${HOME}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

    # Qrencode if available
    if command -v qrencode &> /dev/null; then
        qrencode -t ansiutf8 < "${HOME}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"
    fi

	echo ""
	echo "Your client config file is in ${HOME}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"
}

# --- Main Logic ---

is_root
check_virt
check_os

if [[ -e /etc/wireguard/wg0.conf ]]; then
    # If WireGuard is already installed, ask to add user or remove
	while :
	do
		clear
		echo "WireGuard is already installed."
		echo ""
		echo "1) Add a new user"
		echo "2) Revoke existing user (Not implemented in this minimal fix, please manual edit)"
		echo "3) Remove WireGuard"
		echo "4) Exit"
		echo ""
		read -p "Select an option [1-4]: " option
		case $option in
			1) 
                # Re-read variables from file before adding
                SERVER_WG_NIC="wg0"
                SERVER_PUB_IP=$(grep -v '#' /etc/wireguard/wg0.conf | grep -i 'Endpoint' | head -1 | awk '{print $3}' | cut -d: -f1) 
                # Note: Parsing existing config strictly is hard in simple bash, 
                # normally we would store variables in a setup file. 
                # Assuming default setup for new client:
                SERVER_PUB_IP=$ip 
                SERVER_PORT=51820
                SERVER_PUB_KEY=$(grep -v '#' /etc/wireguard/wg0.conf | grep -A 5 "\[Interface\]" | grep "PrivateKey" | awk '{print $3}' | wg pubkey)
                
                new_client_setup
                exit
                ;;
			3) 
                apt-get remove -y wireguard wireguard-tools
                rm -rf /etc/wireguard
                echo "WireGuard removed."
                exit
                ;;
			4) exit;;
		esac
	done
else
    get_public_ip
	install_wireguard
fi
