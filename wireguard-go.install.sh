#!/bin/bash

# ---------------------------------------------------------
# WireGuard-Go Install Script (Multi-Interface + LXC Supported)
# 
# Features:
# 1. Compiles and installs wireguard-go (Userspace implementation)
# 2. Fix for Debian Testing/Unstable/Hybrid empty VERSION_ID
# 3. Support for creating multiple WireGuard interfaces (wg0, wg1...)
# 4. Independent MTU/Port/Subnet settings per interface
# 5. Detailed multi-line iptables rules in config
# 6. Ability to delete specific interfaces
# 7. Perfect for LXC containers!
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
    local virt_type=$(systemd-detect-virt 2>/dev/null)
    
    if [ "$virt_type" == "lxc" ]; then
        echo -e "${GREEN}LXC container detected. wireguard-go is a perfect fit here!${NC}"
    elif [ "$virt_type" == "openvz" ]; then
        echo -e "${ORANGE}Warning: OpenVZ detected. wireguard-go might work if TUN is enabled.${NC}"
    fi

    # LXC/OpenVZ 跑 wireguard-go 的核心前提是必须有 TUN 设备
    if [ ! -c /dev/net/tun ]; then
        echo -e "${RED}Error: /dev/net/tun is missing or not a character device.${NC}"
        echo -e "在 LXC 容器中运行 wireguard-go 需要开启 TUN 权限。"
        echo -e "如果你使用的是 Proxmox VE (PVE):"
        echo -e "1. 去 PVE 网页端 -> 选择你的 LXC 容器 -> Options -> Features"
        echo -e "2. 勾选相关的权限 (通常 nesting=1 或是直接编辑 /etc/pve/lxc/xxx.conf 加入 lxc.cgroup2.devices.allow: c 10:200 rwm)"
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
    if ! command -v wg &> /dev/null || ! command -v wireguard-go &> /dev/null; then
        echo "Installing WireGuard-Go dependencies..."
        if [ "$os" == "centos" ]; then
            yum install -y epel-release
            yum install -y wireguard-tools iptables git make golang curl iproute
        elif [ "$os" == "fedora" ]; then
            dnf install -y wireguard-tools iptables git make golang curl iproute
        elif [ "$os" == "debian" ] || [ "$os" == "ubuntu" ]; then
            apt-get update
            apt-get install -y wireguard-tools iptables git make golang curl iproute2
        elif [ "$os" == "arch" ]; then
            pacman -S --noconfirm wireguard-tools iptables git make go curl iproute2
        fi

        if ! command -v wireguard-go &> /dev/null; then
            echo "Compiling wireguard-go from source..."
            local pwd_backup=$(pwd)
            cd /tmp
            rm -rf wireguard-go
            git clone https://git.zx2c4.com/wireguard-go
            cd wireguard-go
            make
            cp wireguard-go /usr/local/bin/
            chmod +x /usr/local/bin/wireguard-go
            cd "$pwd_backup"
            echo -e "${GREEN}wireguard-go compiled and installed successfully!${NC}"
        fi
    fi
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
    echo -e "${GREEN}Setup New WireGuard-Go Interface${NC}"
    echo ""

    DEFAULT_WG_NIC=$(get_next_interface_name)
    
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
    
    DEFAULT_MTU=1420
    read -p "Interface MTU (Default 1420): " -e -i "$DEFAULT_MTU" SERVER_MTU

    CLIENT_DNS_1="8.8.8.8"
    read -p "First DNS resolver to use for the clients: " -e -i "$CLIENT_DNS_1" CLIENT_DNS_1

    CLIENT_DNS_2="8.8.4.4"
    read -p "Second DNS resolver to use for the clients: " -e -i "$CLIENT_DNS_2" CLIENT_DNS_2

    SERVER_PRIV_KEY=$(wg genkey)
    SERVER_PUB_KEY=$(echo "$SERVER_PRIV_KEY" | wg pubkey)

    echo "Saving config to /etc/wireguard/$SERVER_WG_NIC.conf..."

    cat > "/etc/wireguard/$SERVER_WG_NIC.conf" <<EOF
[Interface]
Address = $SERVER_WG_IPV4/24,$SERVER_WG_IPV6/64
ListenPort = $SERVER_PORT
PrivateKey = $SERVER_PRIV_KEY
MTU = $SERVER_MTU
PostUp = iptables -I INPUT -p udp --dport $SERVER_PORT -j ACCEPT
PostUp = iptables -I FORWARD -i $SERVER_PUB_NIC -o $SERVER_WG_NIC -j ACCEPT
PostUp = iptables -I FORWARD -i $SERVER_WG_NIC -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE
PostUp = ip6tables -I INPUT -p udp --dport $SERVER_PORT -j ACCEPT
PostUp = ip6tables -I FORWARD -i $SERVER_WG_NIC -j ACCEPT
PostUp = ip6tables -t nat -A POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport $SERVER_PORT -j ACCEPT
PostDown = iptables -D FORWARD -i $SERVER_PUB_NIC -o $SERVER_WG_NIC -j ACCEPT
PostDown = iptables -D FORWARD -i $SERVER_WG_NIC -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE
PostDown = ip6tables -D INPUT -p udp --dport $SERVER_PORT -j ACCEPT
PostDown = ip6tables -D FORWARD -i $SERVER_WG_NIC -j ACCEPT
PostDown = ip6tables -t nat -D POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE

EOF

    echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/wg.conf
    echo "net.ipv6.conf.all.forwarding = 1" >> /etc/sysctl.d/wg.conf
    sysctl --system &> /dev/null

    systemctl start "wg-quick@$SERVER_WG_NIC"
    systemctl enable "wg-quick@$SERVER_WG_NIC"

    echo ""
    echo -e "${GREEN}Interface $SERVER_WG_NIC created successfully using wireguard-go!${NC}"
    
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
    
    local PRIV_KEY=$(grep 'PrivateKey' "$CONF_FILE" | awk '{print $3}')
    if [[ -z "$PRIV_KEY" ]]; then
        echo "Error: Could not find PrivateKey in $CONF_FILE"
        return
    fi
    local SERVER_PUB_KEY=$(echo "$PRIV_KEY" | wg pubkey)
    
    local SERVER_PORT=$(grep 'ListenPort' "$CONF_FILE" | awk '{print $3}')
    
    local BASE_IP_LINE=$(grep 'Address' "$CONF_FILE" | head -n 1)
    if [[ $BASE_IP_LINE =~ ([0-9]+\.[0-9]+\.[0-9]+)\. ]]; then
        local IPV4_BASE="${BASH_REMATCH[1]}"
    else
        echo "Error: Could not parse IPv4 base from config. Please edit manually."
        return
    fi
    
    local IPV6_BASE="fd42:42:42" 
    if [[ $BASE_IP_LINE =~ (fd[0-9a-f:]+)::[0-9]+ ]]; then
        IPV6_BASE="${BASH_REMATCH[1]}"
    fi

    CLIENT_NAME="client"
    read -p "Client name: " -e -i "$CLIENT_NAME" CLIENT_NAME

    CLIENT_PRIV_KEY=$(wg genkey)
    CLIENT_PUB_KEY=$(echo "$CLIENT_PRIV_KEY" | wg pubkey)
    CLIENT_PRE_SHARED_KEY=$(wg genpsk)

    OCTET=2
    while grep -q "${IPV4_BASE}.${OCTET}" "$CONF_FILE"; do
        ((OCTET++))
    done
    
    CLIENT_WG_IPV4="${IPV4_BASE}.${OCTET}"
    CLIENT_WG_IPV6="${IPV6_BASE}::${OCTET}"

    cat >> "$CONF_FILE" <<EOF

[Peer]
PublicKey = $CLIENT_PUB_KEY
PresharedKey = $CLIENT_PRE_SHARED_KEY
AllowedIPs = $CLIENT_WG_IPV4/32,$CLIENT_WG_IPV6/128
EOF

    systemctl restart "wg-quick@$WG_NIC"

    if [[ -z "$SERVER_PUB_IP" ]]; then
        get_public_ip
        SERVER_PUB_IP=$ip
    fi

    read -p "Endpoint IP/Domain for client config: " -e -i "$SERVER_PUB_IP" CONFIRM_ENDPOINT

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

    if command -v qrencode &> /dev/null; then
        echo ""
        qrencode -t ansiutf8 < "$CLIENT_FILE"
        echo ""
    fi

    echo "Client config saved to: $CLIENT_FILE"
}

function select_interface_menu() {
    local prompt="$1"
    mapfile -t configs < <(ls /etc/wireguard/*.conf 2>/dev/null)
    
    if [ ${#configs[@]} -eq 0 ]; then
        echo "No WireGuard interfaces found." >&2
        return 1
    elif [ ${#configs[@]} -eq 1 ]; then
        basename "${configs[0]}" .conf
    else
        echo "$prompt" >&2
        local i=0
        for conf in "${configs[@]}"; do
            echo "$i) $(basename "$conf" .conf)" >&2
            ((i++))
        done
        echo "" >&2
        read -p "Select interface [0-$((i-1))]: " selection
        
        if [[ "$selection" =~ ^[0-9]+$ ]] && [ "$selection" -ge 0 ] && [ "$selection" -lt "$i" ]; then
            basename "${configs[$selection]}" .conf
        else
            echo "Invalid selection." >&2
            return 1
        fi
    fi
}

function remove_interface() {
    echo ""
    echo -e "${RED}Delete a WireGuard Interface${NC}"
    
    SELECTED_NIC=$(select_interface_menu "Select interface to DELETE:")
    if [ $? -ne 0 ]; then
        return
    fi

    echo ""
    echo -e "${RED}WARNING: This will permanently delete $SELECTED_NIC and its configuration!${NC}"
    read -p "Are you sure? [y/N]: " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        systemctl stop "wg-quick@$SELECTED_NIC"
        systemctl disable "wg-quick@$SELECTED_NIC"
        
        rm "/etc/wireguard/$SELECTED_NIC.conf"
        rm -f "${HOME}/$SELECTED_NIC-client-"*.conf
        
        systemctl reset-failed "wg-quick@$SELECTED_NIC"
        systemctl daemon-reload
        
        echo "Interface $SELECTED_NIC removed and systemd cleaned."
    else
        echo "Aborted."
    fi
}

# --- Main Logic ---

is_root
check_virt
check_os

if ls /etc/wireguard/*.conf >/dev/null 2>&1; then
    while :
    do
        clear
        echo "WireGuard-Go Manager (LXC Edition)"
        echo "OS: $os $os_version"
        echo ""
        echo -e "${ORANGE}0) Add a new wg tunnel (wg1, wg2...)${NC}"
        echo "1) Add a new user to an existing tunnel"
        echo "2) Revoke existing user (Manual)"
        echo -e "${RED}3) Delete a specific tunnel (e.g. wg2)${NC}"
        echo -e "${RED}4) Remove WireGuard-Go (Uninstall all)${NC}"
        echo "5) Exit"
        echo ""
        read -p "Select an option [0-5]: " option
        case $option in
            0)
                install_packages
                setup_new_interface
                read -p "Press any key to continue..."
                ;;
            1) 
                SELECTED_NIC=$(select_interface_menu "Select interface to add user to:")
                if [ $? -eq 0 ]; then
                    add_client_to_interface "$SELECTED_NIC"
                fi
                read -p "Press any key to continue..."
                ;;
            3)
                remove_interface
                read -p "Press any key to continue..."
                ;;
            4) 
                read -p "Are you sure you want to remove WireGuard-Go and ALL configs? [y/N]: " -n 1 -r
                echo ""
                if [[ $REPLY =~ ^[Yy]$ ]]; then
                    for conf in /etc/wireguard/*.conf; do
                        if [ -f "$conf" ]; then
                            iface=$(basename "$conf" .conf)
                            systemctl stop "wg-quick@$iface" 2>/dev/null
                            systemctl disable "wg-quick@$iface" 2>/dev/null
                            systemctl reset-failed "wg-quick@$iface" 2>/dev/null
                        fi
                    done
                    
                    if [ "$os" == "debian" ] || [ "$os" == "ubuntu" ]; then
                        apt-get remove -y wireguard-tools
                    elif [ "$os" == "centos" ] || [ "$os" == "fedora" ]; then
                        yum remove -y wireguard-tools
                    elif [ "$os" == "arch" ]; then
                        pacman -Rs --noconfirm wireguard-tools
                    fi
                    
                    rm -rf /etc/wireguard
                    rm -f /usr/local/bin/wireguard-go
                    systemctl daemon-reload
                    echo "WireGuard-Go removed successfully."
                    exit
                fi
                ;;
            5) exit;;
        esac
    done
else
    echo "No existing WireGuard configuration found. Starting initial setup..."
    get_public_ip
    install_packages
    setup_new_interface
fi
