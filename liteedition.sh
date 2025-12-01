#!/usr/bin/env bash

# ULTIMATE DEBIAN OFFENSIVE INSTALLER - LITE / CORE EDITION

set -euo pipefail

# =========================================================
#   ULTIMATE DEBIAN OFFENSIVE INSTALLER (Light Edition)
# =========================================================
#   For legal penetration testing and security research ONLY
#   Debian / Ubuntu / Zorin based systems
#   Heavy frameworks (OpenVAS, Docker, neo4j, ...) are NOT
#   auto-installed anymore: install them manually if needed.
# =========================================================

RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
CYAN="\e[36m"
RESET="\e[0m"

BURP_URL="https://portswigger.net/burp/releases/download?product=community&type=Linux"
TOOLS_DIR="${HOME}/offensive-tools"

# =============================
#  BANNER
# =============================
banner() {
    echo -e "${CYAN}"
    echo "========================================================="
    echo "        ULTIMATE DEBIAN OFFENSIVE TOOLS INSTALLER"
    echo "========================================================="
    echo -e "${RESET}"
}

# =============================
#  SAFETY / ENV CHECKS
# =============================

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[!] This script must be run as root (e.g. sudo $0).${RESET}"
        exit 1
    fi
}

check_distro() {
    if [[ ! -r /etc/os-release ]]; then
        echo -e "${RED}[!] Cannot detect distribution (missing /etc/os-release).${RESET}"
        exit 1
    fi

    # shellcheck disable=SC1091
    . /etc/os-release

    case "${ID:-unknown}" in
        debian|ubuntu|zorin|kali)
            ;;
        *)
            echo -e "${RED}[!] Unsupported distro: ${ID:-unknown}"
            echo -e "    This script is intended for Debian/Ubuntu/Zorin-like systems.${RESET}"
            exit 1
            ;;
    esac
}

trap 'echo -e "\n${RED}[!] Interrupted. Exiting...${RESET}"; exit 1' INT

# =============================
#  APT TOOL PACK  (CLEAN / COMPATIBLE)
# =============================
APT_TOOLS=(
    # Network / Web / Recon
    nmap
    sqlmap
    hydra
    john
    hashcat
    gobuster
    ffuf
    nikto
    tcpdump
    netcat-openbsd
    whois
    dnsutils
    curl
    wget
    git

    # Languages / runtimes
    python3
    python3-pip
    ruby
    ruby-full

    # Build toolchain
    build-essential
    gcc
    make
    cmake

    # Wireless / sniffing (APT-only basics)
    aircrack-ng
    reaver
    bully
    wifite
    wireshark
    tshark

    # File / stego / metadata
    binwalk
    steghide
    stegsnow
    exiftool

    # VPN / anonymity
    openvpn
    tor
    proxychains4
    macchanger

    # Network scanning / mapping
    arp-scan
    zmap
    masscan

    # Security auditing / hardening
    yara
    clamav
    iptables
    ipset
    lynis
    rkhunter

    # Dev libs
    libssl-dev
    libffi-dev
    libpcap-dev

    # Shell & wordlists
    zsh
    seclists

    # QoL / System utils
    tmux
    vim
    neovim
    tree
    p7zip-full
    unrar
    zip
    unzip
    mlocate
    ripgrep
    xclip
    htop

    # Languages / Dev env extra
    golang-go
    default-jdk
    nodejs
    npm
    pipx

    # Exploit Dev / RE (basic)
    gdb
    gdb-multiarch
    strace
    ltrace
    binutils
    gdbserver

    # Forensics (light)
    sleuthkit
    foremost
    scalpel
    testdisk
)

# =============================
#  GIT TOOL PACK (NO DUPLICATES)
# =============================
GIT_TOOLS=(
    # Recon / discovery
    "https://github.com/ProjectDiscovery/subfinder.git"
    "https://github.com/ProjectDiscovery/httpx.git"
    "https://github.com/ProjectDiscovery/naabu.git"
    "https://github.com/ProjectDiscovery/katana.git"
    "https://github.com/OWASP/Amass.git"

    # PrivEsc / enumeration
    "https://github.com/carlospolop/PEASS-ng.git"
    "https://github.com/rebootuser/LinEnum.git"

    # Network / Windows / AD
    "https://github.com/SecureAuthCorp/impacket.git"
    "https://github.com/PowerShellMafia/PowerSploit.git"
    "https://github.com/BC-SECURITY/Empire.git"
    "https://github.com/BloodHoundAD/BloodHound.git"
    "https://github.com/Porchetta-Industries/CrackMapExec.git"
    "https://github.com/lgandx/Responder.git"
    "https://github.com/dirkjanm/mitm6.git"

    # Exploit dev / RE helpers
    "https://github.com/Gallopsled/pwntools.git"

    # Cloud / containers / k8s
    "https://github.com/aquasecurity/trivy.git"
    "https://github.com/aquasecurity/kube-hunter.git"
    "https://github.com/aquasecurity/kube-bench.git"

    # Wireless extras (advanced, Git-only)
    "https://github.com/v1s1t0r1sh3r3/airgeddon.git"
    "https://github.com/ZerBea/hcxdumptool.git"
    "https://github.com/ZerBea/hcxtools.git"
    "https://github.com/bettercap/bettercap.git"
)

# =============================
#  CORE FUNCTIONS
# =============================

prepare_system() {
    echo -e "${YELLOW}[+] Updating system...${RESET}"
    apt update -y && apt upgrade -y

    echo -e "${YELLOW}[+] Installing base dependencies...${RESET}"
    apt install -y \
        software-properties-common \
        ca-certificates \
        curl \
        wget \
        git \
        python3 \
        python3-pip \
        snapd \
        build-essential
}

install_apt_tools() {
    echo -e "${BLUE}[*] Installing APT tools...${RESET}"
    for pkg in "${APT_TOOLS[@]}"; do
        if dpkg -l | awk '{print $2}' | grep -qx "$pkg"; then
            echo -e "${GREEN}[✓] ${pkg} already installed.${RESET}"
        else
            echo -e "${CYAN}[*] Installing ${pkg}...${RESET}"
            if ! apt install -y "$pkg"; then
                echo -e "${RED}[!] Failed to install ${pkg} via apt. Skipping or trying fallback...${RESET}"

                # اگر seclists بود، از snap امتحان کن
                if [[ "$pkg" == "seclists" ]]; then
                    if command -v snap >/dev/null 2>&1; then
                        echo -e "${CYAN}[*] Trying to install seclists via snap...${RESET}"
                        if snap install seclists; then
                            echo -e "${GREEN}[✓] seclists installed via snap.${RESET}"
                        else
                            echo -e "${RED}[!] Failed to install seclists via snap as well.${RESET}"
                        fi
                    else
                        echo -e "${YELLOW}[!] snap is not available; cannot install seclists.${RESET}"
                    fi
                fi

            fi
        fi
    done
}

install_git_tools() {
    echo -e "${BLUE}[*] Installing GIT tools...${RESET}"

    mkdir -p "${TOOLS_DIR}"
    cd "${TOOLS_DIR}" || {
        echo -e "${RED}[!] Cannot cd to ${TOOLS_DIR}.${RESET}"
        exit 1
    }

    for repo in "${GIT_TOOLS[@]}"; do
        name="$(basename "$repo" .git)"
        if [[ -d "$name/.git" ]]; then
            echo -e "${GREEN}[✓] ${name} already cloned.${RESET}"
        else
            echo -e "${CYAN}[*] Cloning ${name}...${RESET}"
            if ! git clone --depth 1 "$repo" "$name"; then
                echo -e "${RED}[!] Failed to clone ${repo}. Skipping.${RESET}"
            fi
        fi
    done

    echo -e "${YELLOW}[!] NOTE:${RESET}"
    echo -e "${YELLOW}    Tools like BloodHound, Empire, CrackMapExec, Responder, mitm6,${RESET}"
    echo -e "${YELLOW}    trivy, kube-hunter, kube-bench, bettercap, airgeddon, hcxdumptool, hcxtools,${RESET}"
    echo -e "${YELLOW}    pwntools, impacket, PowerSploit only got cloned.${RESET}"
    echo -e "${YELLOW}    You still need to configure/install their Python deps or services manually.${RESET}"
}

install_burp() {
    echo -e "${BLUE}[*] Installing Burp Suite Community...${RESET}"

    tmpfile="$(mktemp /tmp/burp-XXXXXX.sh)"
    if ! wget -qO "$tmpfile" "$BURP_URL"; then
        echo -e "${RED}[!] Failed to download Burp from ${BURP_URL}.${RESET}"
        rm -f "$tmpfile"
        return 1
    fi

    chmod +x "$tmpfile"
    echo -e "${YELLOW}[!] Burp installer downloaded to ${tmpfile}.${RESET}"
    echo -e "${YELLOW}    It will now be executed. Review if needed.${RESET}"

    bash "$tmpfile"
    rm -f "$tmpfile"
}

install_metasploit() {
    echo -e "${BLUE}[*] Installing Metasploit Framework...${RESET}"

    # Already installed?
    if command -v msfconsole >/dev/null 2>&1; then
        echo -e "${GREEN}[✓] Metasploit already installed.${RESET}"
        return 0
    fi

    # snap available?
    if ! command -v snap >/dev/null 2>&1; then
        echo -e "${RED}[!] snap command not found. Cannot install metasploit-framework via snap.${RESET}"
        echo -e "${YELLOW}[i] Install snapd manually or install Metasploit from your distro repos.${RESET}"
        return 1
    fi

    # metasploit snap already installed?
    if snap list metasploit-framework >/dev/null 2>&1; then
        echo -e "${GREEN}[✓] metasploit-framework snap already installed.${RESET}"
        return 0
    fi

    echo -e "${CYAN}[*] Installing metasploit-framework via snap...${RESET}"
    if snap install metasploit-framework; then
        echo -e "${GREEN}[✓] metasploit-framework installed via snap. You can run: msfconsole${RESET}"
        return 0
    else
        echo -e "${RED}[!] Failed to install metasploit-framework via snap.${RESET}"
        echo -e "${YELLOW}[i] You may need to install it manually from official docs.${RESET}"
        return 1
    fi
}

install_all() {
    banner
    prepare_system
    install_apt_tools
    install_git_tools
    install_burp
    install_metasploit
    echo -e "${GREEN}[✓] All core tools installed (where possible).${RESET}"
    echo -e "${YELLOW}[i] Heavy services like OpenVAS, Docker, neo4j are NOT auto-installed.${RESET}"
}

update_all() {
    banner
    echo -e "${YELLOW}[+] Updating system packages...${RESET}"
    apt update -y && apt upgrade -y

    echo -e "${YELLOW}[+] Checking APT tools...${RESET}"
    for pkg in "${APT_TOOLS[@]}"; do
        if dpkg -l | awk '{print $2}' | grep -qx "$pkg"; then
            echo -e "${GREEN}[✓] ${pkg} OK.${RESET}"
        else
            echo -e "${CYAN}[*] Installing missing: ${pkg}${RESET}"
            apt install -y "$pkg" || echo -e "${RED}[!] Failed to install ${pkg}.${RESET}"
        fi
    done

    echo -e "${BLUE}[*] Updating Git tools...${RESET}"
    if [[ -d "${TOOLS_DIR}" ]]; then
        cd "${TOOLS_DIR}" || exit 1
        for dir in */; do
            [[ -d "$dir/.git" ]] || continue
            echo -e "${CYAN}[*] Updating ${dir%/}...${RESET}"
            (
                cd "$dir" || exit 0
                git pull --ff-only || echo -e "${RED}[!] git pull failed for ${dir%/}.${RESET}"
            )
        done
    else
        echo -e "${YELLOW}[!] ${TOOLS_DIR} does not exist. Nothing to update.${RESET}"
    fi

    echo -e "${GREEN}[✓] Update complete.${RESET}"
}

# =============================
#  MENU
# =============================
menu() {
    banner
    echo -e "${CYAN}1.${RESET} Install all core tools"
    echo -e "${CYAN}2.${RESET} Check / install missing tools & update git repos"
    echo "------------------------"
    echo -e "${CYAN}q.${RESET} Exit"
}

main() {
    require_root
    check_distro

    while true; do
        menu
        read -rp "Select: " choice
        case "$choice" in
            1) install_all ;;
            2) update_all ;;
            q|Q) echo "Bye."; exit 0 ;;
            *) echo -e "${RED}[!] Invalid option.${RESET}" ;;
        esac
    done
}

main "$@"
