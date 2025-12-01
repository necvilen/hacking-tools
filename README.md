# Ultimate Debian Offensive Installer

Two simple scripts to turn a Debian/Ubuntu/Zorin/Kali system into a penetration testing / red team box:

- **Lite/Core Edition** – lighter baseline for everyday use (`liteedition.sh`)
- **Red Edition** – heavier build with red-team frameworks and tooling (`rededition.sh`)

> ⚠️ For legal penetration testing, security research, and education only.  
> You are fully responsible for any misuse.

---

## Editions

### 🔹 Lite / Core Edition

Script: `liteedition.sh`

- Focused on **core, relatively lightweight** tooling:
  - network & web recon (nmap, sqlmap, gobuster, ffuf, …)
  - password cracking (john, hashcat)
  - Wi-Fi basics (aircrack-ng, wifite, …)
  - light forensics (sleuthkit, foremost, …)
  - basic exploit dev (gdb, gdb-multiarch, …)
  - QoL tools like tmux, vim/neovim, htop, ripgrep, etc.
- Good fit for laptops and “normal” machines

### 🔸 Red Edition

Script: `rededition.sh`

- Includes the Lite/Core baseline + a lot of extra Git-based tooling:
  - ProjectDiscovery stack (subfinder, httpx, naabu, katana, nuclei, …)
  - payload collections (PayloadsAllTheThings, nuclei-templates, …)
  - Windows/AD/Red Team tooling (impacket, CrackMapExec, Responder, BloodHound, Empire, Sliver, Caldera, PowerSploit, …)
  - advanced wireless & MITM (airgeddon, bettercap, hcxdumptool, hcxtools, …)
  - cloud/k8s security (trivy, kube-hunter, kube-bench)
  - social engineering toolkit (SET) and extra web tools
- Intended for **stronger machines** and users who are comfortable configuring large frameworks

---

## Supported Distros

Targeted at Debian-based distributions:

- **Debian**
- **Ubuntu** (and derivatives like Linux Mint)
- **Zorin OS**
- **Kali Linux**

On startup the scripts:

- Check that `/etc/os-release` exists
- Require `ID=` to be one of `debian | ubuntu | zorin | kali`
- Exit cleanly if the distro is unsupported

---

## Requirements

- **root** privileges (run via `sudo` or as root)
- Internet connectivity
- Enough disk space  
  (especially for Red Edition – expect multiple GB of downloads and Git clones)

---

## Quick Install (curl)

> ⚠️ Always **read scripts before piping them into `bash`**.  
> These snippets are for convenience, not an endorsement of blind `curl | bash`.

### Lite/Core Edition

```bash
curl -sSL https://raw.githubusercontent.com/necvilen/hacking-tools/main/liteedition.sh | sudo bash
```

### RED/Core Edition
```bash
curl -sSL https://raw.githubusercontent.com/necvilen/hacking-tools/main/rededition.sh | sudo bash
```

### Manual Installation (clone)
```bash
git clone https://github.com/necvilen/hacking-tools.git
cd necvilen

chmod +x liteedition.sh
chmod +x rededition.sh

# Lite/Core
sudo ./liteedition.sh

# Red
sudo ./rededition.sh
```

