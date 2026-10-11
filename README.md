# 🛡️ NetVigil — Wi-Fi Security Auditor for Termux

> **NetVigil** is a lightweight, terminal-based Wi-Fi security auditor built for
> Termux on Android. It inspects your own network for common misconfigurations,
> weak encryption, exposed router services, and default credentials — no root
> required.

---

## ⚠️ Legal Notice

This tool is intended **solely for use on networks and devices you own or have
explicit written permission to test**. Unauthorised use against networks you do
not own is illegal in most jurisdictions. The author assumes no liability for
misuse.

---

## ✨ Features

| # | Check | What it detects |
|---|-------|-----------------|
| 1 | **Connection Analysis** | Encryption type (WEP/WPA/WPA2/WPA3), signal quality, band |
| 2 | **Nearby Network Scan** | Flags insecure networks (WEP, WPA1, Open) in range |
| 3 | **Router Port Scan** | Detects open admin ports — Telnet, FTP, HTTP, SSH |
| 4 | **Default Credential Check** | Tests 10 common router username/password pairs |
| 5 | **WPS Detection** | Checks if WPS is enabled (exploitable PIN attack vector) |
| 6 | **Audit Summary Report** | Consolidated findings with actionable recommendations |

---

## 📋 Requirements

### System
- Android 7.0 or later
- [Termux](https://f-droid.org/packages/com.termux/) (install from **F-Droid**, not Play Store)
- [Termux:API](https://f-droid.org/packages/com.termux.api/) companion app

### Python
- Python 3.8+
- Standard library only (no heavy dependencies)
- Optional: `nmap` system package for WPS detection

---

## 🚀 Installation

### Step 1 — Install Termux & Termux:API

Download both from **F-Droid** (recommended):
- https://f-droid.org/packages/com.termux/
- https://f-droid.org/packages/com.termux.api/

> ⚠️ The Play Store version of Termux is outdated. Use F-Droid.

---

### Step 2 — Grant Permissions

In Android **Settings → Apps → Termux:API → Permissions**, enable:
- **Location** (required for Wi-Fi scanning on Android 9+)
- **Nearby devices** (Android 12+)

---

### Step 3 — Set Up Termux

Open Termux and run:

```bash
# Update package lists
pkg update -y && pkg upgrade -y

# Install required system packages
pkg install -y python nmap termux-api

# Grant storage access (optional, for saving reports)
termux-setup-storage
```

---

### Step 4 — Clone or Download NetVigil

**Option A — Copy the file directly into Termux:**
```bash
# Create a project folder
mkdir -p ~/netvigil && cd ~/netvigil
```
Then transfer `wifi_auditor.py` into `~/netvigil/`.

**Option B — Using git (if you host it):**
```bash
pkg install -y git
git clone https://github.com/yourname/netvigil.git
cd netvigil
```

---

### Step 5 — Install Python Dependencies

```bash
pip install -r requirements.txt
```

> All core functionality uses Python's standard library.
> `requirements.txt` lists optional enhancements only.

---

## ▶️ Usage

```bash
cd ~/netvigil
python wifi_auditor.py
```

### Example Output

```
╔══════════════════════════════════════════════╗
║        Wi-Fi Security Auditor v1.0           ║
║        Termux Edition                        ║
╚══════════════════════════════════════════════╝

── Step 1: Current Connection ──────────────────
  SSID        : MyHomeNetwork
  BSSID       : AA:BB:CC:DD:EE:FF
  IP Address  : 192.168.1.105
  Band        : 5 GHz (5180 MHz)
  Link Speed  : 433 Mbps
  Signal      : Good  (-58 dBm)
  Security    : WPA2  ✅  Good

── Step 2: Nearby Networks ──────────────────────
  Found 6 network(s):
  ...

── Step 3: Router Port Scan  (192.168.1.1) ────
  OPEN   80     HTTP  (Web Admin)
  ----   443    HTTPS (Web Admin)
  OPEN   23     Telnet  ⚠  Plaintext — disable Telnet!

── Step 4: Default Credential Check ────────────
  ✅  No default credentials accepted.

── Step 5: WPS Check ────────────────────────────
  ⚠  WPS is ENABLED — consider disabling it.

══════════════════════════════════════════════════
              AUDIT SUMMARY REPORT
══════════════════════════════════════════════════
  Issues found: 2
    1. WARNING: Telnet enabled (plaintext remote access)
    2. WARNING: WPS is enabled

  Recommendations:
    1. Disable Telnet in router admin panel
    2. Disable WPS in router wireless settings
```

---

## 📁 Project Structure

```
netvigil/
├── wifi_auditor.py      # Main auditor script
├── setup_termux.sh      # One-command Termux setup
├── requirements.txt     # Python dependencies
├── README.md            # This file
└── LICENSE              # MIT License
```

---

## 🔧 Troubleshooting

| Problem | Fix |
|---------|-----|
| `termux-wifi-connectioninfo` fails | Install Termux:API app + grant Location permission |
| No nearby networks found | Ensure Location permission is granted |
| Router IP not detected | Your subnet may not use .1 as gateway — run `ip route` |
| WPS check skipped | Run `pkg install nmap` |
| Permission denied on `.sh` | Run `chmod +x setup_termux.sh` first |

---

## 🛠️ What NetVigil Does NOT Do

- ❌ Does not crack or brute-force Wi-Fi passwords
- ❌ Does not intercept or capture network traffic
- ❌ Does not test networks you don't own
- ❌ Does not require root access

---

## 📜 License

MIT — see [LICENSE](LICENSE) for full terms.

---

## 👤 Author

Built with Python 3 for Termux on Android.  
Contributions welcome via pull request.
