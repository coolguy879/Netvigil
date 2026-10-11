#!/usr/bin/env python3
"""
===========================================
  Wi-Fi Security Auditor v1.0 for Termux
  Use ONLY on networks you own or have
  explicit written permission to test.
===========================================
"""

import json
import subprocess
import socket
import sys
import time
from datetime import datetime

# ─── Color helpers (no external dependency) ───────────────────────────────────
def red(s):    return f"\033[91m{s}\033[0m"
def green(s):  return f"\033[92m{s}\033[0m"
def yellow(s): return f"\033[93m{s}\033[0m"
def cyan(s):   return f"\033[96m{s}\033[0m"
def bold(s):   return f"\033[1m{s}\033[0m"
def dim(s):    return f"\033[2m{s}\033[0m"

# ─── Known weak/default router credentials ────────────────────────────────────
DEFAULT_CREDS = [
    ("admin",  "admin"),
    ("admin",  "password"),
    ("admin",  "1234"),
    ("admin",  "12345"),
    ("admin",  ""),
    ("root",   "root"),
    ("root",   ""),
    ("user",   "user"),
    ("admin",  "admin123"),
    ("admin",  "router"),
]

# ─── Common router admin ports to check ───────────────────────────────────────
ROUTER_PORTS = {
    80:   "HTTP  (Web Admin)",
    443:  "HTTPS (Web Admin)",
    22:   "SSH",
    23:   "Telnet",       # Insecure – plaintext
    8080: "HTTP Alt",
    8443: "HTTPS Alt",
    21:   "FTP",          # Insecure – plaintext
    53:   "DNS",
    5000: "UPnP / Alt",
}


# ══════════════════════════════════════════════════════════════════════════════
def banner():
    print(cyan(bold("""
╔══════════════════════════════════════════════╗
║        Wi-Fi Security Auditor v1.0           ║
║        Termux Edition                        ║
╠══════════════════════════════════════════════╣
║  ⚠  Use ONLY on YOUR OWN network.            ║
║     Unauthorised testing is illegal.         ║
╚══════════════════════════════════════════════╝
""")))


# ══════════════════════════════════════════════════════════════════════════════
# STEP 1 – Current connection info via Termux API
# ══════════════════════════════════════════════════════════════════════════════
def get_connection_info():
    """Call termux-wifi-connectioninfo and return parsed JSON, or None on error."""
    print(bold("\n── Step 1: Current Connection ──────────────────"))
    try:
        result = subprocess.run(
            ["termux-wifi-connectioninfo"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0 or not result.stdout.strip():
            print(red("  [-] termux-wifi-connectioninfo failed."))
            print(dim("      Install with: pkg install termux-api"))
            return None
        return json.loads(result.stdout)
    except FileNotFoundError:
        print(red("  [-] termux-api not installed. Run: pkg install termux-api"))
        return None
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
        print(red(f"  [-] Error reading connection info: {e}"))
        return None


def analyze_connection(info):
    """Pretty-print and evaluate the current Wi-Fi connection."""
    if not info:
        print(yellow("  Skipping — no connection data."))
        return

    ssid     = info.get("ssid", "Unknown")
    bssid    = info.get("bssid", "Unknown")
    ip       = info.get("ip", "Unknown")
    speed    = info.get("link_speed_mbps", "?")
    freq     = info.get("frequency_mhz", 0)
    rssi     = info.get("rssi", 0)
    security = info.get("security_type", "").upper()

    band = "5 GHz" if int(freq) > 3000 else "2.4 GHz" if freq else "?"

    print(f"  SSID        : {cyan(ssid)}")
    print(f"  BSSID       : {bssid}")
    print(f"  IP Address  : {ip}")
    print(f"  Band        : {band} ({freq} MHz)")
    print(f"  Link Speed  : {speed} Mbps")

    # ── Signal quality ─────────────────────────────────────────────────────
    if rssi:
        if   rssi >= -50: sq = green("Excellent")
        elif rssi >= -60: sq = green("Good")
        elif rssi >= -70: sq = yellow("Fair")
        else:             sq = red("Poor")
        print(f"  Signal      : {sq}  ({rssi} dBm)")

    # ── Encryption rating ──────────────────────────────────────────────────
    print(f"  Security    : ", end="")
    if "WEP" in security:
        print(red(f"{security}  ⚠  CRITICAL — WEP is completely broken!"))
    elif "WPA3" in security:
        print(green(f"{security}  ✅  Excellent"))
    elif "WPA2" in security:
        print(green(f"{security}  ✅  Good (WPA3 upgrade recommended if available)"))
    elif "WPA" in security:
        print(yellow(f"{security}  ⚠  WPA1 is outdated — upgrade to WPA2/WPA3"))
    elif not security or "OPEN" in security:
        print(red("OPEN  ⚠  CRITICAL — No encryption! All traffic is visible!"))
    else:
        print(yellow(f"{security}  (Unknown type)"))


# ══════════════════════════════════════════════════════════════════════════════
# STEP 2 – Nearby network scan
# ══════════════════════════════════════════════════════════════════════════════
def scan_nearby_networks():
    """Use termux-wifi-scaninfo to list nearby networks with security info."""
    print(bold("\n── Step 2: Nearby Networks ──────────────────────"))
    try:
        result = subprocess.run(
            ["termux-wifi-scaninfo"],
            capture_output=True, text=True, timeout=20
        )
        if result.returncode != 0 or not result.stdout.strip():
            print(yellow("  [-] Could not scan nearby networks."))
            return

        networks = json.loads(result.stdout)
        if not networks:
            print(yellow("  No networks found."))
            return

        print(f"  Found {len(networks)} network(s):\n")
        print(f"  {'SSID':<26} {'Security':<10} {'Band':<6} {'Signal'}")
        print(f"  {'─'*26} {'─'*10} {'─'*6} {'─'*10}")

        insecure = 0
        for net in networks[:25]:   # Cap at 25 for readability
            ssid  = (net.get("ssid") or "Hidden")[:25]
            caps  = net.get("capabilities", "").upper()
            freq  = net.get("frequency", 0)
            rssi  = net.get("level", 0)
            band  = "5G" if int(freq) > 3000 else "2.4G"

            if   "WEP"  in caps:                    sec = red("WEP ⚠");   insecure += 1
            elif "WPA3" in caps:                    sec = green("WPA3 ✅")
            elif "WPA2" in caps:                    sec = green("WPA2 ✅")
            elif "WPA"  in caps:                    sec = yellow("WPA ⚠");  insecure += 1
            elif "[ESS]" in caps or caps == "":     sec = red("OPEN ⚠");  insecure += 1
            else:                                   sec = yellow(caps[:10])

            print(f"  {ssid:<26} {sec:<10} {band:<6} {rssi} dBm")

        if insecure:
            print(yellow(f"\n  ⚠  {insecure} insecure network(s) detected nearby."))
        else:
            print(green("\n  ✅  All visible networks use modern encryption."))

    except FileNotFoundError:
        print(red("  [-] termux-api not installed."))
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
        print(yellow(f"  [-] Scan error: {e}"))


# ══════════════════════════════════════════════════════════════════════════════
# STEP 3 – Router port scan
# ══════════════════════════════════════════════════════════════════════════════
def get_gateway_ip(info):
    """Derive the likely gateway IP from the device's IP address."""
    ip = info.get("ip", "") if info else ""
    if not ip:
        return None
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.1"
    return None


def scan_router_ports(router_ip):
    """TCP connect-scan on common router admin ports. Returns list of open ports."""
    print(bold(f"\n── Step 3: Router Port Scan  ({router_ip}) ────────"))

    open_ports = []
    for port, service in ROUTER_PORTS.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.2)
            connected = sock.connect_ex((router_ip, port))
            sock.close()

            if connected == 0:
                open_ports.append((port, service))
                # Flag dangerous services
                if port == 23:
                    print(f"  {red('OPEN')}  {port:<5}  {red(service)}  ⚠  Plaintext — disable Telnet!")
                elif port == 21:
                    print(f"  {yellow('OPEN')}  {port:<5}  {yellow(service)}  ⚠  Plaintext — disable FTP!")
                else:
                    print(f"  {green('OPEN')}  {port:<5}  {service}")
            else:
                print(f"  {dim('----')}  {port:<5}  {dim(service)}")

        except Exception:
            pass   # Silently skip unreachable ports

    if not open_ports:
        print(yellow("  No common admin ports reachable."))
    return open_ports


# ══════════════════════════════════════════════════════════════════════════════
# STEP 4 – Default credential check (HTTP Basic Auth)
# ══════════════════════════════════════════════════════════════════════════════
def check_default_credentials(router_ip, open_ports):
    """
    Attempt HTTP Basic Auth with common default credentials against
    the router's web interface (port 80 or 443).
    """
    print(bold("\n── Step 4: Default Credential Check ────────────"))

    # Find an HTTP/HTTPS port
    target_port = None
    use_https   = False
    for port, _ in open_ports:
        if port in (80, 8080):
            target_port = port; break
        if port in (443, 8443):
            target_port = port; use_https = True; break

    if not target_port:
        print(yellow("  No HTTP/HTTPS port found — skipping credential check."))
        return

    protocol = "https" if use_https else "http"
    url      = f"{protocol}://{router_ip}:{target_port}"
    print(f"  Target : {url}")
    print(f"  Testing {len(DEFAULT_CREDS)} common default credential pairs...\n")

    try:
        import urllib.request, urllib.error, base64, ssl

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        found = False
        for username, password in DEFAULT_CREDS:
            try:
                credentials = base64.b64encode(
                    f"{username}:{password}".encode()
                ).decode()
                req = urllib.request.Request(url)
                req.add_header("Authorization", f"Basic {credentials}")
                req.add_header("User-Agent", "Mozilla/5.0")

                with urllib.request.urlopen(req, timeout=3, context=ctx) as resp:
                    body = resp.read().decode(errors="ignore").lower()
                    login_words = ["login", "sign in", "password", "username"]
                    # 200 OK + no login page = likely authenticated
                    if resp.status == 200 and not any(w in body for w in login_words):
                        print(red(f"  ⚠  VULNERABLE — Default creds accepted: {username}:{password}"))
                        found = True
                        break

            except urllib.error.HTTPError as e:
                # 401 = rejected (good), 403 = forbidden (different issue)
                if e.code not in (401, 403):
                    pass
            except Exception:
                pass

            time.sleep(0.15)    # Polite delay between attempts

        if not found:
            print(green("  ✅  No default credentials accepted (or Basic Auth not in use)."))
            print(dim("      Tip: also check WPS PIN and web UI manually."))

    except ImportError:
        print(yellow("  urllib not available — skipping."))


# ══════════════════════════════════════════════════════════════════════════════
# STEP 5 – WPS detection (parse nmap output if available)
# ══════════════════════════════════════════════════════════════════════════════
def check_wps(router_ip):
    """Try to detect whether WPS is advertised via nmap (if installed)."""
    print(bold("\n── Step 5: WPS Check ────────────────────────────"))
    try:
        result = subprocess.run(
            ["nmap", "--script", "broadcast-wps-info", "-p", "80", router_ip,
             "--open", "-T4", "--host-timeout", "8s"],
            capture_output=True, text=True, timeout=15
        )
        output = result.stdout.lower()
        if "wps" in output:
            if "locked" in output:
                print(yellow("  ⚠  WPS detected but appears locked."))
            else:
                print(red("  ⚠  WPS is ENABLED — consider disabling it in your router settings."))
                print(dim("      WPS PIN attacks can bypass your Wi-Fi password."))
        else:
            print(green("  ✅  WPS not detected (or nmap script unavailable)."))
    except FileNotFoundError:
        print(dim("  nmap not installed — skipping WPS check."))
        print(dim("  Install with: pkg install nmap"))
    except subprocess.TimeoutExpired:
        print(yellow("  WPS check timed out."))


# ══════════════════════════════════════════════════════════════════════════════
# STEP 6 – Summary report
# ══════════════════════════════════════════════════════════════════════════════
def generate_report(info, open_ports):
    """Compile all findings into a human-readable summary."""
    print(bold("\n" + "═"*50))
    print(bold("              AUDIT SUMMARY REPORT"))
    print(bold("═"*50))

    issues  = []
    tips    = []

    # ── Encryption check ──────────────────────────────────────────────────
    if info:
        sec = info.get("security_type", "").upper()
        if "WEP" in sec:
            issues.append("CRITICAL: WEP encryption (completely broken)")
            tips.append("Change router to WPA2 or WPA3 immediately")
        elif not sec or "OPEN" in sec:
            issues.append("CRITICAL: Open network — no encryption")
            tips.append("Enable WPA2 or WPA3 on your router")
        elif "WPA" in sec and "WPA2" not in sec and "WPA3" not in sec:
            issues.append("WARNING: WPA1 is outdated")
            tips.append("Upgrade router firmware and switch to WPA2/WPA3")

    # ── Dangerous ports ───────────────────────────────────────────────────
    for port, svc in open_ports:
        if port == 23:
            issues.append("WARNING: Telnet enabled (plaintext remote access)")
            tips.append("Disable Telnet in router admin panel")
        if port == 21:
            issues.append("WARNING: FTP enabled (plaintext file transfer)")
            tips.append("Disable FTP in router admin panel")

    # ── Print results ─────────────────────────────────────────────────────
    if issues:
        print(red(f"\n  Issues found: {len(issues)}"))
        for i, issue in enumerate(issues, 1):
            print(red(f"    {i}. {issue}"))
        print(yellow(f"\n  Recommendations:"))
        for i, tip in enumerate(tips, 1):
            print(yellow(f"    {i}. {tip}"))
    else:
        print(green("\n  ✅  No critical issues detected."))
        print(green("  Your network configuration looks solid."))

    # ── General hardening tips (always shown) ─────────────────────────────
    print(dim("\n  General Hardening Tips:"))
    print(dim("  • Change default router admin password"))
    print(dim("  • Disable WPS if not needed"))
    print(dim("  • Keep router firmware up to date"))
    print(dim("  • Use WPA3 if your router supports it"))
    print(dim("  • Enable router firewall / SPI"))

    print(bold("\n" + "═"*50))
    print(f"  Completed : {datetime.now().strftime('%Y-%m-%d  %H:%M:%S')}")
    print(bold("═"*50 + "\n"))


# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════
def main():
    banner()
    print(yellow("  ⚠  This tool tests YOUR OWN router/network only.\n"))

    # 1. Connection info
    info = get_connection_info()
    analyze_connection(info)

    # 2. Nearby networks
    scan_nearby_networks()

    open_ports = []
    router_ip  = get_gateway_ip(info)

    if router_ip:
        # 3. Port scan
        open_ports = scan_router_ports(router_ip)

        # 4. Default credentials
        check_default_credentials(router_ip, open_ports)

        # 5. WPS check
        check_wps(router_ip)
    else:
        print(yellow("\n  Could not determine router IP — skipping steps 3–5."))

    # 6. Summary
    generate_report(info, open_ports)


if __name__ == "__main__":
    main()
