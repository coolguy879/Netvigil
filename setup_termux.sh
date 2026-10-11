#!/data/data/com.termux/files/usr/bin/bash
# ═══════════════════════════════════════════════
#   Wi-Fi Security Auditor — Termux Setup Script
# ═══════════════════════════════════════════════

echo ""
echo "  ╔════════════════════════════════════╗"
echo "  ║  Wi-Fi Auditor — Termux Setup      ║"
echo "  ╚════════════════════════════════════╝"
echo ""

# 1. Update package lists
echo "[1/4] Updating packages..."
pkg update -y && pkg upgrade -y

# 2. Install system packages
echo ""
echo "[2/4] Installing system packages..."
pkg install -y python nmap termux-api

# 3. Grant Termux storage permission (needed to save reports)
echo ""
echo "[3/4] Requesting storage permission..."
termux-setup-storage

# 4. Verify Python
echo ""
echo "[4/4] Verifying Python..."
python --version

echo ""
echo "  ✅  Setup complete!"
echo ""
echo "  ─────────────────────────────────────"
echo "  IMPORTANT: Open the Termux:API app"
echo "  and grant it Notification + Location"
echo "  permissions in Android Settings."
echo "  ─────────────────────────────────────"
echo ""
echo "  Run the auditor:"
echo "    python wifi_auditor.py"
echo ""
