#!/usr/bin/env bash
# ── Vane Monitor — Client binary builder (Linux / macOS) ──
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SHARED_DIR="$SCRIPT_DIR/shared"
VENV_DIR="$SCRIPT_DIR/.build_venv"
DIST_DIR="$SCRIPT_DIR/dist"
BUILD_DIR="$SCRIPT_DIR/build"

echo ""
echo "═══════════════════════════════════════════════════"
echo "  Vane Monitor — Client binary builder"
echo "═══════════════════════════════════════════════════"
echo ""

# 1. Clean venv
[ -d "$VENV_DIR" ] && rm -rf "$VENV_DIR"
echo "[1/4] Creating clean build venv …"
python3 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

# 2. Install deps
echo "[2/4] Installing dependencies …"
pip install --upgrade pip -q
pip install -r "$SCRIPT_DIR/requirements.txt" -q

# 3. PyInstaller
echo "[3/4] Running PyInstaller (--onefile) …"
python -m PyInstaller \
    --name VaneMonitorClient \
    --onefile \
    --noconfirm --clean \
    --paths "$SCRIPT_DIR" \
    --add-data "$SHARED_DIR:shared" \
    --hidden-import shared \
    --hidden-import shared.config \
    --hidden-import shared.log_handler \
    --hidden-import shared.constants \
    --hidden-import shared.monitor \
    --hidden-import shared.monitor.network_tests \
    --hidden-import shared.monitor.asn_lookup \
    --distpath "$DIST_DIR" \
    --workpath "$BUILD_DIR" \
    --specpath "$SCRIPT_DIR" \
    "$SCRIPT_DIR/main.py"

# 4. Cleanup
echo "[4/4] Cleaning build venv …"
deactivate
rm -rf "$VENV_DIR"

echo ""
echo "✅  Build complete!  Output: $DIST_DIR/VaneMonitorClient"
echo "   Copy the binary to the target machine and run it."
echo "   On first run it will create client_config.json next to itself."
echo ""
