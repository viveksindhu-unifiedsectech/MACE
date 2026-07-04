#!/usr/bin/env bash
# UnifiedSec MACE Endpoint Agent (UMEA) — Linux installer (systemd timer)
set -euo pipefail

PREFIX="${PREFIX:-/opt/mace-agent}"
INGEST_URL="${MACE_INGEST_URL:-https://ingest.unifiedsec.local/agent}"
INTERVAL_MIN="${MACE_SCAN_INTERVAL_MIN:-30}"

if [ "$EUID" -ne 0 ]; then exec sudo --preserve-env=MACE_INGEST_URL,MACE_SCAN_INTERVAL_MIN bash "$0" "$@"; fi
echo "▶ Installing UMEA to ${PREFIX}"
mkdir -p "${PREFIX}"
INSTALL_SRC="$(cd "$(dirname "$0")/.." && pwd)"
cp -R "${INSTALL_SRC}" "${PREFIX}/agent_module"

cat > "${PREFIX}/mace-agent" <<WRAP
#!/usr/bin/env bash
PYTHONPATH="${PREFIX}/agent_module/.." exec python3 -m mace_platform.agent.cli "\$@"
WRAP
chmod +x "${PREFIX}/mace-agent"

cat > /etc/systemd/system/mace-agent.service <<EOF
[Unit]
Description=UnifiedSec MACE Endpoint Agent — HWAM/SWAM/STIG/Vuln scan
After=network-online.target
[Service]
Type=oneshot
ExecStart=${PREFIX}/mace-agent post --url ${INGEST_URL}
EOF

cat > /etc/systemd/system/mace-agent.timer <<EOF
[Unit]
Description=Run UnifiedSec MACE Endpoint Agent every ${INTERVAL_MIN} minutes
[Timer]
OnBootSec=2min
OnUnitActiveSec=${INTERVAL_MIN}min
Persistent=true
[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now mace-agent.timer
"${PREFIX}/mace-agent" scan --summary || true
echo "✓ Installed. Timer: mace-agent.timer. Logs: journalctl -u mace-agent.service -n 50"
