#!/usr/bin/env bash
# UnifiedSec MACE Endpoint Agent (UMEA) — macOS installer
# Replaces CrowdStrike Falcon Sensor + Tenable Nessus Agent in a single binary.
set -euo pipefail

PREFIX="${PREFIX:-/usr/local/mace-agent}"
INGEST_URL="${MACE_INGEST_URL:-https://ingest.unifiedsec.local/agent}"
INTERVAL_MIN="${MACE_SCAN_INTERVAL_MIN:-30}"

echo "▶ Installing UnifiedSec MACE Endpoint Agent to ${PREFIX}"

if [ "$EUID" -ne 0 ]; then
  echo "  (re-running with sudo)"
  exec sudo --preserve-env=MACE_INGEST_URL,MACE_SCAN_INTERVAL_MIN bash "$0" "$@"
fi

mkdir -p "${PREFIX}"
# Copy agent module next to this installer
INSTALL_SRC="$(cd "$(dirname "$0")/.." && pwd)"
cp -R "${INSTALL_SRC}" "${PREFIX}/agent_module"

# Wrapper
cat > "${PREFIX}/mace-agent" <<'WRAP'
#!/usr/bin/env bash
exec python3 -m mace_platform.agent.cli "$@"
WRAP
chmod +x "${PREFIX}/mace-agent"

# launchd plist for periodic scan
PLIST=/Library/LaunchDaemons/io.unifiedsec.maceagent.plist
cat > "${PLIST}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>io.unifiedsec.maceagent</string>
  <key>ProgramArguments</key>
  <array>
    <string>${PREFIX}/mace-agent</string>
    <string>post</string>
    <string>--url</string>
    <string>${INGEST_URL}</string>
  </array>
  <key>StartInterval</key><integer>$((INTERVAL_MIN * 60))</integer>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PYTHONPATH</key><string>${PREFIX}/agent_module/..</string>
  </dict>
  <key>StandardOutPath</key><string>/var/log/mace-agent.log</string>
  <key>StandardErrorPath</key><string>/var/log/mace-agent.err</string>
</dict>
</plist>
EOF
chown root:wheel "${PLIST}"
chmod 644 "${PLIST}"

echo "▶ Loading launchd job"
launchctl unload "${PLIST}" 2>/dev/null || true
launchctl load "${PLIST}"

echo "▶ First scan…"
"${PREFIX}/mace-agent" scan --summary || true

echo
echo "✓ Installed. mace-agent will scan every ${INTERVAL_MIN} min and POST to:"
echo "    ${INGEST_URL}"
echo "  Run 'sudo launchctl unload ${PLIST}' to stop. Logs: /var/log/mace-agent.log"
