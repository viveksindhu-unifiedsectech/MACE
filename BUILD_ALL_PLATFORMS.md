# Build MACE Agent for Windows / Linux / macOS / Android / iOS

You have two paths.

## Path A — GitHub Actions (recommended, ~5 minutes, $0)

1. Create a private GitHub repo `unifiedsec/mace-agent`.
2. From this directory:
   ```bash
   cd /Users/viveksindhu/Desktop/Unified\ Tech/CompleteUpdatedMaceProd/UnifiedSec_MACE_Complete
   git init
   git add .
   git commit -m "MACE 2.1 — unified agent + Macey + 7-domain CDCS"
   git remote add origin git@github.com:unifiedsec/mace-agent.git
   git push -u origin main
   git tag v1.0.0
   git push origin v1.0.0
   ```
3. Go to `https://github.com/unifiedsec/mace-agent/actions`. The build runs
   on macos-14 + ubuntu-latest + windows-latest in parallel.
4. After ~3-5 minutes click the run → **Artifacts**. Download:
   - `mace-agent-macos`     (the .app + binary)
   - `mace-agent-windows`   (the .exe)
   - `mace-agent-linux`     (the Linux ELF)
   - `mace-agent-android`   (the .apk — needs Android SDK in the runner; we already wired this)
   - `mace-agent-ios`       (the .xcarchive — sign with your Apple ID locally)

The YAML is already at `.github/workflows/build-all.yml`. No changes
needed.

## Path B — Build everything locally on this Mac (~45 min one-time setup)

This requires you to run these commands in **your own terminal** (not
Claude's — brew refuses to run as root, sensibly):

```bash
# 1. (you already have brew installed)

# 2. JDK + Android SDK + Xcode helpers (~10 GB)
brew install --cask temurin@17 android-studio xcodegen
brew install gradle

# 3. Full Xcode — you already started this. Wait for it to finish in
#    the App Store before doing iOS builds.

# 4. Accept Android licences (Android Studio prompts you on first launch).
#    Or non-interactively:
yes | $HOME/Library/Android/sdk/cmdline-tools/latest/bin/sdkmanager --licenses

# 5. Build all platforms in one shot
cd /Users/viveksindhu/Desktop/Unified\ Tech/CompleteUpdatedMaceProd/UnifiedSec_MACE_Complete
bash mace_platform/agent/build/build_all_platforms.sh
```

Outputs in `./dist/`:

| File | Platform |
|---|---|
| `mace-agent` (binary)        | macOS arm64 |
| `MACEAgent.app`              | macOS double-clickable |
| `mace-agent-linux`           | Linux x86_64 (needs Docker) |
| `MACEAgent.apk`              | Android (any phone running Android 7+) |
| `MACEAgent.ipa` (unsigned)   | iOS (sideload via TestFlight or Xcode) |

For Windows `.exe`: PyInstaller cannot reliably cross-build from Mac.
**Use the GitHub Actions step above** — it spawns a Windows runner and
takes ~3 minutes.

## How to send these to your brother and investors

Once `dist/` is populated:

```bash
# Build a single zip for distribution
cd dist
zip -r MACEAgent-v1.0.0.zip *
# Upload to a private URL, or:
gh release create v1.0.0 *
```

Then share:
- `MACEAgent.app` → drag-and-drop to your brother's Mac
- `mace-agent.exe` → email it (Windows users may need to right-click → Properties → Unblock)
- `mace-agent-linux` → `chmod +x mace-agent-linux && ./mace-agent-linux`
- `MACEAgent.apk` → email it or AirDrop; Android user enables "Install from unknown sources"
- `MACEAgent.ipa` → use Apple Configurator or TestFlight (App Store requires a paid Developer account + review)

### What investors see when they run it

Double-clicking opens **two** things simultaneously:
1. The desktop GUI window (the polished tkinter scanner).
2. A browser tab at `http://127.0.0.1:8765/` showing the live dashboard.

The agent scans the device on launch + every 30 min thereafter, posts
to the local API, and the dashboard updates live.
