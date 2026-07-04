#!/usr/bin/env bash
# Build an unsigned iOS .ipa from the MACEAgent Swift sources.
#
# Two paths — xcodegen preferred (clean), swift-build fallback (works
# without xcodegen but produces a Mac-Catalyst-style binary).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "${HERE}"

if command -v xcodegen >/dev/null 2>&1; then
    echo "▶ Generating Xcode project via xcodegen…"
    xcodegen generate
    echo "▶ Archiving for iOS…"
    xcodebuild -project MACEAgent.xcodeproj -scheme MACEAgent \
        -configuration Release \
        -destination 'generic/platform=iOS' \
        -archivePath build/MACEAgent.xcarchive \
        archive \
        CODE_SIGN_IDENTITY="" \
        CODE_SIGNING_REQUIRED=NO \
        CODE_SIGNING_ALLOWED=NO 2>&1 | tail -20
    if [[ -d build/MACEAgent.xcarchive ]]; then
        mkdir -p build/Payload
        cp -R build/MACEAgent.xcarchive/Products/Applications/MACEAgent.app build/Payload/
        (cd build && zip -qr ../../../../../../dist/MACEAgent.ipa Payload)
        echo "✓ dist/MACEAgent.ipa (unsigned)"
    else
        echo "✗ xcodebuild archive failed"; exit 1
    fi
else
    echo "✗ xcodegen not found. Install with: brew install xcodegen"
    echo "  then re-run: bash build_ios.sh"
    exit 1
fi
