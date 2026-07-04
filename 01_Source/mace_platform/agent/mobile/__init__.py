"""
Mobile endpoint adapters for the MACE Endpoint Agent.

Mobile platforms (Android, iOS / iPadOS) have OS-imposed sandboxes that block
the same shell-level introspection used on macOS/Linux/Windows. UMEA supports
them in two complementary ways:

  1. Native module (shipped via MDM / enterprise app stores)
       - Android: a Kotlin/Java service in the MACE Mobile Agent APK that
         calls Build, PackageManager, DevicePolicyManager and KeyStore APIs
         and posts reports over the same /agent ingest endpoint.
       - iOS:     a Swift app delivered through Apple Business Manager /
         Intune that uses MDM query commands (DeviceInformation,
         InstalledApplicationList, SecurityInfo) and reports back.

  2. Tethered scan (for ad-hoc / one-off audits)
       - Android: query a USB-connected device with `adb shell getprop`,
         `pm list packages -f`, `dumpsys`.
       - iOS:     query a USB-connected device with libimobiledevice
         (`ideviceinfo`, `ideviceinstaller -l`) when available.

These adapters return MACEAgentReport bundles with the same shape as the
desktop collectors so downstream MACE pipeline code doesn't branch.
"""
from .android import collect_android, scan_android
from .ios import collect_ios, scan_ios

__all__ = ["collect_android", "scan_android", "collect_ios", "scan_ios"]
