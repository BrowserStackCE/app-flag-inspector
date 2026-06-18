# 🔍 app-flag-inspector

A CLI utility to **decompile and inspect Android APK / iOS IPA security flags** — like `FLAG_SECURE`, DRM protection, root detection, SSL pinning, and more.

Built for developers and QA engineers debugging apps on **BrowserStack App Live**, **screen mirroring tools**, or any environment where screenshot/screen-recording blocking causes issues.

## Quick Start

```bash
# Inspect an APK (no install needed)
npx app-flag-inspector inspect myapp.apk

# Or just pass the file directly
npx app-flag-inspector myapp.apk

# Inspect an IPA
npx app-flag-inspector inspect myapp.ipa
```

## Installation

```bash
# Use directly with npx (no install)
npx app-flag-inspector <command>

# Or install globally
npm install -g app-flag-inspector
```

### Prerequisites

| Tool | Required For | Install |
|------|-------------|---------|
| **apktool** | Decompiling APKs | `brew install apktool` (auto-installed if missing) |
| **Android SDK Build Tools** | Recompile only | Install via [Android Studio](https://developer.android.com/studio) |
| **zipalign** | Recompile only | Included with Android SDK Build Tools |
| **apksigner** | Recompile only | Included with Android SDK Build Tools |

> **Note:** For the default `inspect` command, only `apktool` is needed — the tool will auto-install it via Homebrew if it's not found.

## Commands

### `inspect` (default)

Decompiles the app and scans for security flags. **No modifications are made.**

```bash
npx app-flag-inspector inspect <file.apk|file.ipa> [options]
```

| Option | Description |
|--------|-------------|
| `-o, --output <dir>` | Custom output directory for decompiled files |
| `--keep` | Keep decompiled output after inspection (default: cleaned up) |
| `--json` | Output results as JSON (for CI/CD pipelines) |

**Example output:**

```
🔍 App Flag Inspector — APK Analysis

  File: /path/to/myapp.apk
  Size: 45.23 MB

📱 App Info

  Package:    com.example.myapp
  Min SDK:    24
  Target SDK: 34
  Debuggable: No

🚩 Security Flags Detected: 3

┌─────────────────────────┬──────────┬────────────────────┬──────────────────────────────┬────────┬────────────┐
│ Flag                    │ Severity │ Method             │ File                         │ Line   │ Patchable  │
├─────────────────────────┼──────────┼────────────────────┼──────────────────────────────┼────────┼────────────┤
│ FLAG_SECURE             │ HIGH     │ setFlags           │ smali_classes9/com/app/...   │ 480    │ Yes        │
│ Root Detection          │ MEDIUM   │ Various            │ 12 file(s)                   │ -      │ No         │
│ SSL/Certificate Pinning │ MEDIUM   │ Various            │ 8 file(s)                    │ -      │ No         │
└─────────────────────────┴──────────┴────────────────────┴──────────────────────────────┴────────┴────────────┘

💡 1 flag(s) can be auto-patched. Run with the recompile command:
   npx app-flag-inspector recompile myapp.apk
```

### `recompile`

Patches `FLAG_SECURE` (sets `0x2000` → `0x0`), recompiles, aligns, and signs the APK.

```bash
npx app-flag-inspector recompile <file.apk> [options]
```

| Option | Description |
|--------|-------------|
| `-o, --output <file>` | Output path for patched APK |
| `--no-sign` | Skip signing (you'll need to sign manually) |
| `--keystore <path>` | Path to your keystore file |
| `--alias <name>` | Key alias (default: `mykey`) |

> ⚠️ **Recompile requires Android SDK Build Tools** (`zipalign`, `apksigner`) which come with [Android Studio](https://developer.android.com/studio). After installing, add to your PATH:
> ```bash
> export PATH=$PATH:$ANDROID_HOME/build-tools/<version>
> ```

**Example:**

```bash
# Auto-patch and sign with a debug keystore
npx app-flag-inspector recompile myapp.apk

# Use your own keystore
npx app-flag-inspector recompile myapp.apk --keystore release.jks --alias mykey

# Recompile without signing
npx app-flag-inspector recompile myapp.apk --no-sign
```

### `check-deps`

Verify all dependencies are installed.

```bash
npx app-flag-inspector check-deps
```

```
🔍 Checking dependencies...

  ✔ installed  apktool (required)
  ✔ installed  zipalign (optional — for recompile)
  ✘ not found  apksigner (optional — for recompile)
                Install: Included with Android SDK Build Tools
  ✔ installed  keytool (optional — for recompile)
```

## What It Detects

| Flag / Pattern | Platform | Severity | Auto-Patchable |
|---------------|----------|----------|----------------|
| `FLAG_SECURE` (setFlags / addFlags) | Android | 🔴 HIGH | ✅ Yes |
| `SurfaceView.setSecure()` | Android | 🔴 HIGH | ❌ No |
| `ScreenCaptureCallback` (API 34+) | Android | 🟡 MEDIUM | ❌ No |
| DRM Protection (`MediaDrm`) | Android | 🔴 HIGH | ❌ No |
| Root / Tamper Detection | Android | 🟡 MEDIUM | ❌ No |
| SSL / Certificate Pinning | Android | 🟡 MEDIUM | ❌ No |
| Screenshot Prevention (secure text overlay) | iOS | 🔴 HIGH | ❌ No |
| Jailbreak Detection | iOS | 🟡 MEDIUM | ❌ No |

## CI/CD Integration

Use `--json` for machine-readable output:

```bash
npx app-flag-inspector inspect myapp.apk --json > report.json
```

Example in a GitHub Actions workflow:

```yaml
- name: Check APK security flags
  run: |
    npx app-flag-inspector inspect app/build/outputs/apk/debug/app-debug.apk --json > flags.json
    # Fail if FLAG_SECURE is found
    if jq -e '.findings[] | select(.flag == "FLAG_SECURE")' flags.json > /dev/null 2>&1; then
      echo "::error::FLAG_SECURE detected in APK"
      exit 1
    fi
```

## How It Works

1. **Decompile** — Uses `apktool` to decompile the APK into smali bytecode
2. **Scan** — Greps smali code for known security flag patterns (`0x2000` for `FLAG_SECURE`, `MediaDrm`, `RootBeer`, etc.)
3. **Report** — Displays findings with file locations, severity, and whether they can be auto-patched
4. **Cleanup** — Removes decompiled files (unless `--keep` is used)

For `recompile`:
5. **Patch** — Replaces `0x2000` with `0x0` in smali code near `Window.setFlags()` / `addFlags()` calls
6. **Rebuild** — Uses `apktool b` to recompile the patched smali back into an APK
7. **Align & Sign** — Runs `zipalign` and `apksigner` to produce an installable APK

## ⚠️ Important Notes

- **Recompiling may break apps** that have certificate pinning, root detection, or tamper checks — the re-signed APK will have a different certificate.
- **This tool is for debugging/testing only.** Do not distribute patched APKs.
- **IPA support is basic** — iOS apps are compiled to native ARM, so deep binary analysis requires additional tools.
- The `inspect` command is **read-only** and makes no modifications to the original file.

## License

MIT
