# 🔍 app-flag-inspector

> **Decompile → Detect → Patch** Android APK & iOS IPA security flags in one command.

A zero-config CLI utility that detects `FLAG_SECURE`, DRM protection, root detection, SSL pinning, and other security flags that cause **black screens** on BrowserStack App Live, screen mirroring tools, and automated testing environments.

[![npm version](https://img.shields.io/npm/v/app-flag-inspector)](https://www.npmjs.com/package/app-flag-inspector)
[![license](https://img.shields.io/npm/l/app-flag-inspector)](https://opensource.org/licenses/MIT)

## Quick Start

```bash
# Inspect an APK — zero install, just run
npx app-flag-inspector myapp.apk

# Inspect + auto-patch FLAG_SECURE
npx app-flag-inspector inspect myapp.apk --autofix

# Inspect an IPA
npx app-flag-inspector myapp.ipa
```

> **Zero dependencies to manage.** The tool auto-installs [Homebrew](https://brew.sh) and [apktool](https://apktool.org) if they're missing — just run it.

## Installation

```bash
# Use directly with npx (recommended — no install needed)
npx app-flag-inspector <command>

# Or install globally
npm install -g app-flag-inspector
```

### Prerequisites

| Tool                        | Required For       | Auto-Installed?                                                            |
| --------------------------- | ------------------ | -------------------------------------------------------------------------- |
| **Homebrew**                | Installing apktool | ✅ Yes — installed automatically if missing                                |
| **apktool**                 | Decompiling APKs   | ✅ Yes — installed via Homebrew automatically                              |
| **Android SDK Build Tools** | `recompile` only   | ❌ No — install via [Android Studio](https://developer.android.com/studio) |
| **zipalign**                | `recompile` only   | ❌ No — included with Android SDK Build Tools                              |
| **apksigner**               | `recompile` only   | ❌ No — included with Android SDK Build Tools                              |

> **For `inspect` and `inspect --autofix`**, you don't need to install anything manually — the tool handles it.
> **For `recompile`**, you need Android Studio's SDK Build Tools on your PATH.

## Commands

### `inspect` (default)

Decompiles the app and scans for security flags. **No modifications are made** (unless `--autofix` is used).

```bash
npx app-flag-inspector inspect <file.apk|file.ipa> [options]

# Shortcut — just pass the file
npx app-flag-inspector myapp.apk
```

| Option               | Description                                                   |
| -------------------- | ------------------------------------------------------------- |
| `-o, --output <dir>` | Custom output directory for decompiled files                  |
| `--keep`             | Keep decompiled output after inspection (default: cleaned up) |
| `--json`             | Output results as JSON (for CI/CD pipelines)                  |
| `--autofix`          | Automatically patch and remove high-severity flags            |

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

💡 1 flag(s) can be auto-patched. Run with --autofix:
   npx app-flag-inspector inspect myapp.apk --autofix
```

### `inspect --autofix`

Scans **and patches** high-severity flags in the decompiled smali code. The patched source is kept so you can recompile it.

```bash
npx app-flag-inspector inspect myapp.apk --autofix
```

**What it patches:**

- `FLAG_SECURE` via `Window.setFlags()` / `Window.addFlags()` — sets `0x2000` → `0x0`
- `SurfaceView.setSecure(true)` — sets `0x1` → `0x0`

**What it does NOT patch** (reported only):

- DRM / MediaDrm
- Root / jailbreak detection
- SSL / certificate pinning
- ScreenCaptureCallback (API 34+)

**Example output:**

```
🔧 Autofix — Patching high-severity flags

  ✔ FLAG_SECURE patched
    smali_classes9/com/zehnder/entergy/EntergyBaseFragment.smali:478
    - const/16 v1, 0x2000
    + const/16 v1, 0x0

  ✅ 1 flag(s) patched successfully.

✔ Verification complete — all high-severity patchable flags removed

  📂 Patched decompiled source kept at: /path/to/decompiled_myapp
     To rebuild the APK, run:
     npx app-flag-inspector recompile myapp.apk
```

### `recompile`

Patches `FLAG_SECURE`, recompiles, aligns, and signs the APK — all in one step.

```bash
npx app-flag-inspector recompile <file.apk> [options]
```

| Option                | Description                                 |
| --------------------- | ------------------------------------------- |
| `-o, --output <file>` | Output path for patched APK                 |
| `--no-sign`           | Skip signing (you'll need to sign manually) |
| `--keystore <path>`   | Path to your keystore file                  |
| `--alias <name>`      | Key alias (default: `mykey`)                |

> ⚠️ **Requires Android SDK Build Tools** (`zipalign`, `apksigner`) from [Android Studio](https://developer.android.com/studio). After installing, add to your PATH:
>
> ```bash
> export PATH=$PATH:$ANDROID_HOME/build-tools/<version>
> ```

**Examples:**

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

| Flag / Pattern                              | Platform | Severity  | Auto-Patchable |
| ------------------------------------------- | -------- | --------- | -------------- |
| `FLAG_SECURE` (setFlags / addFlags)         | Android  | 🔴 HIGH   | ✅ Yes         |
| `SurfaceView.setSecure()`                   | Android  | 🔴 HIGH   | ✅ Yes         |
| `ScreenCaptureCallback` (API 34+)           | Android  | 🟡 MEDIUM | ❌ No          |
| DRM Protection (`MediaDrm`)                 | Android  | 🔴 HIGH   | ❌ No          |
| Root / Tamper Detection                     | Android  | 🟡 MEDIUM | ❌ No          |
| SSL / Certificate Pinning                   | Android  | 🟡 MEDIUM | ❌ No          |
| Screenshot Prevention (secure text overlay) | iOS      | 🔴 HIGH   | ❌ No          |
| Jailbreak Detection                         | iOS      | 🟡 MEDIUM | ❌ No          |

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
2. **Scan** — Walks smali files method-by-method, checking if `const 0x2000` feeds into `Window.setFlags()` / `addFlags()` within the same method (no false positives from unrelated code)
3. **Report** — Displays findings with file locations, severity, and whether they can be auto-patched
4. **Autofix** _(optional)_ — Patches `0x2000` → `0x0` in-place, then re-scans to verify
5. **Cleanup** — Removes decompiled files (unless `--keep` or `--autofix` is used)

For `recompile`:

6. **Patch** — Replaces `0x2000` with `0x0` in smali code near `Window.setFlags()` / `addFlags()` calls
7. **Rebuild** — Uses `apktool b` to recompile the patched smali back into an APK
8. **Align & Sign** — Runs `zipalign` and `apksigner` to produce an installable APK

## Auto-Install Chain

When you run the tool for the first time, it automatically sets up everything needed:

```
apktool missing?
  └─→ brew missing?
  │     └─→ Install Homebrew automatically
  │     └─→ Add brew to PATH
  └─→ brew install apktool
  └─→ Continue with inspection
```

No manual setup required for `inspect` and `inspect --autofix`.

## ⚠️ Important Notes

- **Recompiling may break apps** that have certificate pinning, root detection, or tamper checks — the re-signed APK will have a different certificate.
- **This tool is for debugging/testing only.** Do not distribute patched APKs.
- **IPA support is basic** — iOS apps are compiled to native ARM, so deep binary analysis requires additional tools.
- The `inspect` command (without `--autofix`) is **read-only** and makes no modifications to the original file.
- `--autofix` modifies the **decompiled source only** — your original APK is never touched.

## License

MIT
