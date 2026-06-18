const { execSync, exec } = require('child_process');
const path = require('path');
const fs = require('fs');
const chalk = require('chalk');
const ora = require('ora');
const Table = require('cli-table3');
const { ensureApktool } = require('./deps');
const { GREP_PATTERNS } = require('./flags');

/**
 * Main inspect command — decompiles APK/IPA and scans for security flags.
 */
async function inspect(filePath, options) {
  const absPath = path.resolve(filePath);

  // Validate file exists
  if (!fs.existsSync(absPath)) {
    console.error(chalk.red(`\n✘ File not found: ${absPath}\n`));
    process.exit(1);
  }

  const ext = path.extname(absPath).toLowerCase();

  if (ext === '.apk') {
    await inspectApk(absPath, options);
  } else if (ext === '.ipa') {
    await inspectIpa(absPath, options);
  } else {
    console.error(chalk.red(`\n✘ Unsupported file type: ${ext}. Provide an .apk or .ipa file.\n`));
    process.exit(1);
  }
}

/**
 * Inspect an Android APK file.
 */
async function inspectApk(apkPath, options) {
  console.log(chalk.bold.cyan('\n🔍 App Flag Inspector — APK Analysis\n'));
  console.log(chalk.gray(`  File: ${apkPath}`));
  console.log(chalk.gray(`  Size: ${(fs.statSync(apkPath).size / (1024 * 1024)).toFixed(2)} MB\n`));

  // 1. Ensure apktool is available
  const hasApktool = await ensureApktool();
  if (!hasApktool) {
    process.exit(1);
  }

  // 2. Decompile
  const outputDir = options.output || path.join(
    path.dirname(apkPath),
    `decompiled_${path.basename(apkPath, '.apk')}`
  );

  const spinner = ora('Decompiling APK with apktool...').start();

  try {
    // Remove existing output dir if present
    if (fs.existsSync(outputDir)) {
      fs.rmSync(outputDir, { recursive: true, force: true });
    }

    execSync(`apktool d "${apkPath}" -o "${outputDir}" -f`, {
      stdio: 'pipe',
      timeout: 300000, // 5 min timeout
    });
    spinner.succeed('APK decompiled successfully');
  } catch (e) {
    spinner.fail('Failed to decompile APK');
    console.error(chalk.red(`\n  Error: ${e.message}\n`));
    process.exit(1);
  }

  // 3. Scan for flags
  const scanSpinner = ora('Scanning smali code for security flags...').start();
  const results = scanSmaliForFlags(outputDir);
  scanSpinner.succeed('Scan complete');

  // 4. Check AndroidManifest.xml for additional info
  const manifestInfo = parseManifest(outputDir);

  // 5. Display results
  displayResults(results, manifestInfo, options);

  // 6. Cleanup unless --keep
  if (!options.keep) {
    const cleanSpinner = ora('Cleaning up decompiled files...').start();
    try {
      fs.rmSync(outputDir, { recursive: true, force: true });
      cleanSpinner.succeed('Cleaned up');
    } catch (e) {
      cleanSpinner.warn('Could not clean up decompiled directory');
    }
  } else {
    console.log(chalk.gray(`\n  📁 Decompiled output kept at: ${outputDir}\n`));
  }
}

/**
 * Scan decompiled smali directories for security flag patterns.
 */
function scanSmaliForFlags(outputDir) {
  const findings = [];

  // Find all smali directories
  const entries = fs.readdirSync(outputDir);
  const smaliDirs = entries.filter(e =>
    e.startsWith('smali') && fs.statSync(path.join(outputDir, e)).isDirectory()
  );

  if (smaliDirs.length === 0) {
    console.log(chalk.yellow('  ⚠ No smali directories found. APK may be obfuscated or use a non-standard structure.'));
    return findings;
  }

  // --- FLAG_SECURE detection (grep-based, fast) ---
  // setFlags
  try {
    const setFlagsResult = execSync(
      `grep -rn "Window;->setFlags" ${smaliDirs.map(d => `"${path.join(outputDir, d)}"`).join(' ')} 2>/dev/null || true`,
      { encoding: 'utf-8', maxBuffer: 50 * 1024 * 1024 }
    );
    const setFlagsLines = setFlagsResult.trim().split('\n').filter(Boolean);

    for (const line of setFlagsLines) {
      const match = line.match(/^(.+?):(\d+):/);
      if (!match) continue;

      const [, filePath, lineNum] = match;
      const lineNumber = parseInt(lineNum, 10);

      // Read surrounding context to check for 0x2000
      const context = readContext(filePath, lineNumber, 10);
      if (context.includes('0x2000')) {
        findings.push({
          flag: 'FLAG_SECURE',
          method: 'setFlags',
          file: path.relative(outputDir, filePath),
          line: lineNumber,
          severity: 'HIGH',
          constant: '0x2000',
          context: context,
          patchable: true,
        });
      }
    }
  } catch (e) { /* grep returned nothing */ }

  // addFlags
  try {
    const addFlagsResult = execSync(
      `grep -rn "Window;->addFlags" ${smaliDirs.map(d => `"${path.join(outputDir, d)}"`).join(' ')} 2>/dev/null || true`,
      { encoding: 'utf-8', maxBuffer: 50 * 1024 * 1024 }
    );
    const addFlagsLines = addFlagsResult.trim().split('\n').filter(Boolean);

    for (const line of addFlagsLines) {
      const match = line.match(/^(.+?):(\d+):/);
      if (!match) continue;

      const [, filePath, lineNum] = match;
      const lineNumber = parseInt(lineNum, 10);

      const context = readContext(filePath, lineNumber, 10);
      if (context.includes('0x2000')) {
        findings.push({
          flag: 'FLAG_SECURE',
          method: 'addFlags',
          file: path.relative(outputDir, filePath),
          line: lineNumber,
          severity: 'HIGH',
          constant: '0x2000',
          context: context,
          patchable: true,
        });
      }
    }
  } catch (e) { /* grep returned nothing */ }

  // --- Screenshot Capture Callback (API 34+) ---
  try {
    const callbackResult = execSync(
      `grep -rn "registerScreenCaptureCallback" ${smaliDirs.map(d => `"${path.join(outputDir, d)}"`).join(' ')} 2>/dev/null || true`,
      { encoding: 'utf-8', maxBuffer: 50 * 1024 * 1024 }
    );
    const callbackLines = callbackResult.trim().split('\n').filter(Boolean);

    for (const line of callbackLines) {
      const match = line.match(/^(.+?):(\d+):/);
      if (!match) continue;

      findings.push({
        flag: 'ScreenCaptureCallback',
        method: 'registerScreenCaptureCallback',
        file: path.relative(outputDir, match[1]),
        line: parseInt(match[2], 10),
        severity: 'MEDIUM',
        constant: 'N/A',
        context: line,
        patchable: false,
      });
    }
  } catch (e) { /* */ }

  // --- SurfaceView.setSecure ---
  try {
    const surfaceResult = execSync(
      `grep -rn "SurfaceView;->setSecure" ${smaliDirs.map(d => `"${path.join(outputDir, d)}"`).join(' ')} 2>/dev/null || true`,
      { encoding: 'utf-8', maxBuffer: 50 * 1024 * 1024 }
    );
    const surfaceLines = surfaceResult.trim().split('\n').filter(Boolean);

    for (const line of surfaceLines) {
      const match = line.match(/^(.+?):(\d+):/);
      if (!match) continue;

      findings.push({
        flag: 'SurfaceView.setSecure',
        method: 'setSecure',
        file: path.relative(outputDir, match[1]),
        line: parseInt(match[2], 10),
        severity: 'HIGH',
        constant: 'true',
        context: line,
        patchable: false,
      });
    }
  } catch (e) { /* */ }

  // --- DRM / MediaDrm detection ---
  try {
    const drmResult = execSync(
      `grep -rn "MediaDrm" ${smaliDirs.map(d => `"${path.join(outputDir, d)}"`).join(' ')} 2>/dev/null || true`,
      { encoding: 'utf-8', maxBuffer: 50 * 1024 * 1024 }
    );
    const drmLines = drmResult.trim().split('\n').filter(Boolean);

    if (drmLines.length > 0) {
      findings.push({
        flag: 'DRM Protection',
        method: 'MediaDrm',
        file: `${drmLines.length} file(s)`,
        line: '-',
        severity: 'HIGH',
        constant: 'N/A',
        context: `Found MediaDrm usage in ${drmLines.length} location(s)`,
        patchable: false,
      });
    }
  } catch (e) { /* */ }

  // --- Root / Tamper detection ---
  try {
    const rootResult = execSync(
      `grep -rln "RootBeer\\|isRooted\\|SafetyNet\\|isDeviceRooted\\|su_binary" ${smaliDirs.map(d => `"${path.join(outputDir, d)}"`).join(' ')} 2>/dev/null || true`,
      { encoding: 'utf-8', maxBuffer: 50 * 1024 * 1024 }
    );
    const rootFiles = rootResult.trim().split('\n').filter(Boolean);

    if (rootFiles.length > 0) {
      findings.push({
        flag: 'Root Detection',
        method: 'Various',
        file: `${rootFiles.length} file(s)`,
        line: '-',
        severity: 'MEDIUM',
        constant: 'N/A',
        context: `Root/tamper detection found in ${rootFiles.length} file(s)`,
        patchable: false,
      });
    }
  } catch (e) { /* */ }

  // --- SSL Pinning ---
  try {
    const sslResult = execSync(
      `grep -rln "CertificatePinner\\|X509TrustManager\\|checkServerTrusted\\|network_security_config" ${smaliDirs.map(d => `"${path.join(outputDir, d)}"`).join(' ')} 2>/dev/null || true`,
      { encoding: 'utf-8', maxBuffer: 50 * 1024 * 1024 }
    );
    const sslFiles = sslResult.trim().split('\n').filter(Boolean);

    if (sslFiles.length > 0) {
      findings.push({
        flag: 'SSL/Certificate Pinning',
        method: 'Various',
        file: `${sslFiles.length} file(s)`,
        line: '-',
        severity: 'MEDIUM',
        constant: 'N/A',
        context: `SSL pinning detected in ${sslFiles.length} file(s)`,
        patchable: false,
      });
    }
  } catch (e) { /* */ }

  return findings;
}

/**
 * Read lines around a given line number for context.
 */
function readContext(filePath, lineNumber, range) {
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const lines = content.split('\n');
    const start = Math.max(0, lineNumber - range - 1);
    const end = Math.min(lines.length, lineNumber + range);
    return lines.slice(start, end).join('\n');
  } catch (e) {
    return '';
  }
}

/**
 * Parse AndroidManifest.xml for useful metadata.
 */
function parseManifest(outputDir) {
  const manifestPath = path.join(outputDir, 'AndroidManifest.xml');
  const info = {
    packageName: 'unknown',
    minSdk: 'unknown',
    targetSdk: 'unknown',
    permissions: [],
    debuggable: false,
    networkSecurityConfig: false,
  };

  if (!fs.existsSync(manifestPath)) return info;

  try {
    const content = fs.readFileSync(manifestPath, 'utf-8');

    // Package name
    const pkgMatch = content.match(/package="([^"]+)"/);
    if (pkgMatch) info.packageName = pkgMatch[1];

    // SDK versions
    const minSdkMatch = content.match(/android:minSdkVersion="(\d+)"/);
    if (minSdkMatch) info.minSdk = minSdkMatch[1];

    const targetSdkMatch = content.match(/android:targetSdkVersion="(\d+)"/);
    if (targetSdkMatch) info.targetSdk = targetSdkMatch[1];

    // Debuggable
    info.debuggable = content.includes('android:debuggable="true"');

    // Network security config
    info.networkSecurityConfig = content.includes('networkSecurityConfig');

    // Permissions
    const permRegex = /android:name="android\.permission\.([^"]+)"/g;
    let permMatch;
    while ((permMatch = permRegex.exec(content)) !== null) {
      info.permissions.push(permMatch[1]);
    }
  } catch (e) { /* */ }

  return info;
}

/**
 * Display scan results in a formatted table.
 */
function displayResults(findings, manifestInfo, options) {
  // JSON output
  if (options.json) {
    console.log(JSON.stringify({ manifest: manifestInfo, findings }, null, 2));
    return;
  }

  // App info
  console.log(chalk.bold('\n📱 App Info\n'));
  console.log(`  Package:    ${chalk.white(manifestInfo.packageName)}`);
  console.log(`  Min SDK:    ${manifestInfo.minSdk}`);
  console.log(`  Target SDK: ${manifestInfo.targetSdk}`);
  console.log(`  Debuggable: ${manifestInfo.debuggable ? chalk.green('Yes') : chalk.gray('No')}`);
  console.log(`  Network Security Config: ${manifestInfo.networkSecurityConfig ? chalk.yellow('Yes') : chalk.gray('No')}`);

  // Findings
  if (findings.length === 0) {
    console.log(chalk.green('\n✅ No security flags detected! The app should work fine with screen capture / App Live.\n'));
    return;
  }

  console.log(chalk.bold(`\n🚩 Security Flags Detected: ${findings.length}\n`));

  const table = new Table({
    head: [
      chalk.white('Flag'),
      chalk.white('Severity'),
      chalk.white('Method'),
      chalk.white('File'),
      chalk.white('Line'),
      chalk.white('Patchable'),
    ],
    colWidths: [25, 10, 20, 50, 8, 12],
    wordWrap: true,
  });

  for (const f of findings) {
    const severityColor = f.severity === 'HIGH' ? chalk.red : f.severity === 'MEDIUM' ? chalk.yellow : chalk.gray;
    table.push([
      chalk.bold(f.flag),
      severityColor(f.severity),
      f.method,
      chalk.gray(f.file),
      f.line,
      f.patchable ? chalk.green('Yes') : chalk.gray('No'),
    ]);
  }

  console.log(table.toString());

  // Summary
  const patchableCount = findings.filter(f => f.patchable).length;
  if (patchableCount > 0) {
    console.log(chalk.cyan(`\n💡 ${patchableCount} flag(s) can be auto-patched. Run with the recompile command:`));
    console.log(chalk.white(`   npx app-flag-inspector recompile <your-app.apk>\n`));
    console.log(chalk.gray('   ⚠  Recompile requires Android SDK (zipalign, apksigner) installed via Android Studio.\n'));
  }

  // Detail for FLAG_SECURE findings
  const secureFindings = findings.filter(f => f.flag === 'FLAG_SECURE');
  if (secureFindings.length > 0) {
    console.log(chalk.bold('📍 FLAG_SECURE Locations:\n'));
    for (const f of secureFindings) {
      console.log(chalk.yellow(`  → ${f.file}:${f.line}`));
      console.log(chalk.gray(`    Method: ${f.method} | Constant: ${f.constant}`));
    }
    console.log('');
  }
}

/**
 * Inspect an iOS IPA file (basic support).
 */
async function inspectIpa(ipaPath, options) {
  console.log(chalk.bold.cyan('\n🔍 App Flag Inspector — IPA Analysis\n'));
  console.log(chalk.gray(`  File: ${ipaPath}`));
  console.log(chalk.gray(`  Size: ${(fs.statSync(ipaPath).size / (1024 * 1024)).toFixed(2)} MB\n`));

  const outputDir = options.output || path.join(
    path.dirname(ipaPath),
    `decompiled_${path.basename(ipaPath, '.ipa')}`
  );

  const spinner = ora('Extracting IPA...').start();

  try {
    if (fs.existsSync(outputDir)) {
      fs.rmSync(outputDir, { recursive: true, force: true });
    }
    fs.mkdirSync(outputDir, { recursive: true });

    execSync(`unzip -o -q "${ipaPath}" -d "${outputDir}"`, { stdio: 'pipe' });
    spinner.succeed('IPA extracted');
  } catch (e) {
    spinner.fail('Failed to extract IPA');
    console.error(chalk.red(`  Error: ${e.message}\n`));
    process.exit(1);
  }

  // Scan for common iOS security patterns
  const scanSpinner = ora('Scanning for security patterns...').start();
  const findings = scanIpaForFlags(outputDir);
  scanSpinner.succeed('Scan complete');

  // Display
  if (findings.length === 0) {
    console.log(chalk.green('\n✅ No obvious security flags detected in IPA.\n'));
  } else {
    console.log(chalk.bold(`\n🚩 Security Patterns Detected: ${findings.length}\n`));
    for (const f of findings) {
      const severityColor = f.severity === 'HIGH' ? chalk.red : f.severity === 'MEDIUM' ? chalk.yellow : chalk.gray;
      console.log(`  ${severityColor('●')} ${chalk.bold(f.flag)} — ${f.description}`);
    }
    console.log('');
  }

  // Cleanup
  if (!options.keep) {
    fs.rmSync(outputDir, { recursive: true, force: true });
  }
}

/**
 * Scan extracted IPA for security patterns.
 */
function scanIpaForFlags(outputDir) {
  const findings = [];

  try {
    // Search for common iOS security strings in binary/plist files
    const grepResult = execSync(
      `grep -rl "isSecureTextEntry\\|makeSecure\\|UITextField" "${outputDir}" 2>/dev/null || true`,
      { encoding: 'utf-8', maxBuffer: 50 * 1024 * 1024 }
    );
    if (grepResult.trim()) {
      findings.push({
        flag: 'Screenshot Prevention',
        severity: 'HIGH',
        description: 'App may use secure text field overlay to prevent screenshots.',
      });
    }
  } catch (e) { /* */ }

  try {
    const jbResult = execSync(
      `grep -rl "cydia://\\|/Applications/Cydia.app\\|isJailbroken" "${outputDir}" 2>/dev/null || true`,
      { encoding: 'utf-8', maxBuffer: 50 * 1024 * 1024 }
    );
    if (jbResult.trim()) {
      findings.push({
        flag: 'Jailbreak Detection',
        severity: 'MEDIUM',
        description: 'App checks for jailbroken devices.',
      });
    }
  } catch (e) { /* */ }

  return findings;
}

module.exports = { inspect };
