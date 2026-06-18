const { execSync } = require('child_process');
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
    if (options.autofix) {
      console.log(
        chalk.yellow(
          '\n⚠  --autofix is not supported for IPA files (iOS binaries cannot be patched this way).\n',
        ),
      );
    }
    await inspectIpa(absPath, options);
  } else {
    console.error(
      chalk.red(
        `\n✘ Unsupported file type: ${ext}. Provide an .apk or .ipa file.\n`,
      ),
    );
    process.exit(1);
  }
}

/**
 * Inspect an Android APK file.
 */
async function inspectApk(apkPath, options) {
  console.log(chalk.bold.cyan('\n🔍 App Flag Inspector — APK Analysis\n'));
  console.log(chalk.gray(`  File: ${apkPath}`));
  console.log(
    chalk.gray(
      `  Size: ${(fs.statSync(apkPath).size / (1024 * 1024)).toFixed(2)} MB\n`,
    ),
  );

  // 1. Ensure apktool is available
  const hasApktool = await ensureApktool();
  if (!hasApktool) {
    process.exit(1);
  }

  // 2. Decompile
  const outputDir =
    options.output ||
    path.join(
      path.dirname(apkPath),
      `decompiled_${path.basename(apkPath, '.apk')}`,
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

  // 3. Scan for flags — use precise file-level scanning
  const scanSpinner = ora('Scanning smali code for security flags...').start();
  const results = scanSmaliForFlags(outputDir);
  scanSpinner.succeed('Scan complete');

  // 4. Check AndroidManifest.xml for additional info
  const manifestInfo = parseManifest(outputDir);

  // 5. Display results
  displayResults(results, manifestInfo, options);

  // 6. Autofix — patch high-severity flags if --autofix is set
  let autofixResults = [];
  if (options.autofix) {
    autofixResults = runAutofix(outputDir, results);

    // 6b. Re-scan to verify patches applied and show updated state
    console.log('');
    const verifySpinner = ora('Verifying patches...').start();
    const postResults = scanSmaliForFlags(outputDir);
    const remainingPatchable = postResults.filter(
      (f) => f.severity === 'HIGH' && f.patchable && f.found !== false,
    );

    if (remainingPatchable.length === 0) {
      verifySpinner.succeed(
        'Verification complete — all high-severity patchable flags removed',
      );
    } else {
      verifySpinner.warn(
        `Verification complete — ${remainingPatchable.length} high-severity patchable flag(s) still present`,
      );
      for (const r of remainingPatchable) {
        console.log(
          chalk.yellow(`    ⚠ ${r.flag} still found in ${r.file}:${r.line}`),
        );
      }
    }
  }

  // 7. Cleanup unless --keep or --autofix (autofix always keeps for recompile)
  if (options.autofix) {
    // Always keep when autofix is used — user needs the patched source to recompile
    console.log(
      chalk.cyan(
        `\n  📂 Patched decompiled source kept at: ${chalk.bold(outputDir)}`,
      ),
    );
    console.log(chalk.gray('     To rebuild the APK, run:'));
    console.log(
      chalk.white(
        `     npx app-flag-inspector recompile ${path.basename(apkPath)}\n`,
      ),
    );
  } else if (!options.keep) {
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
 *
 * Uses precise per-file analysis: for each file containing a setFlags/addFlags call,
 * reads the file and checks whether a const 0x2000 actually feeds into that specific call
 * (within a tight window), avoiding false positives from unrelated methods in the same file.
 */
function scanSmaliForFlags(outputDir) {
  const findings = [];

  // Find all smali directories
  const entries = fs.readdirSync(outputDir);
  const smaliDirs = entries.filter(
    (e) =>
      e.startsWith('smali') &&
      fs.statSync(path.join(outputDir, e)).isDirectory(),
  );

  if (smaliDirs.length === 0) {
    console.log(
      chalk.yellow(
        '  ⚠ No smali directories found. APK may be obfuscated or use a non-standard structure.',
      ),
    );
    return findings;
  }

  const smaliPaths = smaliDirs
    .map((d) => `"${path.join(outputDir, d)}"`)
    .join(' ');

  // --- FLAG_SECURE detection ---
  // Scan for setFlags
  findFlagSecureByMethod(
    smaliPaths,
    outputDir,
    'Window;->setFlags',
    'setFlags',
    findings,
  );
  // Scan for addFlags
  findFlagSecureByMethod(
    smaliPaths,
    outputDir,
    'Window;->addFlags',
    'addFlags',
    findings,
  );

  // --- SurfaceView.setSecure ---
  try {
    const surfaceResult = execSync(
      `grep -rn "SurfaceView;->setSecure" ${smaliPaths} 2>/dev/null || true`,
      { encoding: 'utf-8', maxBuffer: 50 * 1024 * 1024 },
    );
    const surfaceLines = surfaceResult.trim().split('\n').filter(Boolean);

    for (const line of surfaceLines) {
      const match = line.match(/^(.+?):(\d+):/);
      if (!match) continue;

      findings.push({
        flag: 'SurfaceView.setSecure',
        method: 'setSecure',
        file: path.relative(outputDir, match[1]),
        absFile: match[1],
        line: parseInt(match[2], 10),
        severity: 'HIGH',
        constant: 'true',
        context: line,
        patchable: true,
      });
    }
  } catch (e) {
    /* */
  }

  // --- Screenshot Capture Callback (API 34+) ---
  try {
    const callbackResult = execSync(
      `grep -rn "registerScreenCaptureCallback" ${smaliPaths} 2>/dev/null || true`,
      { encoding: 'utf-8', maxBuffer: 50 * 1024 * 1024 },
    );
    const callbackLines = callbackResult.trim().split('\n').filter(Boolean);

    for (const line of callbackLines) {
      const match = line.match(/^(.+?):(\d+):/);
      if (!match) continue;

      findings.push({
        flag: 'ScreenCaptureCallback',
        method: 'registerScreenCaptureCallback',
        file: path.relative(outputDir, match[1]),
        absFile: match[1],
        line: parseInt(match[2], 10),
        severity: 'MEDIUM',
        constant: 'N/A',
        context: line,
        patchable: false,
      });
    }
  } catch (e) {
    /* */
  }

  // --- DRM / MediaDrm detection ---
  try {
    const drmResult = execSync(
      `grep -rn "MediaDrm" ${smaliPaths} 2>/dev/null || true`,
      { encoding: 'utf-8', maxBuffer: 50 * 1024 * 1024 },
    );
    const drmLines = drmResult.trim().split('\n').filter(Boolean);

    if (drmLines.length > 0) {
      findings.push({
        flag: 'DRM Protection',
        method: 'MediaDrm',
        file: `${drmLines.length} file(s)`,
        absFile: null,
        line: '-',
        severity: 'HIGH',
        constant: 'N/A',
        context: `Found MediaDrm usage in ${drmLines.length} location(s)`,
        patchable: false,
      });
    }
  } catch (e) {
    /* */
  }

  // --- Root / Tamper detection ---
  try {
    const rootResult = execSync(
      `grep -rln "RootBeer\\|isRooted\\|SafetyNet\\|isDeviceRooted\\|su_binary" ${smaliPaths} 2>/dev/null || true`,
      { encoding: 'utf-8', maxBuffer: 50 * 1024 * 1024 },
    );
    const rootFiles = rootResult.trim().split('\n').filter(Boolean);

    if (rootFiles.length > 0) {
      findings.push({
        flag: 'Root Detection',
        method: 'Various',
        file: `${rootFiles.length} file(s)`,
        absFile: null,
        line: '-',
        severity: 'MEDIUM',
        constant: 'N/A',
        context: `Root/tamper detection found in ${rootFiles.length} file(s)`,
        patchable: false,
      });
    }
  } catch (e) {
    /* */
  }

  // --- SSL Pinning ---
  try {
    const sslResult = execSync(
      `grep -rln "CertificatePinner\\|X509TrustManager\\|checkServerTrusted\\|network_security_config" ${smaliPaths} 2>/dev/null || true`,
      { encoding: 'utf-8', maxBuffer: 50 * 1024 * 1024 },
    );
    const sslFiles = sslResult.trim().split('\n').filter(Boolean);

    if (sslFiles.length > 0) {
      findings.push({
        flag: 'SSL/Certificate Pinning',
        method: 'Various',
        file: `${sslFiles.length} file(s)`,
        absFile: null,
        line: '-',
        severity: 'MEDIUM',
        constant: 'N/A',
        context: `SSL pinning detected in ${sslFiles.length} file(s)`,
        patchable: false,
      });
    }
  } catch (e) {
    /* */
  }

  return findings;
}

/**
 * Precise FLAG_SECURE detection for a specific method (setFlags or addFlags).
 *
 * For each file containing the method call, reads the file and walks through
 * line by line. For each setFlags/addFlags call found, looks BACKWARDS (up to 15 lines)
 * for a `const 0x2000`. This avoids false positives where 0x2000 exists in a
 * completely different method in the same file.
 */
function findFlagSecureByMethod(
  smaliPaths,
  outputDir,
  grepPattern,
  methodName,
  findings,
) {
  try {
    const result = execSync(
      `grep -rn "${grepPattern}" ${smaliPaths} 2>/dev/null || true`,
      { encoding: 'utf-8', maxBuffer: 50 * 1024 * 1024 },
    );
    const hitLines = result.trim().split('\n').filter(Boolean);

    // Group hits by file to avoid reading the same file multiple times
    const hitsByFile = {};
    for (const line of hitLines) {
      const match = line.match(/^(.+?):(\d+):/);
      if (!match) continue;
      const [, filePath, lineNum] = match;
      if (!hitsByFile[filePath]) hitsByFile[filePath] = [];
      hitsByFile[filePath].push(parseInt(lineNum, 10));
    }

    for (const [filePath, callLines] of Object.entries(hitsByFile)) {
      let fileContent;
      try {
        fileContent = fs.readFileSync(filePath, 'utf-8');
      } catch (e) {
        continue;
      }
      const lines = fileContent.split('\n');

      for (const callLineNum of callLines) {
        const callLineIdx = callLineNum - 1; // 0-based

        // Look backwards from the call for a const loading 0x2000
        const searchStart = Math.max(0, callLineIdx - 15);
        let foundConst = false;

        for (let i = callLineIdx - 1; i >= searchStart; i--) {
          const l = lines[i];

          // Stop at method boundary — if we hit .method or .end method, the const
          // is in a different method and doesn't apply
          if (/^\s*\.method\s/.test(l) || /^\s*\.end method/.test(l)) {
            break;
          }

          if (/^\s*const(?:\/16|\/high16)?\s+v\d+,\s*0x2000\s*$/.test(l)) {
            foundConst = true;
            break;
          }
        }

        if (foundConst) {
          findings.push({
            flag: 'FLAG_SECURE',
            method: methodName,
            file: path.relative(outputDir, filePath),
            absFile: filePath,
            line: callLineNum,
            severity: 'HIGH',
            constant: '0x2000',
            context: lines
              .slice(
                Math.max(0, callLineIdx - 5),
                Math.min(lines.length, callLineIdx + 3),
              )
              .join('\n'),
            patchable: true,
          });
        }
      }
    }
  } catch (e) {
    /* grep returned nothing */
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
  } catch (e) {
    /* */
  }

  return info;
}

/* ═══════════════════════════════════════════════════════════════
 *  AUTOFIX — patches high-severity patchable flags in-place
 * ═══════════════════════════════════════════════════════════════ */

/**
 * Run autofix on all high-severity, patchable findings.
 * Modifies smali files in-place inside the decompiled directory.
 * Returns an array of { flag, file, line, original, patched } objects.
 */
function runAutofix(outputDir, findings) {
  const patchable = findings.filter(
    (f) => f.severity === 'HIGH' && f.patchable && f.absFile,
  );

  if (patchable.length === 0) {
    console.log(
      chalk.yellow(
        '\n⚠  No high-severity patchable flags found — nothing to autofix.\n',
      ),
    );
    return [];
  }

  console.log(chalk.bold.cyan('\n🔧 Autofix — Patching high-severity flags\n'));

  const patches = [];
  const patchedFileCache = {}; // filePath -> { lines, dirty }

  for (const finding of patchable) {
    const filePath = finding.absFile;

    // Load file lines (use cache if already loaded)
    if (!patchedFileCache[filePath]) {
      try {
        const content = fs.readFileSync(filePath, 'utf-8');
        patchedFileCache[filePath] = {
          lines: content.split('\n'),
          dirty: false,
        };
      } catch (e) {
        console.log(chalk.red(`  ✘ Could not read: ${finding.file}`));
        continue;
      }
    }

    const fileData = patchedFileCache[filePath];
    const { lines } = fileData;

    if (finding.flag === 'FLAG_SECURE') {
      // finding.line points to the setFlags/addFlags call (1-based)
      const callLineIdx = finding.line - 1; // 0-based
      const searchStart = Math.max(0, callLineIdx - 15);

      let patched = false;
      for (let i = callLineIdx - 1; i >= searchStart; i--) {
        const line = lines[i];

        // Stop at method boundary
        if (/^\s*\.method\s/.test(line) || /^\s*\.end method/.test(line)) {
          break;
        }

        const constMatch = line.match(
          /^(\s*const(?:\/16|\/high16)?\s+v\d+,\s*)0x2000(\s*)$/,
        );
        if (constMatch) {
          const original = lines[i];
          lines[i] = `${constMatch[1]}0x0${constMatch[2]}`;
          fileData.dirty = true;
          patched = true;

          patches.push({
            flag: 'FLAG_SECURE',
            file: finding.file,
            line: i + 1,
            original: original.trim(),
            patched: lines[i].trim(),
          });

          console.log(chalk.green(`  ✔ FLAG_SECURE patched`));
          console.log(chalk.gray(`    ${finding.file}:${i + 1}`));
          console.log(chalk.red(`    - ${original.trim()}`));
          console.log(chalk.green(`    + ${lines[i].trim()}`));
          console.log('');
          break; // only patch the nearest const for this call
        }
      }

      if (!patched) {
        console.log(
          chalk.yellow(
            `  ⚠ FLAG_SECURE at ${finding.file}:${finding.line} — const 0x2000 not found nearby (may already be patched)`,
          ),
        );
        console.log('');
      }
    } else if (finding.flag === 'SurfaceView.setSecure') {
      const callLineIdx = finding.line - 1;
      const searchStart = Math.max(0, callLineIdx - 10);

      let patched = false;
      for (let i = callLineIdx - 1; i >= searchStart; i--) {
        const line = lines[i];

        if (/^\s*\.method\s/.test(line) || /^\s*\.end method/.test(line)) {
          break;
        }

        const constMatch = line.match(
          /^(\s*const(?:\/4|\/16)?\s+v\d+,\s*)0x1(\s*)$/,
        );
        if (constMatch) {
          const original = lines[i];
          lines[i] = `${constMatch[1]}0x0${constMatch[2]}`;
          fileData.dirty = true;
          patched = true;

          patches.push({
            flag: 'SurfaceView.setSecure',
            file: finding.file,
            line: i + 1,
            original: original.trim(),
            patched: lines[i].trim(),
          });

          console.log(chalk.green(`  ✔ SurfaceView.setSecure patched`));
          console.log(chalk.gray(`    ${finding.file}:${i + 1}`));
          console.log(chalk.red(`    - ${original.trim()}`));
          console.log(chalk.green(`    + ${lines[i].trim()}`));
          console.log('');
          break;
        }
      }

      if (!patched) {
        console.log(
          chalk.yellow(
            `  ⚠ SurfaceView.setSecure at ${finding.file}:${finding.line} — const 0x1 not found nearby (may already be patched)`,
          ),
        );
        console.log('');
      }
    }
  }

  // Write all modified files back
  for (const [filePath, fileData] of Object.entries(patchedFileCache)) {
    if (fileData.dirty) {
      fs.writeFileSync(filePath, fileData.lines.join('\n'), 'utf-8');
    }
  }

  // Summary
  if (patches.length > 0) {
    console.log(
      chalk.bold.green(`  ✅ ${patches.length} flag(s) patched successfully.`),
    );
  } else {
    console.log(
      chalk.yellow(
        '  ⚠  No patchable constants found — flags may already be patched.',
      ),
    );
  }

  return patches;
}

/**
 * Display scan results in a formatted table.
 */
function displayResults(findings, manifestInfo, options) {
  // JSON output
  if (options.json) {
    const output = { manifest: manifestInfo, findings };
    if (!options.autofix) {
      console.log(JSON.stringify(output, null, 2));
    }
    return;
  }

  // App info
  console.log(chalk.bold('\n📱 App Info\n'));
  console.log(`  Package:    ${chalk.white(manifestInfo.packageName)}`);
  console.log(`  Min SDK:    ${manifestInfo.minSdk}`);
  console.log(`  Target SDK: ${manifestInfo.targetSdk}`);
  console.log(
    `  Debuggable: ${manifestInfo.debuggable ? chalk.green('Yes') : chalk.gray('No')}`,
  );
  console.log(
    `  Network Security Config: ${manifestInfo.networkSecurityConfig ? chalk.yellow('Yes') : chalk.gray('No')}`,
  );

  // Findings
  if (findings.length === 0) {
    console.log(
      chalk.green(
        '\n✅ No security flags detected! The app should work fine with screen capture / App Live.\n',
      ),
    );
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
    const severityColor =
      f.severity === 'HIGH'
        ? chalk.red
        : f.severity === 'MEDIUM'
          ? chalk.yellow
          : chalk.gray;
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
  const patchableCount = findings.filter((f) => f.patchable).length;
  if (patchableCount > 0 && !options.autofix) {
    console.log(
      chalk.cyan(
        `\n💡 ${patchableCount} flag(s) can be auto-patched. Run with --autofix:`,
      ),
    );
    console.log(
      chalk.white(
        `   npx app-flag-inspector inspect <your-app.apk> --autofix\n`,
      ),
    );
    console.log(chalk.gray('   Or use recompile for a full patch + rebuild:'));
    console.log(
      chalk.white(`   npx app-flag-inspector recompile <your-app.apk>\n`),
    );
    console.log(
      chalk.gray(
        '   ⚠  Recompile requires Android SDK (zipalign, apksigner) installed via Android Studio.\n',
      ),
    );
  }

  // Detail for FLAG_SECURE findings
  const secureFindings = findings.filter((f) => f.flag === 'FLAG_SECURE');
  if (secureFindings.length > 0) {
    console.log(chalk.bold('📍 FLAG_SECURE Locations:\n'));
    for (const f of secureFindings) {
      console.log(chalk.yellow(`  → ${f.file}:${f.line}`));
      console.log(
        chalk.gray(`    Method: ${f.method} | Constant: ${f.constant}`),
      );
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
  console.log(
    chalk.gray(
      `  Size: ${(fs.statSync(ipaPath).size / (1024 * 1024)).toFixed(2)} MB\n`,
    ),
  );

  const outputDir =
    options.output ||
    path.join(
      path.dirname(ipaPath),
      `decompiled_${path.basename(ipaPath, '.ipa')}`,
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
    console.log(
      chalk.green('\n✅ No obvious security flags detected in IPA.\n'),
    );
  } else {
    console.log(
      chalk.bold(`\n🚩 Security Patterns Detected: ${findings.length}\n`),
    );
    for (const f of findings) {
      const severityColor =
        f.severity === 'HIGH'
          ? chalk.red
          : f.severity === 'MEDIUM'
            ? chalk.yellow
            : chalk.gray;
      console.log(
        `  ${severityColor('●')} ${chalk.bold(f.flag)} — ${f.description}`,
      );
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
    const grepResult = execSync(
      `grep -rl "isSecureTextEntry\\|makeSecure\\|UITextField" "${outputDir}" 2>/dev/null || true`,
      { encoding: 'utf-8', maxBuffer: 50 * 1024 * 1024 },
    );
    if (grepResult.trim()) {
      findings.push({
        flag: 'Screenshot Prevention',
        severity: 'HIGH',
        description:
          'App may use secure text field overlay to prevent screenshots.',
      });
    }
  } catch (e) {
    /* */
  }

  try {
    const jbResult = execSync(
      `grep -rl "cydia://\\|/Applications/Cydia.app\\|isJailbroken" "${outputDir}" 2>/dev/null || true`,
      { encoding: 'utf-8', maxBuffer: 50 * 1024 * 1024 },
    );
    if (jbResult.trim()) {
      findings.push({
        flag: 'Jailbreak Detection',
        severity: 'MEDIUM',
        description: 'App checks for jailbroken devices.',
      });
    }
  } catch (e) {
    /* */
  }

  return findings;
}

module.exports = { inspect };
