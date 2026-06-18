const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const chalk = require('chalk');
const ora = require('ora');
const { ensureApktool, isInstalled } = require('./deps');

/**
 * Recompile command — decompiles APK, patches FLAG_SECURE, recompiles, signs.
 *
 * Requires:
 *  - apktool (auto-installed via brew)
 *  - zipalign (from Android SDK Build Tools — requires Android Studio)
 *  - apksigner (from Android SDK Build Tools — requires Android Studio)
 */
async function recompile(filePath, options) {
  const absPath = path.resolve(filePath);

  if (!fs.existsSync(absPath)) {
    console.error(chalk.red(`\n✘ File not found: ${absPath}\n`));
    process.exit(1);
  }

  if (!absPath.endsWith('.apk')) {
    console.error(chalk.red('\n✘ Recompile only supports .apk files.\n'));
    process.exit(1);
  }

  console.log(chalk.bold.cyan('\n🔧 App Flag Inspector — Recompile & Patch\n'));
  console.log(chalk.gray(`  File: ${absPath}`));
  console.log(chalk.gray(`  Size: ${(fs.statSync(absPath).size / (1024 * 1024)).toFixed(2)} MB\n`));

  // 1. Check dependencies
  const hasApktool = await ensureApktool();
  if (!hasApktool) process.exit(1);

  if (!isInstalled('zipalign --help 2>&1')) {
    console.error(chalk.red('\n✘ zipalign not found.'));
    console.log(chalk.gray('  zipalign is part of Android SDK Build Tools.'));
    console.log(chalk.gray('  Install Android Studio → SDK Manager → SDK Build Tools'));
    console.log(chalk.gray('  Then add to PATH: export PATH=$PATH:$ANDROID_HOME/build-tools/<version>\n'));
    process.exit(1);
  }

  const shouldSign = options.sign !== false;
  if (shouldSign && !isInstalled('apksigner --version')) {
    console.error(chalk.red('\n✘ apksigner not found.'));
    console.log(chalk.gray('  apksigner is part of Android SDK Build Tools.'));
    console.log(chalk.gray('  Install Android Studio → SDK Manager → SDK Build Tools'));
    console.log(chalk.gray('  Then add to PATH: export PATH=$PATH:$ANDROID_HOME/build-tools/<version>\n'));
    process.exit(1);
  }

  // 2. Decompile
  const decompileDir = path.join(
    path.dirname(absPath),
    `_patch_${path.basename(absPath, '.apk')}`
  );

  const decompileSpinner = ora('Decompiling APK...').start();
  try {
    if (fs.existsSync(decompileDir)) {
      fs.rmSync(decompileDir, { recursive: true, force: true });
    }
    execSync(`apktool d "${absPath}" -o "${decompileDir}" -f`, {
      stdio: 'pipe',
      timeout: 300000,
    });
    decompileSpinner.succeed('Decompiled');
  } catch (e) {
    decompileSpinner.fail('Decompile failed');
    console.error(chalk.red(`  ${e.message}\n`));
    process.exit(1);
  }

  // 3. Find and patch FLAG_SECURE
  const patchSpinner = ora('Patching FLAG_SECURE...').start();
  const patchCount = patchFlagSecure(decompileDir);

  if (patchCount === 0) {
    patchSpinner.info('No FLAG_SECURE instances found — nothing to patch');
  } else {
    patchSpinner.succeed(`Patched ${patchCount} FLAG_SECURE instance(s)`);
  }

  // 4. Recompile
  const outputApk = options.output || path.join(
    path.dirname(absPath),
    `${path.basename(absPath, '.apk')}-patched.apk`
  );
  const unsignedApk = outputApk.replace('.apk', '-unsigned.apk');

  const buildSpinner = ora('Recompiling APK...').start();
  try {
    execSync(`apktool b "${decompileDir}" -o "${unsignedApk}"`, {
      stdio: 'pipe',
      timeout: 300000,
    });
    buildSpinner.succeed('Recompiled');
  } catch (e) {
    buildSpinner.fail('Recompile failed');
    console.error(chalk.red(`  ${e.message}\n`));
    process.exit(1);
  }

  // 5. Align
  const alignedApk = outputApk.replace('.apk', '-aligned.apk');
  const alignSpinner = ora('Aligning APK...').start();
  try {
    execSync(`zipalign -f 4 "${unsignedApk}" "${alignedApk}"`, { stdio: 'pipe' });
    alignSpinner.succeed('Aligned');
  } catch (e) {
    alignSpinner.fail('Alignment failed');
    console.error(chalk.red(`  ${e.message}\n`));
    process.exit(1);
  }

  // 6. Sign
  if (shouldSign) {
    const signSpinner = ora('Signing APK...').start();
    try {
      let keystorePath = options.keystore;
      const keyAlias = options.alias || 'mykey';

      // Auto-generate keystore if not provided
      if (!keystorePath) {
        keystorePath = path.join(path.dirname(absPath), '_debug-keystore.jks');
        if (!fs.existsSync(keystorePath)) {
          execSync(
            `keytool -genkey -v -keystore "${keystorePath}" ` +
            `-keyalg RSA -keysize 2048 -validity 10000 ` +
            `-alias ${keyAlias} ` +
            `-storepass android -keypass android ` +
            `-dname "CN=Debug, OU=Debug, O=Debug, L=Debug, ST=Debug, C=US"`,
            { stdio: 'pipe' }
          );
        }
      }

      execSync(
        `apksigner sign --ks "${keystorePath}" ` +
        `--ks-pass pass:android --key-pass pass:android ` +
        `--ks-key-alias ${keyAlias} ` +
        `--out "${outputApk}" "${alignedApk}"`,
        { stdio: 'pipe' }
      );
      signSpinner.succeed('Signed');
    } catch (e) {
      signSpinner.fail('Signing failed');
      console.error(chalk.red(`  ${e.message}`));
      console.log(chalk.gray('  The unsigned APK is still available at:'));
      console.log(chalk.gray(`  ${unsignedApk}\n`));
    }
  } else {
    // Just rename aligned to output
    fs.renameSync(alignedApk, outputApk);
    console.log(chalk.yellow('  ⚠ APK is unsigned. You must sign it before installing.'));
  }

  // 7. Cleanup temp files
  try {
    fs.rmSync(decompileDir, { recursive: true, force: true });
    if (fs.existsSync(unsignedApk)) fs.unlinkSync(unsignedApk);
    if (fs.existsSync(alignedApk)) fs.unlinkSync(alignedApk);
  } catch (e) { /* best effort */ }

  // 8. Summary
  if (fs.existsSync(outputApk)) {
    console.log(chalk.green(`\n✅ Patched APK ready: ${outputApk}`));
    console.log(chalk.gray(`   Size: ${(fs.statSync(outputApk).size / (1024 * 1024)).toFixed(2)} MB\n`));
    console.log(chalk.cyan('   Install with:'));
    console.log(chalk.white(`   adb install "${outputApk}"\n`));
  }
}

/**
 * Find all FLAG_SECURE (0x2000) usages in smali and patch them to 0x0.
 * Returns the number of patches applied.
 */
function patchFlagSecure(decompileDir) {
  let patchCount = 0;

  const entries = fs.readdirSync(decompileDir);
  const smaliDirs = entries.filter(e =>
    e.startsWith('smali') && fs.statSync(path.join(decompileDir, e)).isDirectory()
  );

  for (const smaliDir of smaliDirs) {
    const fullDir = path.join(decompileDir, smaliDir);

    // Find files with setFlags or addFlags + 0x2000
    try {
      const grepResult = execSync(
        `grep -rln "0x2000" "${fullDir}" 2>/dev/null || true`,
        { encoding: 'utf-8', maxBuffer: 50 * 1024 * 1024 }
      );
      const files = grepResult.trim().split('\n').filter(Boolean);

      for (const file of files) {
        const content = fs.readFileSync(file, 'utf-8');

        // Check if this file actually uses Window;->setFlags or addFlags
        if (!content.includes('Window;->setFlags') && !content.includes('Window;->addFlags')) {
          continue;
        }

        // Patch: replace const/16 vN, 0x2000 and const/high16 vN, 0x2000 with 0x0
        // Only when near a Window;->setFlags or addFlags call
        const lines = content.split('\n');
        let patched = false;

        for (let i = 0; i < lines.length; i++) {
          // Look for the constant assignment
          const constMatch = lines[i].match(/^(\s*const(?:\/16|\/high16)?\s+v\d+,\s*)0x2000(\s*)$/);
          if (!constMatch) continue;

          // Check if within ~15 lines there's a setFlags or addFlags call
          const lookAhead = lines.slice(i, Math.min(i + 15, lines.length)).join('\n');
          if (lookAhead.includes('Window;->setFlags') || lookAhead.includes('Window;->addFlags')) {
            lines[i] = `${constMatch[1]}0x0${constMatch[2]}`;
            patched = true;
            patchCount++;
            console.log(chalk.gray(`    Patched: ${path.relative(decompileDir, file)}:${i + 1}`));
          }
        }

        if (patched) {
          fs.writeFileSync(file, lines.join('\n'), 'utf-8');
        }
      }
    } catch (e) { /* */ }
  }

  return patchCount;
}

module.exports = { recompile };
