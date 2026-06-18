const { execSync } = require('child_process');
const chalk = require('chalk');

const DEPS = [
  {
    name: 'apktool',
    check: 'apktool --version',
    install: 'brew install apktool',
    required: true,
    description: 'APK decompilation & recompilation',
  },
  {
    name: 'zipalign',
    check: 'zipalign --help 2>&1',
    install: 'Included with Android SDK Build Tools (install via Android Studio)',
    required: false, // only for recompile
    description: 'APK alignment (needed for recompile)',
  },
  {
    name: 'apksigner',
    check: 'apksigner --version',
    install: 'Included with Android SDK Build Tools (install via Android Studio)',
    required: false, // only for recompile
    description: 'APK signing (needed for recompile)',
  },
  {
    name: 'keytool',
    check: 'keytool -help 2>&1',
    install: 'Included with Java JDK',
    required: false,
    description: 'Keystore generation (needed for recompile)',
  },
];

function isInstalled(cmd) {
  try {
    execSync(cmd, { stdio: 'pipe' });
    return true;
  } catch (e) {
    // Some tools return non-zero on --help but still exist
    if (e.stdout || e.stderr) return true;
    return false;
  }
}

async function checkDeps(verbose = false) {
  const results = {};

  if (verbose) {
    console.log(chalk.bold('\n🔍 Checking dependencies...\n'));
  }

  for (const dep of DEPS) {
    const installed = isInstalled(dep.check);
    results[dep.name] = installed;

    if (verbose) {
      const status = installed
        ? chalk.green('✔ installed')
        : chalk.red('✘ not found');
      const reqLabel = dep.required
        ? chalk.yellow(' (required)')
        : chalk.gray(' (optional — for recompile)');
      console.log(`  ${status}  ${chalk.bold(dep.name)}${reqLabel}`);
      if (!installed) {
        console.log(chalk.gray(`           Install: ${dep.install}`));
      }
    }
  }

  if (verbose) console.log('');
  return results;
}

async function ensureApktool() {
  if (isInstalled('apktool --version')) return true;

  console.log(chalk.yellow('\n⚠  apktool is not installed.'));

  // Try auto-install via brew
  if (isInstalled('brew --version')) {
    console.log(chalk.cyan('📦 Installing apktool via Homebrew...\n'));
    try {
      execSync('brew install apktool', { stdio: 'inherit' });
      console.log(chalk.green('\n✔ apktool installed successfully!\n'));
      return true;
    } catch (e) {
      console.error(chalk.red('✘ Failed to install apktool via brew.'));
      console.log(chalk.gray('  Install manually: https://apktool.org/docs/install\n'));
      return false;
    }
  } else {
    console.log(chalk.gray('  Homebrew not found. Install apktool manually:'));
    console.log(chalk.gray('  → https://apktool.org/docs/install\n'));
    return false;
  }
}

module.exports = { checkDeps, ensureApktool, isInstalled };
