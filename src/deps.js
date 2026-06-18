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
    required: false,
    description: 'APK alignment (needed for recompile)',
  },
  {
    name: 'apksigner',
    check: 'apksigner --version',
    install: 'Included with Android SDK Build Tools (install via Android Studio)',
    required: false,
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

/**
 * Ensure Homebrew is installed. If not, auto-install it.
 * Returns true if brew is available after this call, false otherwise.
 */
function ensureBrew() {
  if (isInstalled('brew --version')) return true;

  console.log(chalk.yellow('\n⚠  Homebrew is not installed.'));
  console.log(chalk.cyan('📦 Installing Homebrew...\n'));

  try {
    execSync(
      '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"',
      { stdio: 'inherit' },
    );
  } catch (e) {
    console.error(chalk.red('\n✘ Failed to install Homebrew automatically.'));
    console.log(chalk.gray('  Install manually: https://brew.sh\n'));
    return false;
  }

  // After install, brew may not be on PATH yet (especially on Apple Silicon / Linux).
  // The Homebrew installer prints eval instructions — try common locations.
  if (!isInstalled('brew --version')) {
    const brewPaths = [
      '/opt/homebrew/bin',           // macOS Apple Silicon
      '/usr/local/bin',              // macOS Intel
      '/home/linuxbrew/.linuxbrew/bin', // Linux
    ];

    for (const p of brewPaths) {
      try {
        const testCmd = `${p}/brew --version`;
        execSync(testCmd, { stdio: 'pipe' });
        // Found it — add to PATH for this process
        process.env.PATH = `${p}:${process.env.PATH}`;
        console.log(chalk.green(`\n✔ Homebrew installed (found at ${p})`));
        console.log(
          chalk.gray(
            `  ℹ  Add this to your shell profile to make it permanent:\n` +
            `     export PATH="${p}:$PATH"\n`,
          ),
        );
        return true;
      } catch (e) {
        // not at this path, try next
      }
    }

    console.error(
      chalk.red(
        '\n✘ Homebrew was installed but could not be found on PATH.',
      ),
    );
    console.log(
      chalk.gray(
        '  Close and reopen your terminal, or run:\n' +
        '  eval "$(/opt/homebrew/bin/brew shellenv)"\n',
      ),
    );
    return false;
  }

  console.log(chalk.green('\n✔ Homebrew installed successfully!\n'));
  return true;
}

/**
 * Ensure apktool is installed.
 * Chain: check apktool → check brew (install if missing) → install apktool via brew.
 * Returns true if apktool is available after this call, false otherwise.
 */
async function ensureApktool() {
  if (isInstalled('apktool --version')) return true;

  console.log(chalk.yellow('\n⚠  apktool is not installed.'));

  // Step 1: Ensure brew is available (auto-install if needed)
  const hasBrew = ensureBrew();
  if (!hasBrew) {
    console.error(
      chalk.red(
        '✘ Cannot install apktool without Homebrew. Install apktool manually:',
      ),
    );
    console.log(chalk.gray('  → https://apktool.org/docs/install\n'));
    return false;
  }

  // Step 2: Install apktool via brew
  console.log(chalk.cyan('📦 Installing apktool via Homebrew...\n'));
  try {
    execSync('brew install apktool', { stdio: 'inherit' });
  } catch (e) {
    console.error(chalk.red('\n✘ Failed to install apktool via brew.'));
    console.log(
      chalk.gray('  Install manually: https://apktool.org/docs/install\n'),
    );
    return false;
  }

  // Verify it actually works now
  if (!isInstalled('apktool --version')) {
    console.error(
      chalk.red(
        '\n✘ apktool was installed but could not be found on PATH.',
      ),
    );
    console.log(
      chalk.gray('  Try closing and reopening your terminal.\n'),
    );
    return false;
  }

  console.log(chalk.green('\n✔ apktool installed successfully!\n'));
  return true;
}

module.exports = { checkDeps, ensureApktool, ensureBrew, isInstalled };