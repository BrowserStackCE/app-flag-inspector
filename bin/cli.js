#!/usr/bin/env node

const { program } = require('commander');
const { inspect } = require('../src/inspect');
const { recompile } = require('../src/recompile');
const pkg = require('../package.json');

program
  .name('app-flag-inspector')
  .description(
    'Decompile and inspect Android APK / iOS IPA security flags (FLAG_SECURE, screenshot blocking, DRM, etc.)',
  )
  .version(pkg.version);

program
  .command('inspect')
  .alias('i')
  .description(
    'Decompile an APK/IPA and detect security flags (default behavior)',
  )
  .argument('<file>', 'Path to .apk or .ipa file')
  .option('-o, --output <dir>', 'Output directory for decompiled files', null)
  .option(
    '--keep',
    'Keep decompiled output after inspection (default: cleaned up)',
    false,
  )
  .option('--json', 'Output results as JSON', false)
  .option(
    '--autofix',
    'Automatically patch and remove high-severity flags (keeps decompiled source for recompile)',
    false,
  )
  .action(async (file, options) => {
    await inspect(file, options);
  });

program
  .command('recompile')
  .alias('r')
  .description(
    'Patch detected flags and recompile into a new APK (requires Android SDK / apksigner)',
  )
  .argument('<file>', 'Path to .apk file')
  .option('-o, --output <file>', 'Output path for patched APK', null)
  .option('--no-sign', 'Skip signing the recompiled APK')
  .option('--keystore <path>', 'Path to keystore for signing')
  .option('--alias <name>', 'Key alias for signing', 'mykey')
  .action(async (file, options) => {
    await recompile(file, options);
  });

program
  .command('check-deps')
  .description(
    'Check if required dependencies (apktool, zipalign, apksigner) are installed',
  )
  .action(async () => {
    const { checkDeps } = require('../src/deps');
    await checkDeps(true);
  });

// Default command — if user just runs `app-flag-inspector myapp.apk`
program
  .argument('[file]', 'Path to .apk or .ipa file (shortcut for inspect)')
  .action(async (file) => {
    if (file && (file.endsWith('.apk') || file.endsWith('.ipa'))) {
      await inspect(file, {});
    } else if (file) {
      console.error(
        `Unsupported file type: ${file}. Provide an .apk or .ipa file.`,
      );
      process.exit(1);
    }
  });

program.parse();
