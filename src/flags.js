/**
 * Security flag definitions and detection patterns for Android APK smali code.
 *
 * Each flag has:
 *  - name: human-readable name
 *  - constant: the hex constant used in smali
 *  - patterns: regex patterns to search in smali files
 *  - severity: how impactful this flag is for testing/debugging
 *  - description: what the flag does
 *  - patchable: whether this tool can auto-patch it
 */

const ANDROID_FLAGS = [
  {
    name: 'FLAG_SECURE',
    constant: '0x2000',
    decimalValue: 8192,
    patterns: [
      // setFlags with 0x2000
      {
        regex:
          /const(?:\/16|\/high16)?\s+v(\d+),\s*0x2000[\s\S]{0,200}?Window;->setFlags\(II\)V/gm,
        method: 'setFlags',
        label: 'Window.setFlags(FLAG_SECURE)',
      },
      // addFlags with 0x2000
      {
        regex:
          /const(?:\/16|\/high16)?\s+v(\d+),\s*0x2000[\s\S]{0,200}?Window;->addFlags\(I\)V/gm,
        method: 'addFlags',
        label: 'Window.addFlags(FLAG_SECURE)',
      },
      // decimal variant 8192
      {
        regex:
          /const(?:\/16|\/high16)?\s+v(\d+),\s*0x2000[\s\S]{0,200}?Window;->(?:set|add)Flags/gm,
        method: 'setFlags/addFlags',
        label: 'FLAG_SECURE (generic)',
      },
    ],
    severity: 'high',
    description:
      'Prevents screenshots and screen recording. Causes black screen on App Live / screen mirroring.',
    patchable: true,
  },
  {
    name: 'FLAG_KEEP_SCREEN_ON',
    constant: '0x80',
    decimalValue: 128,
    patterns: [
      {
        regex:
          /const(?:\/16|\/high16)?\s+v(\d+),\s*0x80[\s\S]{0,200}?Window;->(?:set|add)Flags/gm,
        method: 'setFlags/addFlags',
        label: 'Window.setFlags(FLAG_KEEP_SCREEN_ON)',
      },
    ],
    severity: 'low',
    description: 'Keeps the screen on while the window is visible.',
    patchable: false,
  },
  {
    name: 'FLAG_FULLSCREEN',
    constant: '0x400',
    decimalValue: 1024,
    patterns: [
      {
        regex:
          /const(?:\/16|\/high16)?\s+v(\d+),\s*0x400[\s\S]{0,200}?Window;->(?:set|add)Flags/gm,
        method: 'setFlags/addFlags',
        label: 'Window.setFlags(FLAG_FULLSCREEN)',
      },
    ],
    severity: 'info',
    description: 'Hides the status bar (deprecated in API 30+).',
    patchable: false,
  },
  {
    name: 'FLAG_TRANSLUCENT_STATUS',
    constant: '0x4000000',
    decimalValue: 67108864,
    patterns: [
      {
        regex:
          /const(?:\/high16)?\s+v(\d+),\s*0x4000000[\s\S]{0,200}?Window;->(?:set|add)Flags/gm,
        method: 'setFlags/addFlags',
        label: 'Window.setFlags(FLAG_TRANSLUCENT_STATUS)',
      },
    ],
    severity: 'info',
    description: 'Makes the status bar translucent.',
    patchable: false,
  },
  {
    name: 'FLAG_TRANSLUCENT_NAVIGATION',
    constant: '0x8000000',
    decimalValue: 134217728,
    patterns: [
      {
        regex:
          /const(?:\/high16)?\s+v(\d+),\s*0x8000000[\s\S]{0,200}?Window;->(?:set|add)Flags/gm,
        method: 'setFlags/addFlags',
        label: 'Window.setFlags(FLAG_TRANSLUCENT_NAVIGATION)',
      },
    ],
    severity: 'info',
    description: 'Makes the navigation bar translucent.',
    patchable: false,
  },
];

// Simple grep-based patterns (faster, used for initial scan)
const GREP_PATTERNS = {
  FLAG_SECURE_SET: {
    pattern: 'Window;->setFlags',
    constant: '0x2000',
    name: 'FLAG_SECURE (setFlags)',
  },
  FLAG_SECURE_ADD: {
    pattern: 'Window;->addFlags',
    constant: '0x2000',
    name: 'FLAG_SECURE (addFlags)',
  },
  SCREENSHOT_CALLBACK: {
    pattern: 'registerScreenCaptureCallback',
    constant: null,
    name: 'Screenshot Capture Callback (API 34+)',
  },
  SURFACE_VIEW_SECURE: {
    pattern: 'SurfaceView;->setSecure',
    constant: null,
    name: 'SurfaceView.setSecure()',
  },
};

// iOS patterns (for IPA inspection — plist / binary checks)
const IOS_PATTERNS = {
  SCREENSHOT_PREVENTION: {
    patterns: ['UITextField', 'isSecureTextEntry', 'makeSecure'],
    name: 'Screenshot Prevention (secure text field overlay)',
    severity: 'high',
  },
  JAILBREAK_DETECTION: {
    patterns: [
      'cydia://',
      '/Applications/Cydia.app',
      'isJailbroken',
      'canOpenURL',
    ],
    name: 'Jailbreak Detection',
    severity: 'medium',
  },
};

module.exports = { ANDROID_FLAGS, GREP_PATTERNS, IOS_PATTERNS };
