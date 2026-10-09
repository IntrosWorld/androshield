const fs = require('node:fs');
const path = require('node:path');
const { version } = require('../package.json');
const destination = path.resolve(__dirname, '../dist');
fs.mkdirSync(destination, { recursive: true });
fs.writeFileSync(path.join(destination, 'Run Portable.cmd'), [
  '@echo off',
  'setlocal',
  'set "TEMP=%~dp0APK Fraud Analyzer Data\\runtime"',
  'set "TMP=%TEMP%"',
  'if not exist "%TEMP%" mkdir "%TEMP%"',
  'if not exist "%TEMP%" exit /b 1',
  `start "" "%~dp0APK-Fraud-Analyzer-Portable-${version}.exe"`,
  'endlocal',
  '',
].join('\r\n'));
