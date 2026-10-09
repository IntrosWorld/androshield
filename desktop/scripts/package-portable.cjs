const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
// NSIS needs substantial temporary space to assemble the embedded runtime.
// Use the workspace drive instead of filling the Windows system drive.
const temp = path.join(root, 'build/packaging-temp');
fs.mkdirSync(temp, { recursive: true });
execFileSync(process.execPath, [require.resolve('electron-builder/cli.js'), '--win', 'portable', ...process.argv.slice(2)], {
  cwd: root, stdio: 'inherit', env: { ...process.env, TEMP: temp, TMP: temp },
});
