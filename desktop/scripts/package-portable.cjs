const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const { getMakeNsisPath } = require('app-builder-lib/out/toolsets/windows');
const root = path.resolve(__dirname, '..');
// NSIS needs substantial temporary space to assemble the embedded runtime.
// Use the workspace drive instead of filling the Windows system drive.
const temp = path.join(root, 'build/packaging-temp');
fs.mkdirSync(temp, { recursive: true });
execFileSync(process.execPath, [require.resolve('electron-builder/cli.js'), '--win', '--dir'], {
  cwd: root, stdio: 'inherit', env: { ...process.env, TEMP: temp, TMP: temp },
});

(async () => {
  const appDir = path.join(root, 'dist/win-unpacked');
  const hash = createHash('sha256');
  async function hashTree(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const file = path.join(dir, entry.name);
      if (entry.isDirectory()) await hashTree(file);
      else {
        hash.update(path.relative(appDir, file));
        for await (const chunk of fs.createReadStream(file)) hash.update(chunk);
      }
    }
  }
  await hashTree(appDir);
  const compiler = await getMakeNsisPath();
  const output = path.join(root, `dist/AndroShield-Portable-${require('../package.json').version}.exe`);
  execFileSync(compiler.path, ['/V2', `/DAPP_DIR=${appDir}`, `/DOUTPUT=${output}`, `/DBUILD_ID=${hash.digest('hex').slice(0, 24)}`, path.join(__dirname, 'portable.nsi')], {
    cwd: root, stdio: 'inherit', env: { ...process.env, ...compiler.env, TEMP: temp, TMP: temp },
  });
  console.log(`Portable app: ${output}`);
})().catch(error => { console.error(error); process.exitCode = 1; });
