// Test the real NSIS launcher over Chromium's loopback debug port, without
// depending on the launcher forwarding Electron's inspector pipes.
const { chromium, expect } = require('@playwright/test');
const { spawn, execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const assert = require('node:assert/strict');
const { pythonPath } = require('../src/backend.cjs');
const root = path.resolve(__dirname, '..');

async function freePort() {
  const server = net.createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

async function launch(executablePath) {
  const port = await freePort();
  const env = { ...process.env, EXTERNAL_API_ENABLED: 'false', TEMP: path.dirname(executablePath), TMP: path.dirname(executablePath) };
  for (const key of ['ELECTRON_RUN_AS_NODE', 'APK_DESKTOP_USER_DATA', 'PORTABLE_EXECUTABLE_DIR']) delete env[key];
  const child = spawn(executablePath, [`--remote-debugging-port=${port}`], { env, stdio: 'ignore' });
  const exited = new Promise(resolve => child.once('exit', resolve));
  let failure;
  child.once('error', error => { failure = error; });
  let browser;
  try {
    console.log('Waiting for portable runtime extraction…');
    await expect.poll(async () => {
      if (failure) throw failure;
      try { return (await fetch(`http://127.0.0.1:${port}/json/version`, { signal: AbortSignal.timeout(1000) })).ok; }
      catch { return false; }
    }, { timeout: 240000, intervals: [500, 1000] }).toBeTruthy();
    browser = await chromium.connectOverCDP(`http://127.0.0.1:${port}`);
    const context = browser.contexts()[0];
    const page = context.pages()[0] || await context.waitForEvent('page');
    await page.waitForURL('http://127.0.0.1:*/', { timeout: 120000 });
    console.log('Portable window loaded.');
    return { page, async close() {
      await page.close();
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('Portable launcher did not exit')), 30000);
        exited.then(() => { clearTimeout(timer); resolve(); });
      });
      await browser.close();
    } };
  } catch (error) {
    if (child.pid && child.exitCode === null) execFileSync('taskkill', ['/pid', String(child.pid), '/t', '/f']);
    await browser?.close();
    throw error;
  }
}

(async () => {
  const testRoot = path.join(root, 'build/portable-tests');
  fs.mkdirSync(testRoot, { recursive: true });
  const data = fs.mkdtempSync(path.join(testRoot, 'run-'));
  const executable = path.join(data, 'Portable Analyzer.exe');
  fs.copyFileSync(process.env.APK_DESKTOP_EXECUTABLE || path.join(root, 'dist/APK-Fraud-Analyzer-Portable-0.1.0.exe'), executable);
  const sample = path.join(data, 'harmless.apk');
  execFileSync(pythonPath(root), [path.join(root, '../tools/make_test_apk.py'), sample]);
  let desktop = await launch(executable);
  try {
    const { page } = desktop;
    const health = await page.evaluate(() => fetch('/api/health', { signal: AbortSignal.timeout(30000) }).then(r => r.json()));
    assert.equal(health.analyzer_ready, true);
    await page.locator('#file-input').setInputFiles(sample);
    await page.locator('#analyze-btn').click();
    await page.waitForFunction(() => !document.getElementById('results').classList.contains('hidden'), null, { timeout: 120000 });
    const history = await page.evaluate(() => fetch('/api/samples').then(r => r.json()));
    const id = history.samples[0].id;
    assert.ok(history.samples[0].risk_score > 70);
    for (const format of ['report.pdf', 'iocs.json', 'iocs.csv']) {
      assert.equal(await page.evaluate(url => fetch(url).then(r => r.status), `/api/samples/${id}/${format}`), 200);
    }
    await page.locator('#theme-toggle').click();
    const profile = path.join(data, 'APK Fraud Analyzer Data');
    await expect.poll(() => fs.existsSync(path.join(profile, 'theme.json')) && JSON.parse(fs.readFileSync(path.join(profile, 'theme.json'), 'utf8'))).toBe('light');
    assert.ok(fs.existsSync(path.join(profile, 'analyzer.db')));
    console.log('Portable analysis, exports, and adjacent data folder passed.');
    await desktop.close();
    desktop = null;
    desktop = await launch(executable);
    assert.equal(await desktop.page.evaluate(() => document.documentElement.dataset.theme), 'light');
    const saved = await desktop.page.evaluate(() => fetch('/api/samples').then(r => r.json()));
    assert.ok(saved.samples.some(sample => sample.id === id));
    console.log('Portable relaunch passed: history and theme retained.');
  } finally { if (desktop) await desktop.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });

