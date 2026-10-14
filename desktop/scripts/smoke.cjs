const { _electron: electron, expect } = require('@playwright/test');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { pythonPath } = require('../src/backend.cjs');
const root = path.resolve(__dirname, '..');
(async () => {
  const data = fs.mkdtempSync(path.join(os.tmpdir(), 'apk-desktop-smoke-'));
  const sample = path.join(data, 'harmless.apk');
  execFileSync(pythonPath(root), [path.join(root, '../tools/make_test_apk.py'), sample]);
  const env = { ...process.env, APK_DESKTOP_USER_DATA: path.join(data, 'profile'), EXTERNAL_API_ENABLED: 'false' };
  delete env.ELECTRON_RUN_AS_NODE;
  const desktop = await electron.launch(process.env.APK_DESKTOP_EXECUTABLE
    ? { executablePath: process.env.APK_DESKTOP_EXECUTABLE, env }
    : { args: [root], env });
  try {
    const page = await desktop.firstWindow();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.waitForURL('http://127.0.0.1:*/', { timeout: 120000 });
    console.log('Desktop window loaded.');
    await page.waitForSelector('#file-input', { state: 'attached' });
    assert.equal(await page.evaluate(() => typeof window.require), 'undefined');
    assert.equal(await page.evaluate(() => typeof Chart), 'function');
    const health = await page.evaluate(() => fetch('/api/health', { signal: AbortSignal.timeout(30000) }).then(r => r.json()));
    assert.equal(health.analyzer_ready, true);
    console.log('Analyzer ready.');
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
    await expect(page.locator('#analysis-empty')).toBeVisible();
    await page.screenshot({ path: path.join(root, 'build/redesign-studio.png') });
    await page.locator('[data-workspace-nav="history"]').click();
    await expect(page.locator('#history-empty')).toBeVisible();
    await expect(page.locator('#upload-card')).not.toBeVisible();
    await page.locator('[data-workspace-nav="folders"]').click();
    await expect(page.locator('#folder-empty')).toBeVisible();
    await page.locator('#settings-open').click();
    await expect(page.locator('#settings-dialog')).toBeVisible();
    await page.locator('#settings-close').click();
    await page.locator('[data-workspace-nav="analysis"]').click();
    await page.locator('#file-input').setInputFiles(sample);
    await page.locator('#analyze-btn').click();
    await page.waitForFunction(() => !document.getElementById('results').classList.contains('hidden'), null, { timeout: 120000 });
    const { samples } = await page.evaluate(() => fetch('/api/samples').then(r => r.json()));
    assert.ok(samples.length > 0);
    assert.ok(samples[0].risk_score > 70, 'harmless fraud fixture should have critical static findings');
    const id = samples[0].id;
    const saved = await page.evaluate(url => fetch(url).then(r => r.json()), `/api/samples/${id}`);
    assert.ok(saved.analysis.yara.matches.length > 0, 'bundled YARA rules must load');
    assert.equal(saved.analysis.apkid.error, undefined, 'APKiD rules must load');
    for (const endpoint of ['report.pdf', 'iocs.csv', 'iocs.json']) {
      const status = await page.evaluate(url => fetch(url).then(r => r.status), `/api/samples/${id}/${endpoint}`);
      assert.equal(status, 200);
    }
    const pdf = path.join(data, 'report.pdf');
    await desktop.evaluate(({ session }, destination) => {
      session.fromPartition('persist:analyzer').once('will-download', (_event, item) => item.setSavePath(destination));
    }, pdf);
    await page.locator('#pdf-btn').click();
    await expect.poll(() => fs.existsSync(pdf) && fs.statSync(pdf).size > 0, { timeout: 15000 }).toBeTruthy();
    assert.equal(fs.readFileSync(pdf).subarray(0, 4).toString(), '%PDF');
    await page.locator('[data-workspace-nav="history"]').click();
    await expect(page.locator('#history-list [data-id]').first()).toBeVisible();
    await page.locator('#history-list [data-id]').first().click();
    await expect(page.locator('body')).toHaveAttribute('data-workspace-view', 'analysis');
    await expect(page.locator('#results')).toBeVisible();
    const folder = path.join(data, 'harmless-folder');
    fs.mkdirSync(folder);
    fs.copyFileSync(sample, path.join(folder, 'sample.apk'));
    await page.locator('#folder-input').setInputFiles(folder);
    await page.locator('#analyze-btn').click();
    await expect(page.locator('#batch-summary')).toContainText('1 completed - 0 active', { timeout: 120000 });
    await page.locator('[data-workspace-nav="folders"]').click();
    await expect(page.locator('[data-folder-batch-id]').first()).toBeVisible();
    await page.locator('[data-folder-batch-id]').first().click();
    await expect(page.locator('body')).toHaveAttribute('data-workspace-view', 'analysis');
    await expect(page.locator('#batch-card')).toBeVisible();
    await page.locator('[data-batch-open]').first().click();
    await expect(page.locator('#results')).toBeVisible();
    assert.deepEqual(errors, []);
    fs.mkdirSync(path.join(root, 'build'), { recursive: true });
    await page.screenshot({ path: path.join(root, 'build/desktop-smoke.png') });
    await page.locator('#theme-toggle').click();
    const themeFile = path.join(data, 'profile/theme.json');
    await expect.poll(() => fs.existsSync(themeFile) && JSON.parse(fs.readFileSync(themeFile, 'utf8'))).toBe('dark');
    await page.setViewportSize({ width: 1000, height: 760 });
    await page.evaluate(() => window.scrollTo(0, 0));
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, 'minimum desktop width must not overflow');
    await expect(page.locator('#workspace-add')).toHaveCSS('background-color', 'rgb(28, 43, 34)');
    await page.screenshot({ path: path.join(root, 'build/redesign-dark-compact.png') });
    await page.locator('#settings-open').click();
    await expect(page.locator('#settings-dialog')).toBeVisible();
    await page.screenshot({ path: path.join(root, 'build/redesign-settings.png') });
    console.log('Desktop smoke passed: isolated renderer, engine health, harmless APK analysis, PDF/IOC exports, native PDF download, saved theme.');
  } finally {
    await desktop.close();
    // Electron closes asynchronously while the backend drains; test data stays in temp.
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
