// Reproducible documentation captures with an isolated profile and harmless APK.
const { _electron: electron, expect } = require('@playwright/test');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { pythonPath } = require('../src/backend.cjs');
const root = path.resolve(__dirname, '..');
const output = path.join(root, '../docs/images');
(async () => {
  const scratch = path.join(root, 'build/screenshot-profiles');
  fs.mkdirSync(scratch, { recursive: true });
  const data = fs.mkdtempSync(path.join(scratch, 'capture-'));
  const sample = path.join(data, 'harmless-demo.apk');
  execFileSync(pythonPath(root), [path.join(root, '../tools/make_test_apk.py'), sample]);
  const env = { ...process.env, APK_DESKTOP_USER_DATA: path.join(data, 'profile'),
    EXTERNAL_API_ENABLED: 'false', AGENT_ENABLED: 'false', AGENT_WORKFLOW_ENABLED: 'false' };
  delete env.ELECTRON_RUN_AS_NODE;
  const desktop = await electron.launch({ args: [root], env });
  try {
    const page = await desktop.firstWindow();
    await page.waitForURL('http://127.0.0.1:*/', { timeout: 120000 });
    await page.setViewportSize({ width: 1440, height: 960 });
    await page.evaluate(() => document.fonts.ready);
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
    await expect(page.locator('#gemini-badge')).not.toBeEmpty();
    // Hide changing machine/provider diagnostics from public documentation.
    await page.addStyleTag({ content: '#gemini-badge { visibility:hidden } html { scroll-behavior:auto!important } * { transition:none!important;animation:none!important }' });
    const shot = async name => page.screenshot({ path: path.join(output, name) });
    await shot('redesign-studio.png');
    await page.locator('#file-input').setInputFiles(sample);
    await page.locator('#analyze-btn').click();
    await expect(page.locator('#results')).toBeVisible({ timeout: 120000 });
    await page.evaluate(() => {
      const chart = Chart.getChart(document.getElementById('gauge'));
      chart.stop(); chart.options.animation = false; chart.update('none');
    });
    for (const [id, file] of [['overview', 'redesign-analysis.png'], ['static-evidence', 'redesign-static-evidence.png'], ['threat-intel', 'redesign-threat-mapping.png']]) {
      await page.locator(`#${id}`).evaluate(el => el.scrollIntoView({ block: 'start', behavior: 'instant' }));
      await shot(file);
    }
    await page.locator('#theme-toggle').click();
    await page.evaluate(() => { const chart = Chart.getChart(document.getElementById('gauge')); chart.stop(); chart.options.animation = false; chart.update('none'); });
    await page.locator('#overview').evaluate(el => el.scrollIntoView({ block: 'start', behavior: 'instant' }));
    await shot('redesign-dark-analysis.png');
    await page.locator('#settings-open').click();
    await expect(page.locator('#settings-status')).toContainText('Settings are stored locally', { timeout: 30000 });
    await shot('redesign-settings.png');
    console.log('Captured redesigned studio, analysis, evidence, mapping, dark mode, and settings.');
  } finally { await desktop.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
