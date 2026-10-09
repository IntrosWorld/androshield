const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { startBackend } = require('../src/backend.cjs');
test('private backend rejects browsers, persists settings, and shuts down', { timeout: 120000 }, async () => {
  const data = fs.mkdtempSync(path.join(os.tmpdir(), 'apk-desktop-test-'));
  const root = path.resolve(__dirname, '..');
  const launch = () => startBackend({ root, data, packaged: false });
  let backend = launch();
  try {
    let connection = await backend.ready;
    assert.equal((await fetch(`${connection.origin}/api/settings`)).status, 403);
    assert.equal((await fetch(`${connection.origin}/api/settings`, { headers: { 'X-Desktop-Token': 'wrong' } })).status, 403);
    const headers = { 'X-Desktop-Token': connection.token, 'Content-Type': 'application/json' };
    const response = await fetch(`${connection.origin}/api/settings`, { method: 'PUT', headers, body: JSON.stringify({ external_api_enabled: false }) });
    assert.equal(response.status, 200);
    await backend.stop();
    await assert.rejects(fetch(`${connection.origin}/api/settings`));
    backend = launch();
    connection = await backend.ready;
    const settings = await fetch(`${connection.origin}/api/settings`, { headers: { 'X-Desktop-Token': connection.token } }).then(r => r.json());
    assert.equal(settings.external_api_enabled, false);
    assert.ok(fs.existsSync(path.join(data, 'analyzer.db')));
  } finally {
    await backend.stop();
    fs.rmSync(data, { recursive: true, force: true });
  }
});
