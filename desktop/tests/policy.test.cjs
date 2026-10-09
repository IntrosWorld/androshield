const test = require('node:test');
const assert = require('node:assert/strict');
const { isLocal, isExport, externalURL } = require('../src/policy.cjs');
const origin = 'http://127.0.0.1:32123';
test('only the owned backend origin receives credentials', () => {
  assert.ok(isLocal(`${origin}/api/health`, origin));
  for (const url of ['http://127.0.0.1:32124', 'http://127.0.0.1.attacker.test:32123', 'https://example.com', 'file:///etc/passwd']) {
    assert.equal(isLocal(url, origin), false);
  }
});
test('only known report endpoints become native downloads', () => {
  assert.ok(isExport(`${origin}/api/samples/abc-123/report.pdf`, origin));
  assert.ok(isExport(`${origin}/api/samples/abc-123/iocs.json`, origin));
  assert.equal(isExport(`${origin}/api/settings`, origin), false);
  assert.equal(isExport('https://example.com/api/samples/abc/report.pdf', origin), false);
});
test('external handlers reject shell protocols and credentials', () => {
  assert.ok(externalURL('https://example.com/help'));
  for (const url of ['file:///C:/Windows/system32/cmd.exe', 'javascript:alert(1)', 'ms-settings:', 'https://name:secret@example.com', 'invalid']) {
    assert.equal(externalURL(url), false);
  }
});
