const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { profilePath, migrateLegacyProfile } = require('../src/profile.cjs');
const fs = require('node:fs');
const os = require('node:os');
test('portable data follows the launcher, not its extraction folder', () => {
  const location = path.resolve('portable folder');
  assert.equal(profilePath({ PORTABLE_EXECUTABLE_DIR: location }), path.join(location, 'AndroShield Data'));
  assert.equal(profilePath({}), null);
  assert.equal(profilePath({ PORTABLE_EXECUTABLE_DIR: location, APK_DESKTOP_USER_DATA: 'test-profile' }), path.resolve('test-profile'));
});
test('rename retains existing portable history and never overwrites a new profile', () => {
  const location = fs.mkdtempSync(path.join(os.tmpdir(), 'androshield-migration-'));
  const legacy = path.join(location, 'APK Fraud Analyzer Data');
  const destination = path.join(location, 'AndroShield Data');
  fs.mkdirSync(legacy);
  fs.writeFileSync(path.join(legacy, 'analyzer.db'), 'existing history');
  migrateLegacyProfile(destination, { PORTABLE_EXECUTABLE_DIR: location });
  assert.equal(fs.readFileSync(path.join(destination, 'analyzer.db'), 'utf8'), 'existing history');
  assert.equal(fs.existsSync(legacy), false);
  fs.mkdirSync(legacy);
  fs.writeFileSync(path.join(legacy, 'analyzer.db'), 'second history');
  migrateLegacyProfile(destination, { PORTABLE_EXECUTABLE_DIR: location });
  assert.equal(fs.readFileSync(path.join(destination, 'analyzer.db'), 'utf8'), 'existing history');
  assert.equal(fs.readFileSync(path.join(legacy, 'analyzer.db'), 'utf8'), 'second history');
  assert.equal(profilePath({}, location), path.join(location, 'AndroShield'));
  assert.throws(() => migrateLegacyProfile(path.join(location, 'elsewhere', 'profile'), { PORTABLE_EXECUTABLE_DIR: location }));
});
