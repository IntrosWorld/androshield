const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { profilePath } = require('../src/profile.cjs');
test('portable data follows the launcher, not its extraction folder', () => {
  const location = path.resolve('portable folder');
  assert.equal(profilePath({ PORTABLE_EXECUTABLE_DIR: location }), path.join(location, 'APK Fraud Analyzer Data'));
  assert.equal(profilePath({}), null);
  assert.equal(profilePath({ PORTABLE_EXECUTABLE_DIR: location, APK_DESKTOP_USER_DATA: 'test-profile' }), path.resolve('test-profile'));
});
