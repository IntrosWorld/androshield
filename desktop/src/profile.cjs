const path = require('node:path');
const fs = require('node:fs');
function profilePath(env, appData) {
  if (env.APK_DESKTOP_USER_DATA) return path.resolve(env.APK_DESKTOP_USER_DATA);
  if (env.PORTABLE_EXECUTABLE_DIR) return path.join(env.PORTABLE_EXECUTABLE_DIR, 'AndroShield Data');
  return appData ? path.join(appData, 'AndroShield') : null;
}
function migrateLegacyProfile(target, env, appData) {
  // Explicit profiles belong to the caller; never move those.
  if (!target || env.APK_DESKTOP_USER_DATA) return;
  const parent = path.resolve(env.PORTABLE_EXECUTABLE_DIR || appData);
  const legacy = path.join(parent, env.PORTABLE_EXECUTABLE_DIR ? 'APK Fraud Analyzer Data' : 'APK Fraud Analyzer');
  const resolvedTarget = path.resolve(target);
  // Migration is a same-parent rename of only the known product profile.
  if (path.dirname(resolvedTarget) !== parent || path.dirname(legacy) !== parent) throw new Error('Invalid profile migration path');
  if (!fs.existsSync(resolvedTarget) && fs.existsSync(legacy)) fs.renameSync(legacy, resolvedTarget);
}
module.exports = { profilePath, migrateLegacyProfile };
