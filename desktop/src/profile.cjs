const path = require('node:path');
function profilePath(env) {
  if (env.APK_DESKTOP_USER_DATA) return path.resolve(env.APK_DESKTOP_USER_DATA);
  if (env.PORTABLE_EXECUTABLE_DIR) return path.join(env.PORTABLE_EXECUTABLE_DIR, 'APK Fraud Analyzer Data');
  return null;
}
module.exports = { profilePath };
