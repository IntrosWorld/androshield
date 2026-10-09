function isLocal(url, origin) {
  try { return new URL(url).origin === origin; } catch { return false; }
}
function isExport(url, origin) {
  if (!isLocal(url, origin)) return false;
  return /^\/api\/samples\/[a-zA-Z0-9-]+\/(report\.pdf|iocs\.(csv|json))$/.test(new URL(url).pathname);
}
function externalURL(url) {
  try { const u = new URL(url); return ['https:', 'http:'].includes(u.protocol) && !u.username && !u.password; } catch { return false; }
}
module.exports = { isLocal, isExport, externalURL };
