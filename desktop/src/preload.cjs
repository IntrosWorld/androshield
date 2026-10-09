const { ipcRenderer } = require('electron');
// Keep theme preference stable even though the private server port changes each run.
// No Electron or filesystem API is exposed to dashboard scripts.
if (location.protocol === 'http:' && location.hostname === '127.0.0.1') {
  const theme = ipcRenderer.sendSync('desktop:theme-read');
  if (theme === 'dark' || theme === 'light') localStorage.setItem('apk-analyzer-theme', theme);
  window.addEventListener('DOMContentLoaded', () => {
    new MutationObserver(() => {
      ipcRenderer.send('desktop:theme-write', document.documentElement.dataset.theme);
    }).observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
  });
}
