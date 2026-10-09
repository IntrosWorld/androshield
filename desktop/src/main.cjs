const { app, BrowserWindow, Menu, dialog, shell, session } = require('electron');
const path = require('node:path');
const fs = require('node:fs');
const { startBackend } = require('./backend.cjs');
const { isLocal, isExport, externalURL } = require('./policy.cjs');
let window, backend, origin;
let quitting = false;
let ready = false;
const root = path.join(__dirname, '..');
app.setName('APK Fraud Analyzer');
if (process.env.APK_DESKTOP_USER_DATA) app.setPath('userData', process.env.APK_DESKTOP_USER_DATA);
const ownsLock = app.requestSingleInstanceLock();
if (!ownsLock) app.quit();
app.on('second-instance', () => { if (window) { if (window.isMinimized()) window.restore(); window.show(); window.focus(); } });

async function openExternal(url) {
  if (!externalURL(url)) return;
  const { response } = await dialog.showMessageBox(window, { type: 'question', title: 'Open external link?',
    message: 'Open this address in your browser?', detail: url, buttons: ['Cancel', 'Open browser'], defaultId: 0, cancelId: 0 });
  if (response === 1) await shell.openExternal(url);
}

function createWindow() {
  window = new BrowserWindow({ width: 1440, height: 940, minWidth: 1000, minHeight: 700,
    title: 'APK Fraud Analyzer', backgroundColor: '#080b10', show: false,
    webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true, webviewTag: false,
      partition: 'persist:analyzer' } });
  window.once('ready-to-show', () => window.show());
  window.webContents.on('will-navigate', (event, url) => {
    if (!origin || !isLocal(url, origin)) { event.preventDefault(); void openExternal(url); }
  });
  window.webContents.setWindowOpenHandler(({ url }) => {
    if (isExport(url, origin)) window.webContents.downloadURL(url);
    else void openExternal(url);
    return { action: 'deny' };
  });
  window.webContents.on('will-attach-webview', event => event.preventDefault());
  window.on('closed', () => { window = null; });
  return window.loadFile(path.join(__dirname, 'loading.html'));
}

async function boot() {
  ready = false;
  await createWindow();
  const ses = session.fromPartition('persist:analyzer');
  ses.setPermissionRequestHandler((_wc, _permission, callback) => callback(false));
  ses.setPermissionCheckHandler(() => false);
  ses.on('will-download', (_event, item) => {
    item.setSaveDialogOptions({ title: 'Save analysis export', defaultPath: path.join(app.getPath('downloads'), path.basename(item.getFilename())) });
  });
  fs.mkdirSync(app.getPath('userData'), { recursive: true });
  backend = startBackend({ root, resources: process.resourcesPath, packaged: app.isPackaged, data: app.getPath('userData'),
    onExit: () => { if (ready && !quitting) { dialog.showErrorBox('Analysis engine stopped', 'Restart the desktop app to continue. Saved analyses are retained.'); app.quit(); } } });
  try {
    const connection = await backend.ready;
    if (quitting) return;
    origin = connection.origin;
    ses.webRequest.onBeforeSendHeaders((details, callback) => {
      if (isLocal(details.url, origin)) details.requestHeaders['X-Desktop-Token'] = connection.token;
      callback({ requestHeaders: details.requestHeaders });
    });
    ses.webRequest.onBeforeRequest((details, callback) => {
      callback({ cancel: !isLocal(details.url, origin) && !details.url.startsWith('blob:') && !details.url.startsWith('devtools:') });
    });
    ses.webRequest.onHeadersReceived((details, callback) => {
      const headers = details.responseHeaders;
      if (isLocal(details.url, origin)) headers['Content-Security-Policy'] = ["default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'self'"];
      callback({ responseHeaders: headers });
    });
    await window.loadURL(origin);
    ready = true;
  } catch (error) {
    if (!quitting) {
      dialog.showErrorBox('Could not start the analyzer', `${error.message}\n\nFor development, install backend/requirements.txt into backend/.venv, then restart. You can also set APK_DESKTOP_PYTHON to a Python executable.`);
      app.quit();
    }
  }
}

app.on('before-quit', event => {
  if (quitting || !backend) return;
  event.preventDefault();
  quitting = true;
  void backend.stop().finally(() => app.quit());
});
app.on('window-all-closed', () => app.quit());
if (ownsLock) app.whenReady().then(() => {
  Menu.setApplicationMenu(Menu.buildFromTemplate([
    ...(process.platform === 'darwin' ? [{ role: 'appMenu' }] : []),
    { label: 'File', submenu: [{ label: 'Open APK…', accelerator: 'CmdOrCtrl+O', click: () => {
      if (ready && window) void window.webContents.executeJavaScript("document.querySelector('input[type=file][accept*=apk]')?.click()");
    } }, { type: 'separator' }, { role: 'quit' }] },
    { role: 'editMenu' }, { label: 'View', submenu: [{ role: 'reload' }, { role: 'resetZoom' }, { role: 'zoomIn' }, { role: 'zoomOut' }, { role: 'togglefullscreen' }, ...(!app.isPackaged ? [{ role: 'toggleDevTools' }] : [])] },
    { label: 'Help', submenu: [{ label: 'Open data folder', click: () => { void shell.openPath(app.getPath('userData')); } },
      { label: 'About APK Fraud Analyzer', click: () => dialog.showMessageBox(window, { title: 'APK Fraud Analyzer', message: `APK Fraud Analyzer ${app.getVersion()}`, detail: 'Static APK analysis and explainable risk scoring.\nElectron desktop with a local Python engine.' }) }] },
  ]));
  return boot();
}).catch(error => { dialog.showErrorBox('Desktop startup failed', error.message); app.quit(); });
