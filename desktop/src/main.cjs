const { app, BrowserWindow, Menu, dialog, shell, session, ipcMain } = require('electron');
const path = require('node:path');
const fs = require('node:fs');
const { startBackend } = require('./backend.cjs');
const { isLocal, isExport, externalURL } = require('./policy.cjs');
const { profilePath, migrateLegacyProfile } = require('./profile.cjs');
let window, backend, origin;
let quitting = false;
let ready = false;
const root = path.join(__dirname, '..');
app.setName('AndroShield');
const profile = profilePath(process.env, app.getPath('appData'));
let profileError;
if (profile) {
  try {
    migrateLegacyProfile(profile, process.env, app.getPath('appData'));
    fs.mkdirSync(profile, { recursive: true });
    fs.accessSync(profile, fs.constants.W_OK);
    app.setPath('userData', profile);
    app.setPath('sessionData', profile);
    fs.mkdirSync(path.join(profile, 'crashes'), { recursive: true });
    app.setPath('crashDumps', path.join(profile, 'crashes'));
    for (const folder of ['tmp', 'exports', 'logs']) fs.mkdirSync(path.join(profile, folder), { recursive: true });
    app.setPath('temp', path.join(profile, 'tmp'));
    app.setPath('downloads', path.join(profile, 'exports'));
    app.setAppLogsPath(path.join(profile, 'logs'));
    process.env.TEMP = process.env.TMP = path.join(profile, 'tmp');
  } catch (error) { profileError = error; }
}
const ownsLock = Boolean(profileError) || app.requestSingleInstanceLock();
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
    title: 'AndroShield', backgroundColor: '#f6f8f6', show: false,
    webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true, webviewTag: false,
      preload: path.join(__dirname, 'preload.cjs'),
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
  if (profileError) {
    dialog.showErrorBox('Cannot open data folder', `Move the portable app to a writable folder, then retry.\n\n${profile}\n${profileError.message}`);
    app.quit();
    return;
  }
  const themeFile = path.join(app.getPath('userData'), 'theme.json');
  const trusted = event => window && event.sender === window.webContents && isLocal(event.senderFrame?.url, origin);
  ipcMain.on('desktop:theme-read', event => {
    let theme = 'light';
    if (trusted(event)) {
      try {
        const saved = JSON.parse(fs.readFileSync(themeFile, 'utf8'));
        if (['dark', 'light'].includes(saved)) theme = saved;
      } catch { /* First launch. */ }
    }
    // Setting returnValue sends the synchronous reply immediately; reply once.
    event.returnValue = theme;
  });
  ipcMain.on('desktop:theme-write', (event, theme) => {
    if (trusted(event) && ['dark', 'light'].includes(theme)) {
      try { fs.writeFileSync(themeFile, JSON.stringify(theme)); } catch { /* Read-only profile. */ }
    }
  });
  Menu.setApplicationMenu(Menu.buildFromTemplate([
    ...(process.platform === 'darwin' ? [{ role: 'appMenu' }] : []),
    { label: 'File', submenu: [{ label: 'Open APK…', accelerator: 'CmdOrCtrl+O', click: () => {
      if (ready && window) void window.webContents.executeJavaScript("document.querySelector('input[type=file][accept*=apk]')?.click()", true);
    } }, { type: 'separator' }, { role: 'quit' }] },
    { role: 'editMenu' }, { label: 'View', submenu: [{ role: 'reload' }, { role: 'resetZoom' }, { role: 'zoomIn' }, { role: 'zoomOut' }, { role: 'togglefullscreen' }, ...(!app.isPackaged ? [{ role: 'toggleDevTools' }] : [])] },
    { label: 'Help', submenu: [{ label: 'Open data folder', click: () => { void shell.openPath(app.getPath('userData')); } },
      { label: 'About AndroShield', click: () => dialog.showMessageBox(window, { title: 'AndroShield', message: `AndroShield ${app.getVersion()}`, detail: 'Static APK analysis and explainable risk scoring.\nElectron desktop with a local Python engine.' }) }] },
  ]));
  return boot();
}).catch(error => { dialog.showErrorBox('Desktop startup failed', error.message); app.quit(); });
