const { spawn } = require('node:child_process');
const { existsSync } = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');
const { randomBytes } = require('node:crypto');

function pythonPath(root) {
  const local = path.join(root, '../backend/.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python');
  return process.env.APK_DESKTOP_PYTHON || (existsSync(local) ? local : (process.platform === 'win32' ? 'python' : 'python3'));
}

function startBackend({ root, resources, packaged, data, onExit = () => {} }) {
  const token = randomBytes(32).toString('hex');
  const command = packaged ? path.join(resources, 'analyzer', process.platform === 'win32' ? 'analyzer.exe' : 'analyzer') : pythonPath(root);
  const args = packaged ? [] : ['-u', path.join(root, 'backend_entry.py')];
  const child = spawn(command, args, { windowsHide: true, cwd: data, stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...process.env, PYTHONUNBUFFERED: '1', PYTHONIOENCODING: 'utf-8' } });
  let stopping = false;
  let lastError = '';
  let killTimer;
  const ready = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('The analyzer did not start within 90 seconds.')), 90000);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.stderr.on('data', chunk => { lastError = (lastError + chunk).slice(-6000); });
    child.once('exit', (code) => {
      clearTimeout(timer);
      clearTimeout(killTimer);
      reject(new Error(`Analyzer stopped (${code}). ${lastError}`));
      if (!stopping) onExit(lastError || `Analyzer stopped (${code}).`);
    });
    readline.createInterface({ input: child.stdout }).on('line', line => {
      try {
        const message = JSON.parse(line);
        if (Number.isInteger(message.port) && message.port > 0 && message.port <= 65535) {
          clearTimeout(timer);
          resolve({ origin: `http://127.0.0.1:${message.port}`, token });
        }
      } catch { /* Libraries may also write diagnostic lines. */ }
    });
  });
  child.stdin.on('error', () => {});
  child.stdin.write(JSON.stringify({ token, data, frontend: path.join(packaged ? resources : path.join(root, 'build'), 'frontend') }) + '\n');
  function stop() {
    if (stopping || child.exitCode !== null || child.signalCode !== null || !child.pid) return Promise.resolve();
    stopping = true;
    return new Promise(resolve => {
      child.once('exit', resolve);
      child.stdin.end('\n');
      killTimer = setTimeout(() => {
        if (process.platform === 'win32') {
          spawn('taskkill', ['/pid', String(child.pid), '/t', '/f'], { windowsHide: true });
        } else child.kill('SIGKILL');
      }, 8000);
    });
  }
  return { ready, stop, child };
}
module.exports = { startBackend, pythonPath };
