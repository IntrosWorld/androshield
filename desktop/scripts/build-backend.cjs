const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { pythonPath } = require('../src/backend.cjs');
const root = path.resolve(__dirname, '..');
const python = pythonPath(root);
try { execFileSync(python, ['-m', 'PyInstaller', '--version'], { stdio: 'pipe' }); }
catch { throw new Error('Install desktop build dependencies first: backend/.venv/Scripts/python -m pip install -r desktop/requirements-build.txt'); }
const args = ['-m', 'PyInstaller', '--noconfirm', '--onedir', '--name', 'analyzer',
  '--distpath', path.join(root, 'backend-dist'), '--workpath', path.join(root, 'backend-build'),
  '--specpath', path.join(root, 'backend-build'), '--paths', path.join(root, '../backend'),
  '--collect-submodules', 'app', '--collect-all', 'androguard', '--collect-all', 'apkid',
  '--collect-all', 'frida', '--collect-data', 'google.generativeai',
  '--collect-submodules', 'sklearn.ensemble', '--collect-submodules', 'sklearn.feature_extraction',
  '--hidden-import', 'uvicorn.logging', '--hidden-import', 'uvicorn.loops.asyncio',
  '--hidden-import', 'uvicorn.protocols.http.h11_impl', '--hidden-import', 'uvicorn.lifespan.on',
  '--add-data', `${path.join(root, '../backend/app/rules')}:app/rules`,
  '--add-data', `${path.join(root, '../backend/app/dynamic/frida_hooks.js')}:app/dynamic`,
  '--add-data', `${path.join(root, '../backend/app/dynamic/frida_antivm.js')}:app/dynamic`,
  '--add-data', `${path.join(root, '../scripts/install_sandbox_components.ps1')}:scripts`,
  '--exclude-module', 'IPython', '--exclude-module', 'notebook', '--exclude-module', 'tkinter',
  path.join(root, 'backend_entry.py')];
execFileSync(python, args, { stdio: 'inherit', cwd: root });
