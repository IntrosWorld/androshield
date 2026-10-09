const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const source = path.join(root, '../frontend');
const output = path.join(root, 'build/frontend');
fs.mkdirSync(output, { recursive: true });
fs.cpSync(source, output, { recursive: true });
let html = fs.readFileSync(path.join(source, 'index.html'), 'utf8');
html = html.replace(/<script>([\s\S]*?)<\/script>/, (_, script) => {
  fs.writeFileSync(path.join(output, 'theme.js'), script);
  return '<script src="theme.js"></script>';
});
html = html.replace('<script src="https://cdn.tailwindcss.com"></script>', '<link rel="stylesheet" href="desktop-tailwind.css" />')
  .replace('https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js', 'chart.umd.js');
fs.writeFileSync(path.join(output, 'index.html'), html);
fs.copyFileSync(path.join(root, 'node_modules/chart.js/dist/chart.umd.js'), path.join(output, 'chart.umd.js'));
fs.copyFileSync(path.join(root, 'node_modules/chart.js/LICENSE.md'), path.join(output, 'CHART-LICENSE.md'));
fs.copyFileSync(path.join(root, 'node_modules/tailwindcss/LICENSE'), path.join(output, 'TAILWIND-LICENSE.txt'));
fs.writeFileSync(path.join(root, 'build/tailwind.css'), '@tailwind base;\n@tailwind components;\n@tailwind utilities;\n');
execFileSync(process.execPath, [path.join(root, 'node_modules/tailwindcss/lib/cli.js'),
  '-i', path.join(root, 'build/tailwind.css'), '-o', path.join(output, 'desktop-tailwind.css'),
  '--content', `${source.replaceAll('\\', '/')}/**/*.{html,js}`, '--minify'], { stdio: 'inherit', cwd: root });
console.log('Desktop assets ready.');
