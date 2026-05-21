import esbuild from 'esbuild';
import { mkdir, readFile, writeFile, readdir, rm } from 'fs/promises';
import { createHash } from 'crypto';
import { join } from 'path';

const isProd = process.env.NODE_ENV === 'production' || process.argv.includes('--prod');

await rm('dist', { recursive: true, force: true });
await mkdir('dist/js', { recursive: true });

// Bundle JS
await esbuild.build({
  entryPoints: ['app/index.js'],
  bundle: true,
  outfile: 'dist/js/index.js',
  format: 'esm',
  target: 'es2022',
  minify: isProd,
  sourcemap: !isProd,
  legalComments: 'none',
  loader: { '.css': 'text' },
});

// Read all CSS files and concatenate into one
const styleDir = 'style';
const cssFiles = (await readdir(styleDir, { recursive: true }))
  .filter(f => f.endsWith('.css') && f !== 'main.css')
  .sort((a, b) => a.localeCompare(b))
  .map(f => join(styleDir, f));

let allCss = '';
for (const file of cssFiles) {
  const content = await readFile(file, 'utf-8');
  allCss += `/* ${file} */\n${content}\n`;
}

const bundledCss = isProd
  ? (await esbuild.transform(allCss, {
    loader: 'css',
    minify: true,
    legalComments: 'none',
  })).code
  : allCss;

// Write bundled CSS
await mkdir('dist/style', { recursive: true });
const hash = createHash('md5').update(bundledCss).digest('hex').slice(0, 8);
const cssFilename = `bundle.${hash}.css`;

// Write hashed version (for HTML <link> cache-busting)
await writeFile(`dist/style/${cssFilename}`, bundledCss);
// Write unhashed version (for shadow DOM <link> — same URL across builds)
await writeFile('dist/style/bundle.css', bundledCss);

// Inject hashed CSS into dist/index.html
let html = await readFile('index.html', 'utf-8');
html = html.replace('/style/main.css', `/style/${cssFilename}`);
await writeFile('dist/index.html', html);

console.log(`Build complete: dist/ (${isProd ? 'production' : 'development'}, css: ${cssFilename})`);
