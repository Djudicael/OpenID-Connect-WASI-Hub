import esbuild from 'esbuild';
import { copyFile, mkdir } from 'fs/promises';
import { join } from 'path';

await esbuild.build({
  entryPoints: ['app/index.js'],
  bundle: true,
  outfile: 'dist/js/index.js',
  format: 'esm',
  target: 'es2022',
  minify: true,
  sourcemap: true,
  loader: {
    '.css': 'text',
  },
});

// Copy static assets
await mkdir('dist/style', { recursive: true });
await copyFile('style/index.css', 'dist/style/index.css');
await copyFile('style/layout.css', 'dist/style/layout.css');
await copyFile('style/components.css', 'dist/style/components.css');
await copyFile('style/pages.css', 'dist/style/pages.css');
await copyFile('index.html', 'dist/index.html');

console.log('Build complete: dist/');
