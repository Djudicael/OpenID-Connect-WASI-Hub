import esbuild from 'esbuild';

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

console.log('Build complete: dist/js/index.js');
