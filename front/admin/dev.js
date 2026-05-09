import express from 'express';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();

app.disable('x-powered-by');
app.use('/style', express.static(join(__dirname, 'style')));
app.use('/js', express.static(join(__dirname, 'dist/js')));
app.use('/', express.static(join(__dirname, 'dist')));

// SPA fallback — serve index.html for all non-API routes
app.get('/*', (req, res) => {
  res.sendFile(join(__dirname, 'index.html'));
});

const PORT = process.env.PORT || 3008;
const BIND_ADDRESS = process.env.BIND_ADDRESS || '127.0.0.1';
app.listen(PORT, BIND_ADDRESS, () => {
  console.log(`Dev server running at http://${BIND_ADDRESS}:${PORT}`);
});
