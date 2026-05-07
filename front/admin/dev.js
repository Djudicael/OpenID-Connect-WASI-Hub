import express from 'express';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();

app.disable('x-powered-by');
app.use('/', express.static(join(__dirname, 'dist')));
app.get('/*', (req, res) => {
  res.sendFile(join(__dirname, 'dist/index.html'));
});

app.listen(3008, () => {
  console.log('Dev server running at http://localhost:3008');
});
