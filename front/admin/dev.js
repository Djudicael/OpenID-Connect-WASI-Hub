import express from 'express';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();

app.disable('x-powered-by');
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '0');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'self'; " +
    "style-src-elem 'self'; " +
    "style-src-attr 'unsafe-inline'; " +
    "img-src 'self' data:; " +
    "font-src 'self'; " +
    "connect-src 'self'; " +
    "object-src 'none'; " +
    "frame-ancestors 'none'; " +
    "base-uri 'self'; " +
    "form-action 'self';"
  );
  next();
});

app.use('/style', express.static(join(__dirname, 'style')));

// Cache static JS assets (hashed filenames allow immutable caching)
app.use('/js', (req, res, next) => {
  res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
  next();
});
app.use('/js', express.static(join(__dirname, 'dist/js')));
app.use('/', express.static(join(__dirname, 'dist')));

// Security contact
app.get('/.well-known/security.txt', (req, res) => {
  res.type('text/plain');
  res.send(`Contact: mailto:security@example.com
Expires: ${new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString()}
Preferred-Languages: en
Canonical: ${req.protocol}://${req.get('host')}/.well-known/security.txt
`);
});

// SPA fallback — serve index.html only for non-file routes (not for .js, .css, etc.)
app.get('/*', (req, res) => {
  if (/\.(js|css|json|png|jpg|jpeg|gif|ico|svg|woff2?|ttf|eot)$/i.test(req.path)) {
    return res.status(404).send('Not Found');
  }
  res.sendFile(join(__dirname, 'index.html'));
});

const PORT = process.env.PORT || 3008;
const BIND_ADDRESS = process.env.BIND_ADDRESS || '127.0.0.1';
app.listen(PORT, BIND_ADDRESS, () => {
  console.log(`Dev server running at http://${BIND_ADDRESS}:${PORT}`);
});
