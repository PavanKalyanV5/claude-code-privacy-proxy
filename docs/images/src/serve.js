// Tiny static server so Playwright can render the diagrams (it blocks the
// file: protocol). Loopback only, exits on its own so it cannot be left
// running by accident.
const http = require('http');
const fs = require('fs');
const path = require('path');

const DIR = __dirname;
const TYPES = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.svg': 'image/svg+xml' };

const server = http.createServer((req, res) => {
  const name = decodeURIComponent(req.url.split('?')[0]).replace(/^\/+/, '') || 'index.html';
  // Confine to this directory: a path check, even on a throwaway server,
  // because "it's only local" is how traversal bugs get written.
  const full = path.resolve(DIR, name);
  if (!full.startsWith(path.resolve(DIR))) {
    res.writeHead(403);
    return res.end('no');
  }
  fs.readFile(full, (err, body) => {
    if (err) {
      res.writeHead(404);
      return res.end('not found');
    }
    res.writeHead(200, { 'content-type': TYPES[path.extname(full)] || 'application/octet-stream' });
    res.end(body);
  });
});

server.listen(8791, '127.0.0.1', () => console.log('http://127.0.0.1:8791/'));
setTimeout(() => process.exit(0), 10 * 60 * 1000).unref();
