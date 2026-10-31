/**
 * Intentionally vulnerable test server — FOR LOCAL TESTING ONLY.
 *
 * This exists so Aegis-DAST can be validated end-to-end against known issues:
 *   - missing security headers + insecure cookie
 *   - reflected XSS at /search?q=
 *   - error-based SQLi at /item?id='
 *   - open redirect at /go?url=
 *
 * DO NOT deploy this anywhere reachable. It is deliberately insecure.
 */
import { createServer, type Server } from 'node:http';
import { URL } from 'node:url';

export function createVulnServer(): Server {
  return createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    const path = url.pathname;

    // Deliberately omit security headers; set an insecure cookie.
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Set-Cookie', 'session=abc123; Path=/');
    res.setHeader('Server', 'VulnServer/1.0');

    if (path === '/') {
      res.statusCode = 200;
      res.end(`<!doctype html><html><head><title>Vuln App</title></head><body>
        <h1>Welcome</h1>
        <nav>
          <a href="/search?q=hello">Search</a>
          <a href="/item?id=1">Item</a>
          <a href="/go?url=/home">Redirector</a>
        </nav>
        <form action="/search" method="get"><input name="q" value="test"><button>Go</button></form>
      </body></html>`);
      return;
    }

    if (path === '/search') {
      const q = url.searchParams.get('q') ?? '';
      res.statusCode = 200;
      // VULN: reflects user input without encoding.
      res.end(`<!doctype html><html><body><h1>Results for ${q}</h1></body></html>`);
      return;
    }

    if (path === '/item') {
      const id = url.searchParams.get('id') ?? '';
      if (id.includes("'") || id.includes('"')) {
        res.statusCode = 500;
        // VULN: leaks a SQL error.
        res.end(`<!doctype html><html><body>
          You have an error in your SQL syntax; check the manual that corresponds to your MySQL server
          version for the right syntax near '${id}'</body></html>`);
        return;
      }
      res.statusCode = 200;
      res.end(`<!doctype html><html><body>Item ${id}</body></html>`);
      return;
    }

    if (path === '/go') {
      const target = url.searchParams.get('url') ?? '/';
      // VULN: unvalidated redirect.
      res.statusCode = 302;
      res.setHeader('Location', target);
      res.end('redirecting');
      return;
    }

    res.statusCode = 404;
    res.end('<!doctype html><html><body>Not found</body></html>');
  });
}

/** Start on a given port (0 = random) and resolve with the actual port. */
export function startVulnServer(port = 0): Promise<{ server: Server; port: number; url: string }> {
  const server = createVulnServer();
  return new Promise((resolve) => {
    server.listen(port, '127.0.0.1', () => {
      const addr = server.address();
      const actual = typeof addr === 'object' && addr ? addr.port : port;
      resolve({ server, port: actual, url: `http://127.0.0.1:${actual}` });
    });
  });
}

// Run standalone: `npm run demo:server`
const isMain = process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/'));
if (isMain) {
  const port = Number.parseInt(process.env.PORT ?? '3000', 10);
  startVulnServer(port).then(({ url }) => {
    console.log(`Vulnerable test server listening at ${url}`);
    console.log('WARNING: intentionally insecure — local testing only. Ctrl+C to stop.');
  });
}
