/**
 * Intentionally vulnerable test server — FOR LOCAL TESTING ONLY.
 *
 * Exists so Aegis-DAST can be validated end-to-end against known issues:
 *   - missing security headers + insecure cookie           (/)
 *   - reflected XSS                                         (/search?q=)
 *   - error-based SQLi                                      (/item?id=')
 *   - open redirect                                         (/go?url=)
 *   - CORS: reflects arbitrary Origin + credentials         (/api)
 *   - OS command injection (simulated)                      (/ping?host=)
 *   - SSRF (simulated server-side fetch)                    (/fetch?url=)
 *   - CRLF / header injection (raw socket)                  (/setlang?lang=)
 *   - LLM prompt injection (simulated vulnerable model)     (/chat?msg=)
 *   - CSRF: POST form without a token                       (/profile)
 *
 * DO NOT deploy this anywhere reachable. It is deliberately insecure.
 */
import { createServer, type Server } from 'node:http';
import { URL } from 'node:url';

export function createVulnServer(): Server {
  return createServer((req, res) => {
    try {
      handle(req, res);
    } catch {
      try {
        if (!res.headersSent) res.statusCode = 500;
        res.end('error');
      } catch {
        /* socket already gone */
      }
    }
  });
}

function handle(req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse): void {
  {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    const path = url.pathname;

    // VULN: TRACE echoes the request (Cross-Site Tracing).
    if (req.method === 'TRACE') {
      res.statusCode = 200;
      res.setHeader('Content-Type', 'message/http');
      res.end(`TRACE ${req.url} HTTP/1.1\r\nhost: ${req.headers.host}\r\n`);
      return;
    }
    // VULN: advertises risky methods.
    if (req.method === 'OPTIONS') {
      res.statusCode = 200;
      res.setHeader('Allow', 'GET, POST, PUT, DELETE, TRACE, OPTIONS');
      res.end('');
      return;
    }

    // --- Routes needing raw control must run BEFORE we set common headers. ---

    // VULN: CRLF injection — reflects `lang` into a header with no sanitization.
    // Node's setHeader blocks CRLF, so we write the response raw to the socket.
    if (path === '/setlang') {
      const lang = url.searchParams.get('lang') ?? 'en'; // already %-decoded (may contain CRLF)
      const body = `<!doctype html><html><body>Language set to ${lang}</body></html>`;
      const raw =
        `HTTP/1.1 200 OK\r\n` +
        `Content-Type: text/html; charset=utf-8\r\n` +
        `Content-Language: ${lang}\r\n` +
        `Content-Length: ${Buffer.byteLength(body)}\r\n` +
        `Connection: close\r\n\r\n` +
        body;
      res.socket?.write(raw);
      res.socket?.end();
      return;
    }

    // --- Common (insecure) headers for the remaining routes. ---
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Set-Cookie', 'session=abc123; Path=/');
    res.setHeader('Server', 'VulnServer/1.0');

    if (path === '/') {
      // VULN: reflects the X-Forwarded-Host header into an absolute link.
      const xfh = req.headers['x-forwarded-host'];
      const canonical = typeof xfh === 'string' ? `https://${xfh}/` : 'https://127.0.0.1/';
      res.statusCode = 200;
      res.end(`<!doctype html><html><head><title>Vuln App</title>
        <link rel="canonical" href="${canonical}"></head><body>
        <h1>Welcome</h1>
        <nav>
          <a href="/search?q=hello">Search</a>
          <a href="/item?id=1">Item</a>
          <a href="/go?url=/home">Redirector</a>
          <a href="/profile">Profile</a>
          <a href="/ping?host=127.0.0.1">Ping</a>
          <a href="/fetch?url=http://example.com/feed">Fetch</a>
          <a href="/setlang?lang=en">Language</a>
          <a href="/api?x=1">API</a>
          <a href="/chat?msg=hello">Chat</a>
          <a href="/render?name=guest">Render</a>
        </nav>
        <form action="/search" method="get"><input name="q" value="test"><button>Go</button></form>
      </body></html>`);
      return;
    }

    // VULN: server-side template injection — evaluates {{a*b}} style expressions.
    if (path === '/render') {
      const name = url.searchParams.get('name') ?? 'guest';
      const m = name.match(/(\d{3,})\s*\*\s*(\d+)/);
      const out = m ? String(Number(m[1]) * Number(m[2])) : name;
      res.statusCode = 200;
      res.end(`<!doctype html><html><body><h1>Hello ${out}</h1></body></html>`);
      return;
    }

    // VULN: exposed sensitive files.
    if (path === '/.git/config') {
      res.statusCode = 200;
      res.end('[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = git@github.com:acme/secret.git\n');
      return;
    }
    if (path === '/.env') {
      res.statusCode = 200;
      res.end('DB_PASSWORD=sup3rs3cret\nAPI_KEY=AKIAIOSFODNN7EXAMPLE\nDEBUG=true\n');
      return;
    }

    // VULN: GraphQL introspection enabled.
    if (path === '/graphql') {
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ data: { __schema: { queryType: { name: 'Query' }, types: [{ name: 'User' }] } } }));
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
      res.statusCode = 302; // VULN: unvalidated redirect
      try {
        res.setHeader('Location', target); // Node rejects CRLF here (ERR_INVALID_CHAR)
      } catch {
        res.setHeader('Location', '/'); // models a server that refuses bad Location values
      }
      res.end('redirecting');
      return;
    }

    if (path === '/profile') {
      res.statusCode = 200;
      // VULN: state-changing POST form with no anti-CSRF token.
      res.end(`<!doctype html><html><body>
        <form action="/profile" method="post">
          <input name="email" value="user@example.com">
          <input name="bio" value="hi">
          <button>Save</button>
        </form></body></html>`);
      return;
    }

    if (path === '/api') {
      // VULN: reflects arbitrary Origin and allows credentials.
      const origin = req.headers['origin'];
      if (origin) {
        res.setHeader('Access-Control-Allow-Origin', Array.isArray(origin) ? origin[0]! : origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
      }
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ ok: true, x: url.searchParams.get('x') }));
      return;
    }

    if (path === '/ping') {
      const host = url.searchParams.get('host') ?? '';
      // VULN (simulated): "runs" ping <host> in a shell. If the input injects an
      // `echo <marker>`, the marker appears in the output — modeling command exec.
      // We mimic the shell stripping quotes from the echoed argument.
      const echo = host.match(/echo\s+([A-Za-z0-9"']+)/);
      const out = echo ? echo[1]!.replace(/['"]/g, '') : 'PING statistics: 0% packet loss';
      res.statusCode = 200;
      // Note: we do NOT reflect the raw host in the non-echo case (avoids a
      // simulated-SSRF artifact where an echoed hostname looks like a fetch).
      res.end(`<!doctype html><html><body><pre>${out}</pre></body></html>`);
      return;
    }

    if (path === '/fetch') {
      const target = url.searchParams.get('url') ?? '';
      // VULN (simulated): the server fetches the URL and leaks the resolver error,
      // modeling an SSRF-capable endpoint.
      let host = '';
      try {
        host = new URL(target).host;
      } catch {
        host = target;
      }
      res.statusCode = 200;
      res.end(`<!doctype html><html><body>
        Error fetching ${target}: getaddrinfo ENOTFOUND ${host}</body></html>`);
      return;
    }

    if (path === '/chat') {
      const msg = url.searchParams.get('msg') ?? '';
      // VULN (simulated LLM): follows instructions embedded in user input. If the
      // message asks to multiply A by B, it "obeys" and returns the product only.
      const m = msg.match(/(\d+)\s*(?:multiplied by|times|\*|x)\s*(\d+)/i);
      res.statusCode = 200;
      if (m) {
        const product = Number.parseInt(m[1]!, 10) * Number.parseInt(m[2]!, 10);
        res.end(`<!doctype html><html><body>${product}</body></html>`);
      } else {
        // Does NOT echo the message back (so this isn't an XSS/reflection source).
        res.end(`<!doctype html><html><body>Hello! How can I help you today?</body></html>`);
      }
      return;
    }

    res.statusCode = 404;
    res.end('<!doctype html><html><body>Not found</body></html>');
  }
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
