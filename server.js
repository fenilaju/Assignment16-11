require('dotenv').config();

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const { MongoClient, MongoServerError, ObjectId } = require('mongodb');

const scrypt = promisify(crypto.scrypt);
const root = __dirname;
const port = Number(process.env.PORT || 3000);
const mongoUri = process.env.MONGODB_URI;
const dbName = process.env.MONGODB_DB || 'login_app';
const sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const sessionDuration = 7 * 24 * 60 * 60;
const cookieName = 'login_session';
const publicFiles = new Set(['index.html', 'login.html', 'dashboard.html', 'app.js', 'particles.js', 'style.css']);

const mimeTypes = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
};

function sendJson(res, status, data, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
  res.end(JSON.stringify(data));
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
      if (body.length > 10_000) {
        reject(new Error('Request too large'));
        req.destroy();
      }
    });
    req.on('end', () => {
      try { resolve(JSON.parse(body || '{}')); }
      catch { reject(new Error('Invalid JSON')); }
    });
    req.on('error', reject);
  });
}

async function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = await scrypt(password, salt, 64);
  return { salt, hash: hash.toString('hex') };
}

async function passwordMatches(password, user) {
  const candidate = await hashPassword(password, user.passwordSalt);
  const expected = Buffer.from(user.passwordHash, 'hex');
  const actual = Buffer.from(candidate.hash, 'hex');
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

function makeSession(user) {
  const payload = Buffer.from(JSON.stringify({ id: user._id.toString(), exp: Date.now() + sessionDuration * 1000 })).toString('base64url');
  const signature = crypto.createHmac('sha256', sessionSecret).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}

function readSession(req) {
  const cookies = Object.fromEntries((req.headers.cookie || '').split(';').map((item) => {
    const separator = item.indexOf('=');
    return separator < 0 ? ['', ''] : [item.slice(0, separator).trim(), item.slice(separator + 1).trim()];
  }));
  const token = cookies[cookieName];
  if (!token) return null;
  const [payload, signature] = token.split('.');
  if (!payload || !signature) return null;
  const expected = crypto.createHmac('sha256', sessionSecret).update(payload).digest();
  let received;
  try { received = Buffer.from(signature, 'base64url'); } catch { return null; }
  if (received.length !== expected.length || !crypto.timingSafeEqual(received, expected)) return null;
  try {
    const session = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    return session.exp > Date.now() ? session : null;
  } catch { return null; }
}

function sessionCookie(value, maxAge) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  return `${cookieName}=${value}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${secure}`;
}

function cleanUser(user) {
  return { id: user._id.toString(), name: user.name, email: user.email };
}

function serveFile(req, res) {
  const pathname = new URL(req.url, 'http://localhost').pathname;
  let decoded;
  try { decoded = decodeURIComponent(pathname); } catch { res.writeHead(400).end('Bad request'); return; }
  const relative = decoded === '/' ? 'index.html' : decoded.replace(/^\/+/, '');
  if (!publicFiles.has(relative)) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }).end('Not found'); return; }
  const filePath = path.resolve(root, relative);
  if (filePath !== root && !filePath.startsWith(root + path.sep)) { res.writeHead(403).end('Forbidden'); return; }
  fs.readFile(filePath, (error, data) => {
    if (error) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }).end('Not found'); return; }
    res.writeHead(200, { 'Content-Type': mimeTypes[path.extname(filePath)] || 'application/octet-stream', 'X-Content-Type-Options': 'nosniff' });
    res.end(data);
  });
}

async function start() {
  if (!mongoUri) throw new Error('MONGODB_URI is required. See README.md for setup.');
  if (process.env.NODE_ENV === 'production' && !process.env.SESSION_SECRET) {
    throw new Error('SESSION_SECRET is required in production.');
  }

  const client = new MongoClient(mongoUri);
  await client.connect();
  const users = client.db(dbName).collection('users');
  await users.createIndex({ email: 1 }, { unique: true });

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    try {
      if (req.method === 'POST' && url.pathname === '/api/register') {
        const { name, email, password } = await readJson(req);
        const cleanName = typeof name === 'string' ? name.trim() : '';
        const cleanEmail = typeof email === 'string' ? email.trim().toLowerCase() : '';
        if (!cleanName || cleanName.length > 80 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
          return sendJson(res, 400, { ok: false, error: 'Enter a name and a valid email address.' });
        }
        if (typeof password !== 'string' || password.length < 8 || password.length > 128) {
          return sendJson(res, 400, { ok: false, error: 'Password must be 8 to 128 characters.' });
        }
        const credentials = await hashPassword(password);
        const user = { name: cleanName, email: cleanEmail, passwordSalt: credentials.salt, passwordHash: credentials.hash, createdAt: new Date() };
        try {
          const result = await users.insertOne(user);
          user._id = result.insertedId;
        } catch (error) {
          if (error instanceof MongoServerError && error.code === 11000) return sendJson(res, 409, { ok: false, error: 'This email is already registered.' });
          throw error;
        }
        return sendJson(res, 201, { ok: true, user: cleanUser(user) }, { 'Set-Cookie': sessionCookie(makeSession(user), sessionDuration) });
      }

      if (req.method === 'POST' && url.pathname === '/api/login') {
        const { email, password } = await readJson(req);
        const cleanEmail = typeof email === 'string' ? email.trim().toLowerCase() : '';
        const user = await users.findOne({ email: cleanEmail });
        if (!user || typeof password !== 'string' || !(await passwordMatches(password, user))) {
          return sendJson(res, 401, { ok: false, error: 'Incorrect email or password.' });
        }
        return sendJson(res, 200, { ok: true, user: cleanUser(user) }, { 'Set-Cookie': sessionCookie(makeSession(user), sessionDuration) });
      }

      if (req.method === 'GET' && url.pathname === '/api/me') {
        const session = readSession(req);
        if (!session || !/^[a-f\d]{24}$/i.test(session.id)) return sendJson(res, 401, { ok: false });
        const user = await users.findOne({ _id: new ObjectId(session.id) }, { projection: { name: 1, email: 1 } });
        if (!user) return sendJson(res, 401, { ok: false });
        return sendJson(res, 200, { ok: true, user: cleanUser(user) });
      }

      if (req.method === 'POST' && url.pathname === '/api/logout') {
        return sendJson(res, 200, { ok: true }, { 'Set-Cookie': sessionCookie('', 0) });
      }

      if (req.method === 'GET' || req.method === 'HEAD') return serveFile(req, res);
      return sendJson(res, 404, { ok: false, error: 'Not found.' });
    } catch (error) {
      if (!res.headersSent) sendJson(res, 400, { ok: false, error: error.message === 'Request too large' ? 'Request is too large.' : 'The request could not be completed.' });
    }
  });

  server.listen(port, () => console.log(`Login app listening on port ${port}`));
  const shutdown = async () => { server.close(); await client.close(); };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

start().catch((error) => { console.error(error.message); process.exit(1); });
