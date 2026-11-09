const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'data', 'db.json');

const SESSION_DAYS = 30;
const MAX_BODY = 16 * 1024;
const NAME_RE = /^[A-Za-z0-9_]{3,16}$/;
const MIN_PASSWORD = 6;
const MAX_PASSWORD = 128;
const DAY = 24 * 60 * 60 * 1000;

const failures = new Map();
const hits = new Map();

function load() {
  try {
    const parsed = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    const db = { accounts: parsed.accounts || {}, sessions: parsed.sessions || {} };
    const now = Date.now();
    for (const [token, session] of Object.entries(db.sessions)) {
      if (session.expires < now) delete db.sessions[token];
    }
    return db;
  } catch {
    return { accounts: {}, sessions: {} };
  }
}

const db = load();

function writeNow() {
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  const tmp = `${DATA_FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(db), 'utf8');
  fs.renameSync(tmp, DATA_FILE);
}

let saveTimer = null;
function save() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = null;
    writeNow();
  }, 200);
}

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

/** Same UUID Minecraft derives for offline-mode players, so the game can use it later. */
function offlineUuid(name) {
  const bytes = crypto.createHash('md5').update(`OfflinePlayer:${name}`, 'utf8').digest();
  bytes[6] = (bytes[6] & 0x0f) | 0x30;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** Sliding window: returns true when the key has more than `max` hits in `windowMs`. */
function limited(map, key, max, windowMs) {
  const now = Date.now();
  const list = (map.get(key) || []).filter((t) => now - t < windowMs);
  list.push(now);
  map.set(key, list);
  return list.length > max;
}

function recentFailures(key) {
  const now = Date.now();
  const list = (failures.get(key) || []).filter((t) => now - t < 15 * 60 * 1000);
  failures.set(key, list);
  return list.length;
}

function send(res, status, body) {
  const data = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(data),
    'Cache-Control': 'no-store'
  });
  res.end(data);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        reject(new Error('too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try {
        resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {});
      } catch {
        reject(new Error('bad json'));
      }
    });
    req.on('error', reject);
  });
}

function checkCredentials({ username, password, repeat }, isRegister) {
  const name = String(username || '').trim();
  const pass = String(password || '');
  if (!NAME_RE.test(name)) {
    return { error: 'Ник: от 3 до 16 символов, только латиница, цифры и _' };
  }
  if (pass.length < MIN_PASSWORD || pass.length > MAX_PASSWORD) {
    return { error: `Пароль: от ${MIN_PASSWORD} до ${MAX_PASSWORD} символов` };
  }
  if (isRegister && pass !== String(repeat || '')) {
    return { error: 'Пароли не совпадают' };
  }
  return { name, pass };
}

function userView(record) {
  return {
    username: record.displayName,
    uuid: offlineUuid(record.displayName),
    createdAt: record.createdAt
  };
}

function newSession(key) {
  const token = crypto.randomBytes(32).toString('base64url');
  db.sessions[token] = { key, expires: Date.now() + SESSION_DAYS * DAY };
  return token;
}

function sessionFromRequest(req) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) return null;
  const token = header.slice(7);
  const session = db.sessions[token];
  if (!session) return null;
  if (session.expires < Date.now()) {
    delete db.sessions[token];
    save();
    return null;
  }
  return { token, ...session };
}

const server = http.createServer(async (req, res) => {
  const ip = req.socket.remoteAddress || 'unknown';
  try {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Max-Age', '86400');
    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      return res.end();
    }

    const url = new URL(req.url, 'http://localhost');

    if (req.method === 'GET' && url.pathname === '/api/health') {
      return send(res, 200, { ok: true, service: 'nimbus-auth', version: 1 });
    }

    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
      try {
        const html = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8');
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
        return res.end(html);
      } catch {
        return send(res, 200, { ok: true, service: 'nimbus-auth', version: 1 });
      }
    }

    if (req.method === 'POST' && url.pathname === '/api/register') {
      if (limited(hits, `reg:${ip}`, 10, 60 * 60 * 1000)) {
        return send(res, 429, { ok: false, error: 'Слишком много регистраций с этого адреса, попробуй позже' });
      }
      const body = await readBody(req);
      const check = checkCredentials(body, true);
      if (check.error) return send(res, 400, { ok: false, error: check.error });

      const key = check.name.toLowerCase();
      if (db.accounts[key]) {
        return send(res, 409, { ok: false, error: 'Этот ник уже занят' });
      }
      const salt = crypto.randomBytes(16).toString('hex');
      db.accounts[key] = {
        displayName: check.name,
        salt,
        hash: hashPassword(check.pass, salt),
        createdAt: Date.now(),
        lastLogin: Date.now()
      };
      const token = newSession(key);
      save();
      return send(res, 201, { ok: true, token, user: userView(db.accounts[key]) });
    }

    if (req.method === 'POST' && url.pathname === '/api/login') {
      if (limited(hits, `login:${ip}`, 60, 10 * 60 * 1000)) {
        return send(res, 429, { ok: false, error: 'Слишком много запросов, подожди несколько минут' });
      }
      const body = await readBody(req);
      const check = checkCredentials(body, false);
      if (check.error) return send(res, 400, { ok: false, error: check.error });

      const key = check.name.toLowerCase();
      const failKey = `fail:${key}`;
      if (recentFailures(failKey) >= 8) {
        return send(res, 429, { ok: false, error: 'Слишком много неверных попыток. Подожди 15 минут' });
      }
      const record = db.accounts[key];
      const wrong = () => {
        const list = failures.get(failKey) || [];
        list.push(Date.now());
        failures.set(failKey, list);
        return send(res, 401, { ok: false, error: 'Неверный ник или пароль' });
      };
      if (!record) return wrong();

      const given = Buffer.from(hashPassword(check.pass, record.salt), 'hex');
      const expected = Buffer.from(record.hash, 'hex');
      if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) {
        return wrong();
      }
      failures.delete(failKey);
      record.lastLogin = Date.now();
      const token = newSession(key);
      save();
      return send(res, 200, { ok: true, token, user: userView(record) });
    }

    if (req.method === 'GET' && url.pathname === '/api/me') {
      const session = sessionFromRequest(req);
      if (!session || !db.accounts[session.key]) {
        return send(res, 401, { ok: false, error: 'Сессия истекла, войди снова' });
      }
      return send(res, 200, { ok: true, user: userView(db.accounts[session.key]) });
    }

    if (req.method === 'POST' && url.pathname === '/api/logout') {
      const session = sessionFromRequest(req);
      if (session) {
        delete db.sessions[session.token];
        save();
      }
      return send(res, 200, { ok: true });
    }

    return send(res, 404, { ok: false, error: 'Нет такого адреса' });
  } catch (error) {
    if (error.message === 'bad json' || error.message === 'too large') {
      return send(res, 400, { ok: false, error: 'Некорректный запрос' });
    }
    console.error('[auth]', error);
    return send(res, 500, { ok: false, error: 'Внутренняя ошибка сервера' });
  }
});

function shutdown() {
  if (saveTimer) {
    clearTimeout(saveTimer);
    saveTimer = null;
  }
  writeNow();
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

server.listen(PORT, HOST, () => {
  console.log(`Nimbus auth server on http://${HOST}:${PORT}, data: ${DATA_FILE}`);
  if (HOST === '0.0.0.0' || HOST === '::') {
    for (const list of Object.values(os.networkInterfaces())) {
      for (const net of list || []) {
        if (net.family === 'IPv4' && !net.internal) {
          console.log(`  другой ПК в этой сети: http://${net.address}:${PORT}`);
        }
      }
    }
  }
});

module.exports = { offlineUuid, checkCredentials };
