'use strict';

// straw licence server - key only, no accounts for the client.
//
// The cheat sends its key + a hardware fingerprint every 3 s. One key lives on
// exactly one machine: the first machine that presents the key binds it, and any
// second machine with the same key gets the key auto-banned on the spot.
//
//   /api/v1/session   first contact, binds the key to this machine
//   /api/v1/ping      every 3 s, keeps the live row fresh, answers banned/live
//   /dashboard        you: live machines, ips, hwid, ban/unban, keys

const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const crypto = require('crypto');

const db = require('./db');
const auth = require('./auth');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(24).toString('hex');

// a machine counts as live while it has pinged within this window
const LIVE_WINDOW_SEC = Number(process.env.LIVE_WINDOW_SEC || 10);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.json({ limit: '16kb' }));
app.use(cookieParser(SECRET));
app.use('/public', express.static(path.join(__dirname, 'public')));

// ── helpers ───────────────────────────────────────────────────────────────

const loginHits = new Map();

function rateLimited(ip) {
  const now = Date.now();
  const hit = loginHits.get(ip);
  if (hit && hit.until > now && hit.count >= 10) return true;
  if (!hit || hit.until <= now) loginHits.set(ip, { count: 0, until: now + 60_000 });
  loginHits.get(ip).count += 1;
  return false;
}

function clientIp(req) {
  return (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '')
    .toString().split(',')[0].trim();
}

function signSession(userId, role) {
  const exp = Date.now() + 12 * 60 * 60 * 1000;
  const body = `${userId}.${role}.${exp}`;
  const mac = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return `${body}.${mac}`;
}

function readSession(req) {
  const raw = req.cookies?.straw_session;
  if (!raw) return null;
  const parts = String(raw).split('.');
  if (parts.length !== 4) return null;
  const [uid, role, exp, mac] = parts;
  const want = crypto.createHmac('sha256', SECRET)
    .update(`${uid}.${role}.${exp}`).digest('base64url');
  if (mac.length !== want.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(want))) return null;
  if (Number(exp) < Date.now()) return null;
  return { userId: Number(uid), role };
}

function requireRole(...roles) {
  return (req, res, next) => {
    const session = readSession(req);
    if (!session) {
      if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'auth' });
      return res.redirect('/login');
    }
    if (roles.length && !roles.includes(session.role)) {
      return res.status(403).json({ error: 'role' });
    }
    req.session = session;
    next();
  };
}

// what the dashboard needs to render one machine
const DEVICE_SQL = `
  SELECT d.id, d.key_id, d.hwid, d.hw_info, d.ip, d.first_seen, d.last_seen,
         k.code AS key, k.banned, k.ban_reason, k.days, k.note,
         (now() - d.last_seen) < interval '${LIVE_WINDOW_SEC} seconds' AS live
    FROM devices d
    JOIN keys k ON k.id = d.key_id`;

// ── client api ────────────────────────────────────────────────────────────

app.get('/healthz', (_req, res) => res.json({ ok: true }));
app.get('/api/v1/ping', (_req, res) => res.json({ ok: true, t: Date.now() }));
app.get('/api/v1/pubkey', (_req, res) => res.json(auth.publicKey()));

function ticketFor(key) {
  const exp = Math.floor(Date.now() / 1000) + 120;   // short, re-signed on ping
  const payload = `k=${key.code};e=${exp}`;
  const signed = auth.signTicket(payload);
  return `${signed.payload}|${signed.sig}`;
}

// ── offset pushes ─────────────────────────────────────────────────────────

async function latestUpdate() {
  return db.one('SELECT * FROM updates ORDER BY version DESC LIMIT 1');
}

// returns the newest table when this client build is older than it.
// a negative version means "not managed by offset pushes" (the rblx build).
async function outdated(version) {
  const latest = await latestUpdate();
  if (!latest) return null;
  const mine = Number(version);
  if (!Number.isFinite(mine) || mine < 0) return null;
  return mine < latest.version ? latest : null;
}

function updateTicket(latest) {
  const exp = Math.floor(Date.now() / 1000) + 120;
  const payload = `v=${latest.version};sha=${latest.sha};e=${exp}`;
  const signed = auth.signTicket(payload);
  return `${signed.payload}|${signed.sig}`;
}

async function banKey(keyId, reason) {
  await db.query(
    `UPDATE keys SET banned = TRUE, ban_reason = $1, banned_at = now() WHERE id = $2`,
    [reason, keyId]);
}

// first contact from a machine: bind or refuse
app.post('/api/v1/session', async (req, res) => {
  try {
    const { key, hwid, hw } = req.body || {};
    if (!key || !hwid) return res.status(400).json({ error: 'missing key or hwid' });

    const row = await db.one('SELECT * FROM keys WHERE code = $1', [String(key).toUpperCase()]);
    if (!row) return res.status(404).json({ error: 'unknown key' });
    if (!row.active) return res.status(403).json({ error: 'key disabled' });
    if (row.banned) {
      return res.status(403).json({ error: 'banned', reason: row.ban_reason || 'banned' });
    }

    // second machine on the same key: ban immediately, this is the whole point
    if (row.hwid && row.hwid !== hwid) {
      await banKey(row.id, 'used on a second machine');
      await db.query(
        `INSERT INTO devices (key_id, hwid, hw_info, ip)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (key_id, hwid) DO UPDATE
           SET last_seen = now(), ip = EXCLUDED.ip, hw_info = EXCLUDED.hw_info`,
        [row.id, hwid, hw || null, clientIp(req)]);
      console.warn(`[ban] ${row.code} second hwid ${hwid.slice(0, 12)} from ${clientIp(req)}`);
      return res.status(403).json({ error: 'banned', reason: 'used on a second machine' });
    }

    const ip = clientIp(req);
    if (!row.hwid) {
      await db.query(
        `UPDATE keys SET hwid = $1, hw_info = $2, first_ip = $3, last_ip = $3,
                first_seen = now(), last_seen = now()
          WHERE id = $4`,
        [hwid, hw || null, ip, row.id]);
    } else {
      await db.query('UPDATE keys SET last_seen = now(), last_ip = $1 WHERE id = $2',
                     [ip, row.id]);
    }

    await db.query(
      `INSERT INTO devices (key_id, hwid, hw_info, ip)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (key_id, hwid) DO UPDATE
         SET last_seen = now(), ip = EXCLUDED.ip, hw_info = EXCLUDED.hw_info`,
      [row.id, hwid, hw || null, ip]);

    // a build older than the newest pushed offset table is not allowed in
    const behind = await outdated(req.body?.version);
    if (behind) {
      return res.status(426).json({
        error: 'update required', version: behind.version, note: behind.note || '',
      });
    }

    console.log(`[session] ${row.code} hwid=${hwid.slice(0, 12)} ip=${ip}`);
    res.json({ ok: true, ticket: ticketFor(row), plan: `${row.days}d` });
  } catch (err) {
    console.error('[session]', err);
    res.status(500).json({ error: 'server' });
  }
});

// every 3 s
app.post('/api/v1/ping', async (req, res) => {
  try {
    const { key, hwid, hw } = req.body || {};
    if (!key || !hwid) return res.status(400).json({ error: 'missing key or hwid' });

    const row = await db.one('SELECT * FROM keys WHERE code = $1', [String(key).toUpperCase()]);
    if (!row) return res.status(404).json({ error: 'unknown key' });

    if (row.banned) {
      return res.json({ ok: false, banned: true, reason: row.ban_reason || 'banned' });
    }
    if (row.hwid && row.hwid !== hwid) {
      await banKey(row.id, 'used on a second machine');
      console.warn(`[ban] ${row.code} hwid mismatch on ping`);
      return res.json({ ok: false, banned: true, reason: 'used on a second machine' });
    }

    const ip = clientIp(req);
    await db.query(
      `UPDATE keys SET last_seen = now(), last_ip = $1,
              hwid = COALESCE(hwid, $2), first_seen = COALESCE(first_seen, now())
        WHERE id = $3`, [ip, hwid, row.id]);
    await db.query(
      `INSERT INTO devices (key_id, hwid, hw_info, ip)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (key_id, hwid) DO UPDATE
         SET last_seen = now(), ip = EXCLUDED.ip, hw_info = EXCLUDED.hw_info`,
      [row.id, hwid, hw || null, ip]);

    const behindPing = await outdated(req.body?.version);
    if (behindPing) {
      return res.status(426).json({
        error: 'update required', version: behindPing.version, note: behindPing.note || '',
      });
    }

    res.json({ ok: true, ticket: ticketFor(row) });
  } catch (err) {
    console.error('[ping]', err);
    res.status(500).json({ error: 'server' });
  }
});

// ── update payload (client) ───────────────────────────────────────────────

app.get('/api/v1/update', async (req, res) => {
  try {
    const key = String(req.query.key || '').toUpperCase();
    const hwid = String(req.query.hwid || '');
    const version = Number(req.query.version) || 0;

    const row = await db.one('SELECT * FROM keys WHERE code = $1', [key]);
    if (!row) return res.status(404).json({ error: 'unknown key' });
    if (row.banned) return res.status(403).json({ error: 'banned', reason: row.ban_reason });
    if (row.hwid && row.hwid !== hwid) {
      return res.status(403).json({ error: 'banned', reason: 'used on a second machine' });
    }

    const latest = await latestUpdate();
    if (!latest || version >= latest.version) {
      return res.json({ ok: true, upToDate: true, version: latest ? latest.version : 0 });
    }

    res.json({
      ok: true,
      version: latest.version,
      note: latest.note || '',
      payload: latest.payload,
      ticket: updateTicket(latest),
    });
  } catch (err) {
    console.error('[update]', err);
    res.status(500).json({ error: 'server' });
  }
});

// ── dashboard ─────────────────────────────────────────────────────────────

app.get('/login', (req, res) => res.render('login', { error: null }));

app.get('/', requireRole(), (req, res) => {
  res.render('dashboard', { role: req.session.role });
});

app.post('/login', async (req, res) => {
  try {
    const { user, pass } = req.body || {};
    if (rateLimited(clientIp(req))) {
      return res.render('login', { error: 'Too many attempts, wait a minute.' });
    }
    const row = await db.one('SELECT * FROM users WHERE lower(username) = lower($1)', [user || '']);
    if (!row || row.disabled || !auth.verifyPassword(pass || '', row.pass_hash)) {
      return res.render('login', { error: 'Wrong user or password.' });
    }
    res.cookie('straw_session', signSession(row.id, row.role), {
      httpOnly: true, sameSite: 'lax', maxAge: 12 * 60 * 60 * 1000,
      secure: process.env.NODE_ENV === 'production',
    });
    res.redirect('/');
  } catch (err) {
    console.error('[dash login]', err);
    res.render('login', { error: 'Server error.' });
  }
});

app.post('/logout', (_req, res) => {
  res.clearCookie('straw_session');
  res.redirect('/login');
});

app.get('/api/admin/stats', requireRole('owner', 'admin', 'staff'), async (_req, res) => {
  const live = await db.one(
    `SELECT count(*)::int AS n FROM devices
      WHERE (now() - last_seen) < interval '${LIVE_WINDOW_SEC} seconds'`);
  const keys = await db.one('SELECT count(*)::int AS n FROM keys');
  const banned = await db.one('SELECT count(*)::int AS n FROM keys WHERE banned');
  const hwids = await db.one('SELECT count(DISTINCT hwid)::int AS n FROM devices');
  res.json({ live: live.n, keys: keys.n, banned: banned.n, hwids: hwids.n });
});

app.get('/api/admin/live', requireRole('owner', 'admin', 'staff'), async (_req, res) => {
  const rows = await db.query(`${DEVICE_SQL} ORDER BY d.last_seen DESC LIMIT 200`);
  res.json({ devices: rows.rows });
});

app.get('/api/admin/keys', requireRole('owner', 'admin', 'staff'), async (_req, res) => {
  const rows = await db.query(`
    SELECT k.*, (SELECT count(*) FROM devices d WHERE d.key_id = k.id)::int AS devices
      FROM keys k ORDER BY k.created_at DESC LIMIT 500`);
  res.json({ keys: rows.rows });
});

app.post('/api/admin/keys', requireRole('owner', 'admin', 'staff'), async (req, res) => {
  const days = Math.min(Math.max(Number(req.body?.days) || 30, 1), 3650);
  const count = Math.min(Math.max(Number(req.body?.count) || 1, 1), 50);
  const note = String(req.body?.note || '').slice(0, 120);

  const created = [];
  for (let i = 0; i < count; i++) {
    const { code } = auth.newKey(days);
    await db.query('INSERT INTO keys (code, days, note) VALUES ($1, $2, $3)', [code, days, note]);
    created.push(code);
  }
  res.json({ ok: true, keys: created });
});

app.post('/api/admin/keys/:id/ban', requireRole('owner', 'admin', 'staff'), async (req, res) => {
  const banned = req.body?.banned !== false;      // default: ban
  await db.query(
    `UPDATE keys SET banned = $1, ban_reason = $2, banned_at = CASE WHEN $1 THEN now() ELSE NULL END
      WHERE id = $3`,
    [banned, banned ? String(req.body?.reason || 'manual ban').slice(0, 120) : null,
     Number(req.params.id)]);
  res.json({ ok: true, banned });
});

// unban also unlocks the key from the machine it was locked to
app.post('/api/admin/keys/:id/reset', requireRole('owner', 'admin'), async (req, res) => {
  const id = Number(req.params.id);
  await db.query(
    `UPDATE keys SET banned = FALSE, ban_reason = NULL, banned_at = NULL,
            hwid = NULL, hw_info = NULL, first_ip = NULL, last_ip = NULL,
            first_seen = NULL, last_seen = NULL
      WHERE id = $1`, [id]);
  await db.query('DELETE FROM devices WHERE key_id = $1', [id]);
  res.json({ ok: true });
});

app.delete('/api/admin/keys/:id', requireRole('owner', 'admin', 'staff'), async (req, res) => {
  await db.query('DELETE FROM keys WHERE id = $1', [Number(req.params.id)]);
  res.json({ ok: true });
});

app.delete('/api/admin/devices/:id', requireRole('owner', 'admin'), async (req, res) => {
  await db.query('DELETE FROM devices WHERE id = $1', [Number(req.params.id)]);
  res.json({ ok: true });
});

// offset pushes
app.get('/api/admin/updates', requireRole('owner', 'admin', 'staff'), async (_req, res) => {
  const rows = await db.query(
    'SELECT id, version, sha, note, created_at, length(payload) AS size FROM updates ORDER BY version DESC LIMIT 50');
  res.json({ updates: rows.rows });
});

app.get('/api/admin/updates/:id', requireRole('owner', 'admin', 'staff'), async (req, res) => {
  const row = await db.one('SELECT * FROM updates WHERE id = $1', [Number(req.params.id)]);
  if (!row) return res.status(404).json({ error: 'not found' });
  res.json({ update: row });
});

app.post('/api/admin/updates', requireRole('owner', 'admin', 'staff'), async (req, res) => {
  let parsed;
  try {
    parsed = JSON.parse(String(req.body?.payload || ''));
  } catch {
    return res.status(400).json({ error: 'payload is not valid json' });
  }
  if (typeof parsed !== 'object' || Array.isArray(parsed)) {
    return res.status(400).json({ error: 'payload must be an object' });
  }

  const latest = await latestUpdate();
  const version = (latest ? latest.version : 0) + 1;
  parsed.version = version;

  const payload = JSON.stringify(parsed);
  const sha = crypto.createHash('sha256').update(payload).digest('hex');
  const note = String(req.body?.note || '').slice(0, 200);

  await db.query('INSERT INTO updates (version, payload, sha, note) VALUES ($1, $2, $3, $4)',
                 [version, payload, sha, note]);
  console.log(`[update] pushed v${version} (${payload.length} bytes)`);
  res.json({ ok: true, version, sha });
});

// dashboard accounts (the panel itself still needs a login)
app.get('/api/admin/users', requireRole('owner', 'admin', 'staff'), async (_req, res) => {
  const rows = await db.query('SELECT id, username, role, disabled, created_at FROM users ORDER BY id');
  res.json({ users: rows.rows });
});

app.post('/api/admin/users', requireRole('owner', 'admin'), async (req, res) => {
  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '');
  const role = ['owner', 'admin', 'staff'].includes(req.body?.role) ? req.body.role : 'staff';

  if (username.length < 3) return res.status(400).json({ error: 'username too short' });
  if (password.length < 6) return res.status(400).json({ error: 'password min 6 chars' });
  if (role === 'owner' && req.session.role !== 'owner') {
    return res.status(403).json({ error: 'only an owner may create owners' });
  }

  try {
    await db.query('INSERT INTO users (username, pass_hash, role) VALUES ($1, $2, $3)',
                   [username, auth.hashPassword(password), role]);
    res.json({ ok: true });
  } catch (err) {
    if (String(err).includes('duplicate')) return res.status(409).json({ error: 'exists' });
    throw err;
  }
});

app.post('/api/admin/users/:id/password', requireRole('owner', 'admin'), async (req, res) => {
  const password = String(req.body?.password || '');
  if (password.length < 6) return res.status(400).json({ error: 'password min 6 chars' });
  await db.query('UPDATE users SET pass_hash = $1 WHERE id = $2',
                 [auth.hashPassword(password), Number(req.params.id)]);
  res.json({ ok: true });
});

app.post('/api/admin/users/:id/role', requireRole('owner'), async (req, res) => {
  const role = req.body?.role;
  if (!['owner', 'admin', 'staff'].includes(role)) return res.status(400).json({ error: 'role' });
  await db.query('UPDATE users SET role = $1 WHERE id = $2', [role, Number(req.params.id)]);
  res.json({ ok: true });
});

app.delete('/api/admin/users/:id', requireRole('owner'), async (req, res) => {
  await db.query('DELETE FROM users WHERE id = $1 AND role <> $2', [Number(req.params.id), 'owner']);
  res.json({ ok: true });
});

// ── boot ──────────────────────────────────────────────────────────────────

async function bootstrap() {
  await db.migrate();
  auth.initSigning();

  const owner = await db.one(`SELECT id FROM users WHERE role = 'owner' LIMIT 1`);
  if (!owner) {
    const username = process.env.BOOTSTRAP_USER || 'admin';
    const password = process.env.BOOTSTRAP_PASS || crypto.randomBytes(9).toString('base64url');
    await db.query('INSERT INTO users (username, pass_hash, role) VALUES ($1, $2, $3)',
                   [username, auth.hashPassword(password), 'owner']);
    console.log('════════════════════════════════════════════════════');
    console.log(' bootstrap owner account (dashboard only)');
    console.log(`   user: ${username}`);
    console.log(`   pass: ${password}`);
    console.log('════════════════════════════════════════════════════');
  }

  app.listen(PORT, () => console.log(`[straw] listening on :${PORT}`));
}

bootstrap().catch((err) => {
  console.error('[boot]', err);
  process.exit(1);
});
