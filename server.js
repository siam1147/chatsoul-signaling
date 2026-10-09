'use strict';
/**
 * ChatSoul signaling + matchmaking server (Node.js, Socket.IO).
 *
 * Responsibilities
 *  - Authenticate sockets with short-lived HMAC tokens issued by PHP
 *  - Matchmaking: FIFO waiting queue, filters, block lists, one session per user
 *  - Relay WebRTC signaling (offer / answer / ICE) between the two matched peers ONLY
 *  - Relay text chat + media-state events between the pair
 *  - Report lifecycle to PHP/MySQL through an internal, secret-protected API
 *
 * Media (audio/video) NEVER passes through this server - it flows peer-to-peer
 * (or via your TURN server when a direct path is impossible).
 *
 * Configuration: environment variables (see README.md).
 */

const http = require('http');
const crypto = require('crypto');
const { Server } = require('socket.io');

// --------------------------------------------------------------------------
// Configuration
// --------------------------------------------------------------------------
const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '0.0.0.0';
const SIGNAL_SECRET = process.env.SIGNAL_SECRET || 'CHANGE_ME_signal_secret_32_chars_min';
const INTERNAL_SECRET = process.env.INTERNAL_SECRET || 'CHANGE_ME_internal_secret_32_chars';
const PHP_INTERNAL_URL = process.env.PHP_INTERNAL_URL || 'http://127.0.0.1/chatsoul/api/matching/internal.php';
// Hostnames allowed to open sockets (browser Origin header). Comma separated.
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'localhost,127.0.0.1').split(',').map((s) => s.trim()).filter(Boolean);
const NODE_ENV = process.env.NODE_ENV || 'development';

if (NODE_ENV === 'production' && (SIGNAL_SECRET.startsWith('CHANGE_ME') || INTERNAL_SECRET.startsWith('CHANGE_ME'))) {
  console.error('FATAL: set SIGNAL_SECRET and INTERNAL_SECRET before running in production.');
  process.exit(1);
}

const log = (...a) => console.log(new Date().toISOString(), ...a);
// TEMPORARY dev logging for WebRTC signaling (never logs SDP/ICE bodies or chat text).
// Disable with SIGNAL_DEBUG=0
const SIGNAL_DEBUG = process.env.SIGNAL_DEBUG !== '0';
const dbg = (...a) => { if (SIGNAL_DEBUG) log('[sig]', ...a); };
const qlog = (...a) => { if (SIGNAL_DEBUG) log('[queue]', ...a); };
const tag = (u) => (u ? `${u.name}#${u.uid}` : 'none');

// --------------------------------------------------------------------------
// State (in memory; single-process. See README for scaling notes.)
// --------------------------------------------------------------------------
/** uid -> user session */
const users = new Map();
/** matchId -> { id, a, b, startedAt } */
const matches = new Map();
/** FIFO waiting queue of uids */
let queue = [];
/** nonces already used (token replay protection) nonce -> expiry (ms) */
const usedNonces = new Map();

let settings = { store_messages: false, max_message_length: 500, prefer_filters: true, match_timeout_sec: 0 };

// --------------------------------------------------------------------------
// PHP internal API
// --------------------------------------------------------------------------
async function php(action, body = {}) {
  try {
    const res = await fetch(PHP_INTERNAL_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Internal-Secret': INTERNAL_SECRET },
      body: JSON.stringify({ action, ...body }),
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    return await res.json();
  } catch (err) {
    log('php call failed:', action, err.message);
    return null;
  }
}

async function refreshSettings() {
  const r = await php('settings');
  if (r && r.ok) {
    settings = {
      store_messages: !!r.store_messages,
      max_message_length: Math.min(1000, Math.max(50, r.max_message_length || 500)),
      prefer_filters: !!r.prefer_filters,
      match_timeout_sec: r.match_timeout_sec || 0,
    };
  }
}

// --------------------------------------------------------------------------
// Token verification
// --------------------------------------------------------------------------
function b64urlToBuf(s) {
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function verifyToken(token) {
  if (typeof token !== 'string' || token.length > 1024) return null;
  const [payload, sig] = token.split('.');
  if (!payload || !sig) return null;
  const expected = crypto.createHmac('sha256', SIGNAL_SECRET).update(payload).digest();
  const given = b64urlToBuf(sig);
  if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return null;
  let data;
  try { data = JSON.parse(b64urlToBuf(payload).toString('utf8')); } catch { return null; }
  if (!data || !data.uid || !data.exp || data.exp * 1000 < Date.now()) return null;
  if (usedNonces.has(data.n)) return null; // single-use
  usedNonces.set(data.n, data.exp * 1000 + 1000);
  return data;
}
setInterval(() => {
  const now = Date.now();
  for (const [n, exp] of usedNonces) if (exp < now) usedNonces.delete(n);
}, 60_000).unref();

// --------------------------------------------------------------------------
// Tiny per-user rate limiter (token bucket)
// --------------------------------------------------------------------------
function allow(user, key, max, perMs) {
  const now = Date.now();
  const b = (user.buckets[key] ||= { n: max, t: now });
  b.n = Math.min(max, b.n + ((now - b.t) / perMs) * max);
  b.t = now;
  if (b.n < 1) return false;
  b.n -= 1;
  return true;
}

// --------------------------------------------------------------------------
// HTTP server (health + internal admin endpoints) and Socket.IO
// --------------------------------------------------------------------------
function readBody(req) {
  return new Promise((resolve) => {
    let s = '';
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    req.on('data', (c) => { s += c; if (s.length > 10_000) { finish({}); req.destroy(); } });
    req.on('end', () => { try { finish(JSON.parse(s || '{}')); } catch { finish({}); } });
    req.on('close', () => finish({}));
    req.on('error', () => finish({}));
  });
}

function internalAuthorized(req) {
  const given = Buffer.from(String(req.headers['x-internal-secret'] || ''));
  const want = Buffer.from(INTERNAL_SECRET);
  return given.length === want.length && crypto.timingSafeEqual(given, want);
}

const httpServer = http.createServer((req, res) => {
  handleHttp(req, res).catch((err) => {
    log('http handler error:', err && err.message);
    try { if (!res.headersSent) { res.writeHead(500, { 'Content-Type': 'application/json' }); } res.end('{"ok":false}'); } catch { /* ignore */ }
  });
});

async function handleHttp(req, res) {
  const send = (code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };
  const path = (req.url || '').split('?')[0];

  if (path === '/health') return send(200, { ok: true, online: users.size });
  if (!path.startsWith('/internal/')) return send(404, { ok: false });
  if (!internalAuthorized(req)) return send(403, { ok: false });

  if (req.method === 'GET' && path === '/internal/stats') {
    return send(200, {
      ok: true,
      online: users.size,
      waiting: queue.length,
      active_chats: matches.size,
      matches: [...matches.values()].map((m) => ({
        id: m.id, a: m.a, b: m.b, a_name: users.get(m.a)?.name, b_name: users.get(m.b)?.name,
        since: new Date(m.startedAt).toISOString(),
      })),
    });
  }
  if (req.method === 'POST' && path === '/internal/end-match') {
    const b = await readBody(req);
    await endMatch(Number(b.match_id), b.reason || 'admin', Number(b.by) || null);
    return send(200, { ok: true });
  }
  if (req.method === 'POST' && path === '/internal/disconnect-user') {
    const b = await readBody(req);
    const u = users.get(Number(b.uid));
    if (u) {
      if (b.reason !== 'logout') u.socket.emit('banned', { reason: 'Your account has been restricted.' });
      dropUser(u, 'ban');
      u.socket.disconnect(true);
    }
    return send(200, { ok: true, found: !!u });
  }
  if (req.method === 'POST' && path === '/internal/reload-settings') {
    await refreshSettings();
    return send(200, { ok: true });
  }
  return send(404, { ok: false });
}

function originAllowed(origin) {
  if (!origin) return true; // non-browser clients (no Origin) - token still required
  try {
    const host = new URL(origin).hostname;
    return ALLOWED_ORIGINS.includes(host) || ALLOWED_ORIGINS.includes(origin);
  } catch { return false; }
}

const io = new Server(httpServer, {
  cors: { origin: (origin, cb) => cb(null, originAllowed(origin)), methods: ['GET', 'POST'] },
  maxHttpBufferSize: 20_000,
  pingInterval: 10_000,
  pingTimeout: 8_000,
  allowRequest: (req, cb) => cb(null, originAllowed(req.headers.origin)),
});

// --------------------------------------------------------------------------
// Auth middleware
// --------------------------------------------------------------------------
io.use(async (socket, next) => {
  const tok = verifyToken(socket.handshake.auth && socket.handshake.auth.token);
  if (!tok) return next(new Error('auth'));
  const chk = await php('user_check', { uid: tok.uid });
  if (!chk) return next(new Error('backend'));
  if (!chk.allowed) return next(new Error('banned'));
  socket.data.tok = tok;
  socket.data.blocked = new Set((chk.blocked || []).map(Number));
  next();
});

// --------------------------------------------------------------------------
// Matchmaking
// --------------------------------------------------------------------------
function publicProfile(u) {
  return { name: u.name, country: u.cc, language: u.lang };
}

function filtersOf(u) {
  // After match_timeout_sec the waiting user's own filters are relaxed (0 = never relax)
  const relaxed = settings.match_timeout_sec > 0 && u.joinedAt && Date.now() - u.joinedAt > settings.match_timeout_sec * 1000;
  if (!settings.prefer_filters || relaxed) return { country: '', language: '' };
  return { country: u.pref.country, language: u.pref.language };
}

/** Why a and b may NOT be matched (null = compatible). Same rules as before, now explainable in logs. */
function incompatReason(a, b) {
  if (a.uid === b.uid) return 'same user';                         // never match with yourself
  if (a.blocked.has(b.uid) || b.blocked.has(a.uid)) return 'block list'; // block lists (both directions)
  if (a.lastPartner === b.uid && queue.length > 2) return 'just matched before (queue>2)'; // avoid instantly re-pairing the same two
  const fa = filtersOf(a), fb = filtersOf(b);
  if (fa.country && fa.country !== b.cc) return `${a.name} wants country ${fa.country} but ${b.name} is ${b.cc}`;
  if (fa.language && fa.language !== b.lang) return `${a.name} wants language ${fa.language} but ${b.name} is ${b.lang}`;
  if (fb.country && fb.country !== a.cc) return `${b.name} wants country ${fb.country} but ${a.name} is ${a.cc}`;
  if (fb.language && fb.language !== a.lang) return `${b.name} wants language ${fb.language} but ${a.name} is ${a.lang}`;
  return null;
}
const compatible = (a, b) => incompatReason(a, b) === null;

function removeFromQueue(uid) {
  const i = queue.indexOf(uid);
  if (i !== -1) queue.splice(i, 1);
}

async function enqueue(u, pref) {
  if (u.state === 'connected') await endMatch(u.matchId, 'next', u.uid);
  if (u.state === 'matching') { dbg(`enqueue ignored: ${tag(u)} already matching`); return; }
  if (queue.includes(u.uid)) dbg(`enqueue: ${tag(u)} was ALREADY in queue (stale entry) - de-duplicating`);
  u.pref = pref;
  u.cancelRequested = false;
  u.state = 'waiting';
  u.joinedAt = Date.now();
  removeFromQueue(u.uid);
  queue.push(u.uid);
  qlog(`enqueue ${tag(u)} country=${pref.country || '-'} lang=${pref.language || '-'} | waiting=${queue.length} [${queue.map((x) => tag(users.get(x))).join(', ')}] online=${users.size}`);
  u.socket.emit('searching', { online: users.size, waiting: queue.length });
  php('queue_join', { uid: u.uid, country: pref.country, language: pref.language });
  tryMatch(u);
}

async function tryMatch(me) {
  if (me.state !== 'waiting') return;
  // explain (at most every 10s per user) why nobody was matched, so a silent "Searching..." can be diagnosed
  const explain = !me.lastExplain || Date.now() - me.lastExplain > 10_000;
  if (explain) me.lastExplain = Date.now();
  for (const uid of queue) {
    const other = users.get(uid);
    if (uid !== me.uid && explain) {
      const why = !other ? 'no live session (stale queue entry)' : other.state !== 'waiting' ? `state=${other.state}` : incompatReason(me, other);
      qlog(`tryMatch ${tag(me)} vs ${tag(other) === 'none' ? '#' + uid : tag(other)}: ${why ? 'SKIP - ' + why : 'compatible'}`);
    }
    if (!other || other.state !== 'waiting' || !compatible(me, other)) continue;
    // lock both synchronously so concurrent tryMatch calls cannot grab them
    removeFromQueue(me.uid); removeFromQueue(other.uid);
    me.state = 'matching'; other.state = 'matching';
    qlog(`match_start requested for ${tag(other)} + ${tag(me)}`);
    const r = await php('match_start', { a: other.uid, b: me.uid });
    qlog(`match_start result: ${r ? JSON.stringify({ ok: r.ok, match_id: r.match_id, error: r.error }) : 'NO RESPONSE (PHP call failed - see "php call failed" line above)'}`);
    // Either side may have left during the await
    const alive = (x) => users.get(x.uid) === x && x.socket.connected;
    if (r && r.ok && !(Number(r.match_id) > 0)) { dbg(`match_start returned invalid match_id=${r.match_id} - treating as failure`); r.ok = false; }
    if (!r || !r.ok || !alive(me) || !alive(other) || me.cancelRequested || other.cancelRequested) {
      if (r && r.ok) php('match_end', { match_id: r.match_id, reason: 'aborted' });
      for (const x of [me, other]) {
        if (alive(x) && x.cancelRequested) {
          // user cancelled / left while the match was being created: do not re-queue them
          x.cancelRequested = false; x.state = 'idle';
          php('queue_leave', { uid: x.uid });
        } else if (alive(x)) { x.state = 'waiting'; x.joinedAt = Date.now(); queue.unshift(x.uid); x.socket.emit('searching', { online: users.size, waiting: queue.length }); }
        else if (users.get(x.uid) === x) dropUser(x, 'disconnect');
      }
      if (!r) await new Promise((res) => setTimeout(res, 1000));
      return;
    }
    if (matches.has(r.match_id)) dbg(`WARNING duplicate matchId ${r.match_id} already active (${tag(users.get(matches.get(r.match_id).a))} <-> ${tag(users.get(matches.get(r.match_id).b))}) - overwriting`);
    const m = { id: r.match_id, a: other.uid, b: me.uid, startedAt: Date.now() };
    matches.set(m.id, m);
    other.state = me.state = 'connected';
    other.matchId = me.matchId = m.id;
    other.partner = me.uid; me.partner = other.uid;
    // `other` waited longer, `me` just arrived: `me` is the caller (creates the offer)
    me.socket.emit('matched', { matchId: m.id, role: 'caller', partner: publicProfile(other) });
    other.socket.emit('matched', { matchId: m.id, role: 'callee', partner: publicProfile(me) });
    log(`match #${m.id}: ${other.name} <-> ${me.name}`);
    dbg(`match #${m.id} roles: caller=${tag(me)} callee=${tag(other)} active_matches=${matches.size} queue=${queue.length}`);
    return;
  }
}

/** End a match; notify the other side. `by` = uid that initiated (may be null). */
async function endMatch(matchId, reason, by) {
  const m = matches.get(matchId);
  if (!m) { dbg(`endMatch: matchId=${matchId} not found (reason=${reason})`); return; }
  matches.delete(matchId);
  dbg(`match #${matchId} ended reason=${reason} by=${by} (${tag(users.get(m.a))} <-> ${tag(users.get(m.b))}) duration=${Math.round((Date.now() - m.startedAt) / 1000)}s`);
  // A block takes effect immediately for the live session (the DB list is only read at connect)
  if (reason === 'block') {
    users.get(m.a)?.blocked.add(m.b);
    users.get(m.b)?.blocked.add(m.a);
  }
  for (const uid of [m.a, m.b]) {
    const u = users.get(uid);
    if (!u) continue;
    u.state = 'idle'; u.matchId = null; u.partner = null; u.lastPartner = uid === m.a ? m.b : m.a;
    if (uid !== by) u.socket.emit('partner-left', { reason: reason === 'block' ? 'next' : reason });
    else u.socket.emit('match-ended', { reason });
  }
  php('match_end', { match_id: matchId, reason });
}

/** Remove a user from queue / matches (does not close the socket). */
function dropUser(u, reason) {
  removeFromQueue(u.uid);
  if (u.state === 'waiting') php('queue_leave', { uid: u.uid });
  if (u.matchId != null) {
    if (reason === 'disconnect' || reason === 'replaced') dbg(`socket ${reason} during match #${u.matchId}: ${tag(u)} partner=${u.partner}`);
    endMatch(u.matchId, reason, u.uid);
  }
  if (users.get(u.uid) === u) users.delete(u.uid);
}

// --------------------------------------------------------------------------
// Socket events
// --------------------------------------------------------------------------
/** Wrap a socket handler so a thrown error can never crash the whole process. */
const safe = (fn) => async (...args) => {
  try { await fn(...args); } catch (err) { log('handler error:', err && err.stack ? err.stack : err); }
};

io.on('connection', (socket) => {
  const t = socket.data.tok;

  // Prevent duplicate active sessions: newest connection wins
  const old = users.get(t.uid);
  if (old) {
    old.socket.emit('session-replaced');
    dropUser(old, 'replaced');
    old.socket.disconnect(true);
  }

  const u = {
    uid: Number(t.uid), name: String(t.name).slice(0, 32), cc: String(t.cc || 'XX'), lang: String(t.lang || 'en'),
    socket, blocked: socket.data.blocked, state: 'idle', matchId: null, partner: null, lastPartner: null,
    pref: { country: '', language: '' }, joinedAt: 0, buckets: {},
  };
  users.set(u.uid, u);
  socket.emit('ready', { online: users.size });
  log(`+ ${u.name} (${users.size} online)`);
  dbg(`connect ${tag(u)} socket=${socket.id}${old ? ' (replaced older session)' : ''}`);

  socket.on('find', safe(async (p) => {
    qlog(`'find' received from ${tag(u)} socket=${socket.id} state=${u.state}`);
    if (!allow(u, 'find', 10, 10_000)) { qlog(`rate-limited ${tag(u)}`); return socket.emit('rate-limited'); }
    const pref = {
      country: typeof p?.country === 'string' && /^[A-Z]{2}$/.test(p.country) && p.country !== 'XX' ? p.country : '',
      language: typeof p?.language === 'string' && /^[a-z]{2,3}$/.test(p.language) ? p.language : '',
    };
    await enqueue(u, pref);
  }));

  socket.on('cancel', safe(() => {
    qlog(`'cancel' received from ${tag(u)} state=${u.state}`);
    if (u.state === 'waiting') { removeFromQueue(u.uid); u.state = 'idle'; php('queue_leave', { uid: u.uid }); }
    else if (u.state === 'matching') u.cancelRequested = true; // honoured when match_start returns
    socket.emit('cancelled');
  }));

  // WebRTC signaling relay: only to the matched partner, only valid kinds
  socket.on('signal', safe((msg) => {
    const kind = msg && msg.kind;
    if (u.state !== 'connected') return dbg(`signal REJECTED (not connected, state=${u.state}) kind=${kind} from=${tag(u)} matchId=${msg && msg.matchId}`);
    if (!allow(u, 'signal', 200, 10_000)) return dbg(`signal REJECTED (rate limit) from=${tag(u)}`);
    if (!msg || !['offer', 'answer', 'ice'].includes(kind)) return dbg(`signal REJECTED (invalid kind=${kind}) from=${tag(u)}`);
    if (msg.matchId !== u.matchId) return dbg(`signal REJECTED (stale matchId: got=${msg.matchId} expected=${u.matchId}) kind=${kind} from=${tag(u)}`);
    const peer = users.get(u.partner);
    if (!peer) return dbg(`signal FAILED (partner missing: partner uid=${u.partner}) kind=${kind} from=${tag(u)} matchId=${u.matchId}`);
    if (!peer.socket.connected) return dbg(`signal FAILED (partner socket disconnected) kind=${kind} from=${tag(u)} to=${tag(peer)} matchId=${u.matchId}`);
    if (peer.matchId !== u.matchId) return dbg(`signal FAILED (partner matchId mismatch: ${peer.matchId} vs ${u.matchId}) kind=${kind} from=${tag(u)} to=${tag(peer)}`);
    peer.socket.emit('signal', { kind, data: msg.data, matchId: u.matchId });
    // ICE is noisy: count it, log offer/answer individually
    if (kind === 'ice') { u.iceRelayed = (u.iceRelayed || 0) + 1; if (u.iceRelayed === 1 || u.iceRelayed % 10 === 0) dbg(`signal relayed kind=ice #${u.iceRelayed} from=${tag(u)} to=${tag(peer)} matchId=${u.matchId}`); }
    else { dbg(`signal relayed kind=${kind} from=${tag(u)} to=${tag(peer)} matchId=${u.matchId}`); if (kind === 'offer') { u.iceRelayed = 0; } }
  }));

  socket.on('chat', safe((text) => {
    if (u.state !== 'connected') return;
    if (!allow(u, 'chat', 8, 10_000)) return socket.emit('rate-limited');
    if (typeof text !== 'string') return;
    const body = text.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '').trim().slice(0, settings.max_message_length);
    if (!body) return;
    const peer = users.get(u.partner);
    if (!peer) return;
    peer.socket.emit('chat', { text: body, ts: Date.now() });
    socket.emit('chat-ack', { ts: Date.now() });
    php('message', { match_id: u.matchId, sender: u.uid, body });
  }));

  socket.on('typing', safe(() => {
    if (u.state !== 'connected' || !allow(u, 'typing', 5, 5_000)) return;
    users.get(u.partner)?.socket.emit('typing');
  }));

  socket.on('media-state', safe((s) => {
    if (u.state !== 'connected' || !allow(u, 'media', 20, 10_000)) return;
    users.get(u.partner)?.socket.emit('media-state', { cam: !!s?.cam, mic: !!s?.mic });
  }));

  socket.on('next', safe(async (p) => {
    qlog(`'next' received from ${tag(u)} socket=${socket.id} state=${u.state}`);
    if (!allow(u, 'find', 10, 10_000)) return socket.emit('rate-limited');
    const pref = p && typeof p === 'object' ? {
      // '' (Worldwide / Any language) MUST clear the restriction. It used to fall back to the OLD saved filter,
      // so "Worldwide" after choosing a country kept restricting matches to that country.
      country: typeof p.country === 'string' ? (/^[A-Z]{2}$/.test(p.country) && p.country !== 'XX' ? p.country : '') : u.pref.country,
      language: typeof p.language === 'string' ? (/^[a-z]{2,3}$/.test(p.language) ? p.language : '') : u.pref.language,
    } : u.pref;
    await enqueue(u, pref);
  }));

  socket.on('leave', safe(async () => {
    qlog(`'leave' received from ${tag(u)} state=${u.state}`);
    if (u.state === 'connected') await endMatch(u.matchId, 'hangup', u.uid);
    else if (u.state === 'matching') { u.cancelRequested = true; socket.emit('cancelled'); }
    else if (u.state === 'waiting') { removeFromQueue(u.uid); u.state = 'idle'; php('queue_leave', { uid: u.uid }); socket.emit('cancelled'); }
  }));

  socket.on('disconnect', safe((why) => {
    dbg(`disconnect ${tag(u)} socket=${socket.id} why=${why} state=${u.state} matchId=${u.matchId} current=${users.get(u.uid) === u}`);
    if (users.get(u.uid) === u) {
      dropUser(u, 'disconnect');
      log(`- ${u.name} (${users.size} online)`);
    }
  }));
});

// Relax filters for long waiters and retry matching periodically
setInterval(() => {
  for (const uid of [...queue]) {
    const u = users.get(uid);
    if (u && u.state === 'waiting') tryMatch(u);
  }
}, 2_000).unref();

// Report peak online users every minute; refresh settings every 2 minutes
setInterval(() => php('peak', { online: users.size }), 60_000).unref();
setInterval(refreshSettings, 120_000).unref();

// --------------------------------------------------------------------------
// Boot
// --------------------------------------------------------------------------
(async () => {
  await php('reset');
  await refreshSettings();
  httpServer.listen(PORT, HOST, () => {
    log(`ChatSoul signaling listening on ${HOST}:${PORT} (${NODE_ENV})`);
    log(`PHP internal API: ${PHP_INTERNAL_URL}`);
  });
})();

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, async () => {
    log('shutting down...');
    io.close();
    await php('reset');
    process.exit(0);
  });
}

// --------------------------------------------------------------------------
// Process-level crash protection: log and keep serving instead of dying
// --------------------------------------------------------------------------
process.on('uncaughtException', (err) => log('uncaughtException:', err && err.stack ? err.stack : err));
process.on('unhandledRejection', (err) => log('unhandledRejection:', err && err.stack ? err.stack : err));

// Housekeeping: drop dead entries from the queue (stale / disconnected users)
setInterval(() => {
  queue = queue.filter((uid) => {
    const u = users.get(uid);
    return u && u.state === 'waiting' && u.socket.connected;
  });
}, 15_000).unref();
