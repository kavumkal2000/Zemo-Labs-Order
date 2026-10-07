// Zemo Labs Order Desk — standalone web server with logins and roles.
// Run locally:  node server.js            → http://localhost:8080
// Hosted:       set DATA_DIR to a persistent disk path (see README). HTTPS is handled by the host.
// No npm dependencies.
'use strict';
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');

const PORT = process.env.PORT || 8080;
const DATA_DIR = process.env.DATA_DIR || __dirname;
const DATA = path.join(DATA_DIR, 'data.json'), USERS = path.join(DATA_DIR, 'users.json'), SECRET_FILE = path.join(DATA_DIR, 'secret.key'), BACKUPS = path.join(DATA_DIR, 'backups');
const COLS = ['settings', 'products', 'clients', 'orders', 'purchases', 'priceHistory', 'payouts', 'closes'];
const OWNER_ONLY = new Set(['settings', 'products', 'priceHistory', 'payouts', 'closes']);
const SESSION_DAYS = 30;

fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(DATA) && fs.existsSync(path.join(__dirname, 'data.json'))) fs.copyFileSync(path.join(__dirname, 'data.json'), DATA); // first boot: seed from the package
let db = fs.existsSync(DATA) ? JSON.parse(fs.readFileSync(DATA, 'utf8')) : {}; for (const c of COLS) db[c] = db[c] || [];
let users = fs.existsSync(USERS) ? JSON.parse(fs.readFileSync(USERS, 'utf8')) : [];
const SECRET = fs.existsSync(SECRET_FILE) ? fs.readFileSync(SECRET_FILE, 'utf8') : (() => { const s = crypto.randomBytes(32).toString('hex'); fs.writeFileSync(SECRET_FILE, s); return s; })();

let saveT; const save = () => { clearTimeout(saveT); saveT = setTimeout(() => { fs.writeFileSync(DATA + '.tmp', JSON.stringify(db, null, 1)); fs.renameSync(DATA + '.tmp', DATA); }, 150); };
const saveUsers = () => fs.writeFileSync(USERS, JSON.stringify(users, null, 1));
function backup() { try { fs.mkdirSync(BACKUPS, { recursive: true }); const f = path.join(BACKUPS, 'data-' + new Date().toISOString().slice(0, 10) + '.json'); if (!fs.existsSync(f) && fs.existsSync(DATA)) fs.copyFileSync(DATA, f); const old = fs.readdirSync(BACKUPS).sort().slice(0, -60); old.forEach(x => fs.unlinkSync(path.join(BACKUPS, x))); } catch (e) {} }
backup(); setInterval(backup, 6 * 3600 * 1000);

// ---- auth helpers ----
const hash = (pw, salt) => { salt = salt || crypto.randomBytes(16).toString('hex'); return salt + ':' + crypto.scryptSync(pw, salt, 64).toString('hex'); };
const verify = (pw, stored) => { const [salt] = stored.split(':'); return crypto.timingSafeEqual(Buffer.from(hash(pw, salt)), Buffer.from(stored)); };
const sign = s => crypto.createHmac('sha256', SECRET).update(s).digest('base64url');
function makeToken(u) { const body = Buffer.from(JSON.stringify({ u: u.username, exp: Date.now() + SESSION_DAYS * 864e5 })).toString('base64url'); return body + '.' + sign(body); }
function readToken(t) { if (!t) return null; const [body, sig] = t.split('.'); if (!body || !sig || sign(body) !== sig) return null; try { const d = JSON.parse(Buffer.from(body, 'base64url')); if (d.exp < Date.now()) return null; return users.find(x => x.username === d.u) || null; } catch (e) { return null; } }
const cookies = req => Object.fromEntries((req.headers.cookie || '').split(';').map(c => c.trim().split('=')).filter(x => x[0]).map(([k, ...v]) => [k, decodeURIComponent(v.join('='))]));
const attempts = {}; function tooMany(ip) { const a = attempts[ip] || { n: 0, t: 0 }; if (Date.now() - a.t > 15 * 60e3) a.n = 0; return a.n >= 10; }
function failed(ip) { const a = attempts[ip] || { n: 0, t: 0 }; a.n++; a.t = Date.now(); attempts[ip] = a; }

// ---- responses ----
const json = (res, code, body) => { res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(body === undefined ? '' : JSON.stringify(body)); };
const html = (res, code, body, extra) => { res.writeHead(code, Object.assign({ 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }, extra || {})); res.end(body); };
const redirect = (res, to, extra) => { res.writeHead(302, Object.assign({ Location: to }, extra || {})); res.end(); };
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const body = req => new Promise(r => { let b = ''; req.on('data', c => { b += c; if (b.length > 2e6) req.destroy(); }); req.on('end', () => r(b)); });
const form = s => Object.fromEntries(new URLSearchParams(s));
const secure = req => (req.headers['x-forwarded-proto'] || '').includes('https');
const cookie = (req, v, maxAge) => `zemo_session=${v}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure(req) ? '; Secure' : ''}`;

const PAGE = (title, inner) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} · Zemo Labs Order Desk</title>
<style>body{font:15px/1.5 system-ui,sans-serif;background:#f3f5f7;color:#15202b;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center;padding:16px}
.card{background:#fff;border:1px solid #d3dae1;border-radius:12px;padding:28px;width:100%;max-width:420px}h1{font-size:1.2rem;margin:0 0 4px}.sub{color:#5b6b7a;font-size:.9rem;margin-bottom:18px}
label{display:block;font-size:.8rem;color:#5b6b7a;font-weight:600;margin:12px 0 4px}input,select{width:100%;box-sizing:border-box;padding:9px 10px;border:1px solid #d3dae1;border-radius:8px;font:inherit}
button{margin-top:18px;width:100%;padding:10px;border:0;border-radius:8px;background:#0f6b6e;color:#fff;font-weight:600;font-size:1rem;cursor:pointer}.err{background:#f9dedb;color:#b3261e;padding:8px 10px;border-radius:8px;margin-top:12px;font-size:.9rem}
table{border-collapse:collapse;width:100%;font-size:.9rem;margin-top:12px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #d3dae1}a{color:#0f6b6e}.row{display:flex;gap:8px}.row button{margin:0}.wide{max-width:760px}
@media(prefers-color-scheme:dark){body{background:#0f1519;color:#e6ecf0}.card{background:#171f26;border-color:#2b3842}input,select{background:#121a20;color:#e6ecf0;border-color:#2b3842}th,td{border-color:#2b3842}.sub,label{color:#93a3b1}}</style></head><body>${inner}</body></html>`;

const loginPage = (err, next) => PAGE('Sign in', `<form class="card" method="post" action="/login"><h1>Zemo Labs Order Desk</h1><div class="sub">Sign in to continue</div>
<label>Username</label><input name="username" autocomplete="username" required autofocus><label>Password</label><input name="password" type="password" autocomplete="current-password" required>
<input type="hidden" name="next" value="${esc(next || '/')}">${err ? `<div class="err">${esc(err)}</div>` : ''}<button>Sign in</button></form>`);
const setupPage = err => PAGE('Set up', `<form class="card" method="post" action="/setup"><h1>Welcome — create the owner account</h1><div class="sub">This runs once. The owner can change prices, settings and manage users.</div>
<label>Your name</label><input name="name" required value="Jeff"><label>Username</label><input name="username" required autocomplete="username" value="jeff"><label>Password (12+ characters)</label><input name="password" type="password" minlength="12" required autocomplete="new-password">
${err ? `<div class="err">${esc(err)}</div>` : ''}<button>Create owner account</button></form>`);
function usersPage(me, err) {
  const reps = (db.settings[0] && db.settings[0].reps || []).map(r => r.name);
  return PAGE('Users', `<div class="card wide"><h1>Users</h1><div class="sub">Signed in as ${esc(me.name)} · <a href="/">Back to Order Desk</a> · <a href="/logout">Sign out</a></div>
<table><thead><tr><th>Name</th><th>Username</th><th>Role</th><th>Rep</th><th></th></tr></thead><tbody>${users.map(u => `<tr><td>${esc(u.name)}</td><td>${esc(u.username)}</td><td>${esc(u.role)}</td><td>${esc(u.rep || '')}</td><td>${u.username === me.username ? '' : `<form method="post" action="/users/delete" style="display:inline"><input type="hidden" name="username" value="${esc(u.username)}"><button style="background:#b3261e;padding:4px 10px;font-size:.8rem">Remove</button></form>`}</td></tr>`).join('')}</tbody></table>
<form method="post" action="/users/add"><h1 style="margin-top:24px;font-size:1rem">Add a user</h1><label>Name</label><input name="name" required><label>Username</label><input name="username" required pattern="[a-z0-9._-]+" title="lower-case letters, numbers, . _ -"><label>Password (12+ characters)</label><input name="password" type="password" minlength="12" required>
<label>Role</label><select name="role"><option value="staff">Staff — enters orders, purchases, inventory counts, clients (no pricing/settings)</option><option value="owner">Owner — everything</option><option value="rep">Sales rep — sees only their own statement</option></select>
<label>Rep name (for the Sales rep role)</label><select name="rep"><option value="">—</option>${reps.map(r => `<option>${esc(r)}</option>`).join('')}</select>${err ? `<div class="err">${esc(err)}</div>` : ''}<button>Add user</button></form>
<form method="post" action="/users/password"><h1 style="margin-top:24px;font-size:1rem">Change my password</h1><label>New password (12+ characters)</label><input name="password" type="password" minlength="12" required><button>Change password</button></form></div>`);
}

// ---- data views per role ----
function viewFor(user, col, docs) {
  if (user.role !== 'rep') return docs;
  if (col === 'orders') return docs.filter(o => o.rep === user.rep);
  if (col === 'settings') return docs.map(s => Object.assign({}, s, { reps: (s.reps || []).filter(r => r.name === user.rep), shipping: [], paymentMethods: [] }));
  if (col === 'products') return docs.map(p => ({ id: p.id, name: p.name, order: p.order }));
  if (col === 'payouts') return docs.filter(p => p.rep === user.rep);
  if (col === 'closes') return docs.map(c => ({ id: c.id, closedAt: c.closedAt, snapshot: { month: c.snapshot.month, pnl: {}, reps: Object.fromEntries(Object.entries(c.snapshot.reps || {}).filter(([n]) => n === user.rep)), repOrders: Object.fromEntries(Object.entries(c.snapshot.repOrders || {}).filter(([n]) => n === user.rep)), inv: [], invTotal: 0, recv: [], recvTotal: 0, purchases: 0 } }));
  return [];
}
function canWrite(user, col) { if (user.role === 'owner') return true; if (user.role === 'rep') return false; return !OWNER_ONLY.has(col); }

http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x'); const p = url.pathname; const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  const me = readToken(cookies(req).zemo_session);
  if (!users.length) { // first run
    if (p === '/setup' && req.method === 'POST') { const f = form(await body(req)); if (!f.username || (f.password || '').length < 12) return html(res, 400, setupPage('Password must be at least 12 characters.')); users.push({ name: f.name || f.username, username: f.username.trim().toLowerCase(), role: 'owner', hash: hash(f.password) }); saveUsers(); return redirect(res, '/', { 'Set-Cookie': cookie(req, makeToken(users[0]), SESSION_DAYS * 86400) }); }
    return html(res, 200, setupPage());
  }
  if (p === '/login') { if (req.method === 'POST') { if (tooMany(ip)) return html(res, 429, loginPage('Too many attempts. Try again in 15 minutes.')); const f = form(await body(req)); const u = users.find(x => x.username === (f.username || '').trim().toLowerCase()); if (!u || !verify(f.password || '', u.hash)) { failed(ip); return html(res, 401, loginPage('Wrong username or password.', f.next)); } return redirect(res, (f.next || '/').startsWith('/') ? f.next || '/' : '/', { 'Set-Cookie': cookie(req, makeToken(u), SESSION_DAYS * 86400) }); } return html(res, 200, loginPage('', url.searchParams.get('next'))); }
  if (p === '/logout') return redirect(res, '/login', { 'Set-Cookie': cookie(req, '', 0) });
  if (p === '/healthz') return json(res, 200, { ok: true });
  if (!me) { if (p.startsWith('/api/')) return json(res, 401, { error: 'sign in' }); return redirect(res, '/login?next=' + encodeURIComponent(p)); }

  if (p === '/users' || p.startsWith('/users/')) {
    if (p === '/users/password' && req.method === 'POST') { const f = form(await body(req)); if ((f.password || '').length < 12) return html(res, 400, usersPage(me, 'Password must be at least 12 characters.')); me.hash = hash(f.password); saveUsers(); return redirect(res, '/users'); }
    if (me.role !== 'owner') return html(res, 403, PAGE('Not allowed', '<div class="card"><h1>Owner only</h1><a href="/">Back</a></div>'));
    if (p === '/users/add' && req.method === 'POST') { const f = form(await body(req)); const un = (f.username || '').trim().toLowerCase(); if (!/^[a-z0-9._-]+$/.test(un)) return html(res, 400, usersPage(me, 'Bad username.')); if (users.find(x => x.username === un)) return html(res, 400, usersPage(me, 'That username exists.')); if ((f.password || '').length < 12) return html(res, 400, usersPage(me, 'Password must be at least 12 characters.')); if (f.role === 'rep' && !f.rep) return html(res, 400, usersPage(me, 'Pick the rep name for a Sales rep account.')); users.push({ name: f.name || un, username: un, role: ['owner', 'staff', 'rep'].includes(f.role) ? f.role : 'staff', rep: f.role === 'rep' ? f.rep : undefined, hash: hash(f.password) }); saveUsers(); return redirect(res, '/users'); }
    if (p === '/users/delete' && req.method === 'POST') { const f = form(await body(req)); if (f.username !== me.username) { users = users.filter(x => x.username !== f.username); saveUsers(); } return redirect(res, '/users'); }
    return html(res, 200, usersPage(me));
  }

  if (p.startsWith('/api/')) {
    const parts = p.split('/').filter(Boolean); const col = parts[1], id = parts[2];
    if (col === 'ping') return json(res, 200, { ok: true });
    if (col === 'me') return json(res, 200, { name: me.name, username: me.username, role: me.role, rep: me.rep || null, canWriteSettings: me.role === 'owner' });
    if (!COLS.includes(col)) return json(res, 404, { error: 'unknown collection' });
    if (req.method === 'GET') return json(res, 200, viewFor(me, col, db[col]));
    if (!canWrite(me, col)) return json(res, 403, { error: 'not allowed for your role' });
    if (!id) return json(res, 400, { error: 'id required' });
    const b = await body(req); const i = db[col].findIndex(d => d.id === id);
    if (req.method === 'DELETE') { if (i >= 0) db[col].splice(i, 1); save(); return json(res, 204); }
    if (req.method === 'PUT') { let d; try { d = JSON.parse(b || '{}'); } catch (e) { return json(res, 400, { error: 'bad json' }); } if (typeof d !== 'object' || Array.isArray(d)) return json(res, 400, { error: 'bad doc' }); d.id = id; d._by = me.username; d._at = new Date().toISOString(); if (i >= 0) db[col][i] = d; else db[col].push(d); save(); return json(res, 200, d); }
    return json(res, 405, { error: 'method not allowed' });
  }
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
  fs.createReadStream(path.join(__dirname, 'index.html')).pipe(res);
}).listen(PORT, () => console.log(`Zemo Order Desk on http://localhost:${PORT}   data: ${DATA_DIR}`));
