// Zemo Order Desk — standalone web server with logins and roles.
// Run locally:  node server.js            → http://localhost:8080
// Hosted:       set DATA_DIR to a persistent disk path (see README). HTTPS is handled by the host.
// No npm dependencies.
'use strict';
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');

const PORT = process.env.PORT || 8080;
const DATA_DIR = process.env.DATA_DIR || __dirname;
const DATA = path.join(DATA_DIR, 'data.json'), USERS = path.join(DATA_DIR, 'users.json'), SECRET_FILE = path.join(DATA_DIR, 'secret.key'), BACKUPS = path.join(DATA_DIR, 'backups');
const COLS = ['settings', 'products', 'clients', 'orders', 'purchases', 'priceHistory', 'payouts', 'closes', 'requests'];
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

const PAGE = (title, inner) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} · Zemo Order Desk</title><link rel="icon" href="/favicon.png">
<style>body{font:15px/1.5 system-ui,sans-serif;background:#f3f5f7;color:#15202b;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center;padding:16px}
.card{background:#fff;border:1px solid #d3dae1;border-radius:12px;padding:28px;width:100%;max-width:420px}h1{font-size:1.2rem;margin:0 0 4px}.sub{color:#5b6b7a;font-size:.9rem;margin-bottom:18px}
label{display:block;font-size:.8rem;color:#5b6b7a;font-weight:600;margin:12px 0 4px}input,select{width:100%;box-sizing:border-box;padding:9px 10px;border:1px solid #d3dae1;border-radius:8px;font:inherit}
button{margin-top:18px;width:100%;padding:10px;border:0;border-radius:8px;background:#0f6b6e;color:#fff;font-weight:600;font-size:1rem;cursor:pointer}.err{background:#f9dedb;color:#b3261e;padding:8px 10px;border-radius:8px;margin-top:12px;font-size:.9rem}
table{border-collapse:collapse;width:100%;font-size:.9rem;margin-top:12px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #d3dae1}a{color:#0f6b6e}.row{display:flex;gap:8px}.row button{margin:0}.wide{max-width:760px}
@media(prefers-color-scheme:dark){body{background:#0f1519;color:#e6ecf0}.card{background:#171f26;border-color:#2b3842}input,select{background:#121a20;color:#e6ecf0;border-color:#2b3842}th,td{border-color:#2b3842}.sub,label{color:#93a3b1}}</style></head><body>${inner}</body></html>`;

const orderPage = () => { const co = Object.assign({ name: 'Zemo' }, (db.settings[0] || {}).company || {}); return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Order · Zemo</title><link rel="icon" href="/favicon.png">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wght@500;600;700&family=Source+Sans+3:wght@400;600&family=JetBrains+Mono:wght@400;600&display=swap">
<style>:root{--bg:#f3f5f7;--surface:#fff;--line:#d3dae1;--fg:#15202b;--muted:#5b6b7a;--accent:#0f6b6e;--accent-fg:#fff;--soft:#d9eeee;--bad:#b3261e;--bad-soft:#f9dedb;--good:#1f7a3d;--good-soft:#dcf1e2}
@media(prefers-color-scheme:dark){:root{--bg:#0f1519;--surface:#171f26;--line:#2b3842;--fg:#e6ecf0;--muted:#93a3b1;--accent:#4fb3b4;--accent-fg:#06282a;--soft:#143a3b;--bad:#f08a82;--bad-soft:#3e1a17;--good:#5fcf82;--good-soft:#15331f}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 "Source Sans 3",system-ui,sans-serif}h1,h2,h3{font-family:Archivo,system-ui,sans-serif;margin:0;letter-spacing:-.01em}
.wrap{max-width:960px;margin:0 auto;padding:24px 16px 60px}.top{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap;margin-bottom:6px}.top h1{font-size:1.5rem}.sub{color:var(--muted)}
.ruo{background:var(--soft);color:var(--accent);border-radius:10px;padding:10px 14px;font-weight:600;margin:14px 0 18px;font-size:.9rem}
.grid{display:grid;gap:16px;grid-template-columns:1fr 340px}@media(max-width:820px){.grid{grid-template-columns:1fr}}
.card{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:16px;min-width:0}
label{display:block;font-size:.78rem;color:var(--muted);font-weight:600;margin:10px 0 4px}input,select,textarea{width:100%;padding:8px 10px;border:1px solid var(--line);border-radius:8px;font:inherit;background:var(--surface);color:var(--fg)}
.search{margin-bottom:8px}.plist{max-height:420px;overflow:auto;border:1px solid var(--line);border-radius:10px}.prow{display:flex;align-items:center;gap:10px;padding:8px 10px;border-bottom:1px solid var(--line)}.prow:last-child{border-bottom:0}.prow .n{flex:1;min-width:0}.prow .pr{font-family:"JetBrains Mono",monospace;color:var(--muted);font-size:.85rem}.prow input{width:64px;text-align:right}
.cart td{padding:6px 4px;border-bottom:1px solid var(--line);font-size:.92rem}.cart .r{text-align:right;font-family:"JetBrains Mono",monospace}.tot{display:flex;justify-content:space-between;padding:4px 0;font-size:.95rem}.tot b{font-family:"JetBrains Mono",monospace}
button{padding:11px 16px;border:0;border-radius:9px;background:var(--accent);color:var(--accent-fg);font-weight:700;font-size:1rem;cursor:pointer;width:100%;margin-top:12px}button:disabled{opacity:.5}
.note{font-size:.8rem;color:var(--muted)}.err{background:var(--bad-soft);color:var(--bad);padding:8px 10px;border-radius:8px;margin-top:10px;font-size:.9rem}.ok{background:var(--good-soft);color:var(--good);padding:14px;border-radius:10px;font-weight:600}
.two{display:grid;gap:10px;grid-template-columns:1fr 1fr}@media(max-width:480px){.two{grid-template-columns:1fr}}</style></head><body><div class="wrap">
<div class="top"><img src="/logo.png" alt="${esc(co.name)}" style="height:84px;width:auto"><span class="sub" style="font-size:1.05rem">Wholesale order request</span></div>
<div class="ruo">${esc(co.ruo || 'All products are sold for research use only (RUO). Not for human or veterinary use.')} By submitting, you confirm you are ordering on behalf of a licensed clinic or research facility.</div>
<form id="f" class="grid" novalidate>
 <div>
  <div class="card"><h3>Your clinic</h3><div class="two"><div><label>Clinic / practice *</label><input name="clinic" required></div><div><label>Contact name *</label><input name="contact" required></div>
  <div><label>Email *</label><input name="email" type="email"></div><div><label>Phone</label><input name="phone"></div></div>
  <label>Ship-to address</label><input name="address" placeholder="Street, City, State ZIP">
  <div class="two"><div><label>Shipping</label><select name="shippingType" id="ship"></select></div><div><label>Payment</label><select name="payment"><option>Square (card)</option><option>Zelle</option><option>ACH</option></select></div></div>
  <label>Notes / PO number</label><textarea name="notes" rows="2"></textarea></div>
  <div class="card" style="margin-top:16px"><h3>Products</h3><input class="search" id="q" placeholder="Search products…" style="margin-top:8px"><div class="plist" id="plist"></div><p class="note">Prices shown are single-unit list prices. Volume pricing (10+, 20+, 50+, 100+) is applied automatically on your invoice.</p></div>
 </div>
 <div><div class="card" style="position:sticky;top:16px"><h3>Your order</h3><table class="cart" id="cart" style="width:100%;margin-top:8px"></table><div id="tots" style="margin-top:8px"></div><div id="msg"></div><button id="go">Submit order request</button><p class="note">We review every request before it ships. You'll get a confirmation and invoice from ${esc(co.name)}.</p></div></div>
</form></div>
<script>
(async () => {
const $=id=>document.getElementById(id); const fmt=n=>n.toLocaleString('en-US',{style:'currency',currency:'USD'}); const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const cat=await (await fetch('/api/public/catalog')).json(); const qty={};
$('ship').innerHTML='<option value="">Select…</option>'+cat.shipping.filter(s=>s.name!=='Local Pickup').map(s=>'<option>'+esc(s.name)+' — '+fmt(s.charge)+'</option>').join('')+'<option>Local Pickup</option>';
const tier=(p,q)=>{const t=p.tiers||[];const i=q>=100?4:q>=50?3:q>=20?2:q>=10?1:0;for(let k=i;k>=0;k--)if(t[k]!=null)return t[k];return p.price;};
function renderList(){const q=($('q').value||'').toLowerCase();$('plist').innerHTML=cat.products.filter(p=>p.name.toLowerCase().includes(q)).map(p=>'<div class="prow"><div class="n">'+esc(p.name)+'</div><div class="pr">'+fmt(p.price)+'</div><input type="number" min="0" step="1" data-id="'+p.id+'" value="'+(qty[p.id]||'')+'" placeholder="0" aria-label="Qty"></div>').join('');}
function renderCart(){const rows=cat.products.filter(p=>qty[p.id]>0);let sub=0;$('cart').innerHTML=rows.map(p=>{const u=tier(p,qty[p.id]);const t=u*qty[p.id];sub+=t;return '<tr><td>'+esc(p.name)+'<br><span class="note">'+qty[p.id]+' × '+fmt(u)+'</span></td><td class="r">'+fmt(t)+'</td></tr>';}).join('')||'<tr><td class="note">No products selected yet.</td></tr>';
 const shipName=($('ship').value||'').split(' — ')[0];const sh=cat.shipping.find(s=>s.name===shipName);const shipC=sh?sh.charge:0;const pay=document.querySelector('[name=payment]').value;const fee=pay.startsWith('Square')?(sub+shipC)*cat.squareFeePct:0;
 $('tots').innerHTML=rows.length?'<div class="tot"><span>Products</span><b>'+fmt(sub)+'</b></div><div class="tot"><span>Shipping</span><b>'+fmt(shipC)+'</b></div>'+(fee?'<div class="tot"><span>Card processing ('+(cat.squareFeePct*100).toFixed(0)+'%)</span><b>'+fmt(fee)+'</b></div>':'')+'<div class="tot" style="border-top:1px solid var(--line);margin-top:4px;padding-top:8px;font-size:1.05rem"><span>Estimated total</span><b>'+fmt(sub+shipC+fee)+'</b></div>':'';}
$('plist').addEventListener('input',e=>{if(e.target.dataset.id){qty[e.target.dataset.id]=+e.target.value||0;renderCart();}});$('q').oninput=renderList;$('ship').onchange=renderCart;document.querySelector('[name=payment]').onchange=renderCart;renderList();renderCart();
$('f').onsubmit=async e=>{e.preventDefault();const fd=new FormData($('f'));const d=Object.fromEntries(fd.entries());d.shippingType=(d.shippingType||'').split(' — ')[0];d.payment=d.payment.startsWith('Square')?'Square':d.payment;d.lines=cat.products.filter(p=>qty[p.id]>0).map(p=>({product:p.name,qty:qty[p.id]}));
 $('msg').innerHTML='';if(!d.clinic||!d.contact||!(d.email||d.phone)||!d.lines.length){$('msg').innerHTML='<div class="err">Please fill in clinic, contact, an email or phone, and pick at least one product.</div>';return;}
 $('go').disabled=true;const r=await fetch('/api/public/order',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)});const j=await r.json().catch(()=>({}));
 if(r.ok){document.querySelector('.grid').innerHTML='<div class="card ok" style="grid-column:1/-1">Thank you — your request <b>#'+esc(j.ref)+'</b> is in. '+esc(cat.company||'Zemo')+' will confirm, invoice, and ship. Questions: reply to your confirmation email.</div>';}else{$('go').disabled=false;$('msg').innerHTML='<div class="err">'+esc(j.error||'Something went wrong. Please try again.')+'</div>';}};
})();
</script></body></html>`; };
const loginPage = (err, next) => PAGE('Sign in', `<form class="card" method="post" action="/login"><img src="/logo.png" alt="Zemo" style="width:170px;display:block;margin:0 auto 14px"><h1 style="text-align:center">Order Desk</h1><div class="sub">Sign in to continue</div>
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
  if (col === 'orders') return docs.filter(o => o.rep === user.rep).map(o => ({ id: o.id, num: o.num, date: o.date, datePaid: o.datePaid, paid: !!o.paid, client: o.client, rep: o.rep, payment: o.payment, shippingType: o.shippingType, shippingCharge: o.shippingCharge, discountAmt: o.discountAmt, discountPct: o.discountPct, feeWaived: !!o.feeWaived, lines: (o.lines || []).map(l => ({ product: l.product, qty: l.qty, unitPrice: l.unitPrice, promo: l.promo })) })); // no costs, notes, provider, tracking, carrier cost
  if (col === 'settings') return docs.map(s => ({ id: s.id, squareFeePct: s.squareFeePct, deductSquareFromCommission: s.deductSquareFromCommission, revenueBasis: s.revenueBasis, reps: (s.reps || []).filter(r => r.name === user.rep), shipping: (s.shipping || []).map(x => ({ name: x.name, charge: x.charge, cost: 0 })), paymentMethods: [] }));
  if (col === 'products') return docs.map(p => ({ id: p.id, name: p.name, order: p.order }));
  if (col === 'payouts') return docs.filter(p => p.rep === user.rep);
  if (col === 'closes') return docs.map(c => ({ id: c.id, closedAt: c.closedAt, snapshot: { month: c.snapshot.month, pnl: {}, reps: Object.fromEntries(Object.entries(c.snapshot.reps || {}).filter(([n]) => n === user.rep)), repOrders: Object.fromEntries(Object.entries(c.snapshot.repOrders || {}).filter(([n]) => n === user.rep)), inv: [], invTotal: 0, recv: [], recvTotal: 0, purchases: 0 } }));
  return [];
}
function canWrite(user, col) { if (user.role === 'owner') return true; if (user.role === 'rep') return false; return !OWNER_ONLY.has(col); }

http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x'); const p = url.pathname; const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  // Read-only report access: set REPORT_TOKEN in the environment, then GET /api/* with header  Authorization: Bearer <token>
  const auth = req.headers.authorization || '';
  const reportToken = process.env.REPORT_TOKEN;
  const isReport = reportToken && auth === 'Bearer ' + reportToken && req.method === 'GET' && p.startsWith('/api/');
  const me = isReport ? { name: 'Report', username: '_report', role: 'owner', readOnly: true } : readToken(cookies(req).zemo_session);
  if (!users.length) { // first run
    if (p === '/setup' && req.method === 'POST') { const f = form(await body(req)); if (!f.username || (f.password || '').length < 12) return html(res, 400, setupPage('Password must be at least 12 characters.')); users.push({ name: f.name || f.username, username: f.username.trim().toLowerCase(), role: 'owner', hash: hash(f.password) }); saveUsers(); return redirect(res, '/', { 'Set-Cookie': cookie(req, makeToken(users[0]), SESSION_DAYS * 86400) }); }
    return html(res, 200, setupPage());
  }
  if (p === '/login') { if (req.method === 'POST') { if (tooMany(ip)) return html(res, 429, loginPage('Too many attempts. Try again in 15 minutes.')); const f = form(await body(req)); const u = users.find(x => x.username === (f.username || '').trim().toLowerCase()); if (!u || !verify(f.password || '', u.hash)) { failed(ip); return html(res, 401, loginPage('Wrong username or password.', f.next)); } return redirect(res, (f.next || '/').startsWith('/') ? f.next || '/' : '/', { 'Set-Cookie': cookie(req, makeToken(u), SESSION_DAYS * 86400) }); } return html(res, 200, loginPage('', url.searchParams.get('next'))); }
  if (p === '/logout') return redirect(res, '/login', { 'Set-Cookie': cookie(req, '', 0) });
  if (p === '/healthz') return json(res, 200, { ok: true });
  if (['/logo.png', '/logo-mark.png', '/favicon.png'].includes(p)) { const f = path.join(__dirname, p.slice(1)); if (!fs.existsSync(f)) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': 'image/png', 'Cache-Control': 'public, max-age=86400' }); return fs.createReadStream(f).pipe(res); }
  // ---- Public clinic ordering page (no login). Shows product names + Tier 1 list price only; saves to `requests` for owner/staff approval. ----
  const portalOn = !(db.settings[0] && db.settings[0].clinicPortal === false);
  if (p === '/order' || p === '/order/') { if (!portalOn) return html(res, 404, PAGE('Unavailable', '<div class="card"><h1>Online ordering is paused</h1><div class="sub">Please contact Zemo directly.</div></div>')); return html(res, 200, orderPage()); }
  if (p === '/api/public/catalog') { if (!portalOn) return json(res, 404, { error: 'off' }); const st = db.settings[0] || {}; return json(res, 200, { products: db.products.filter(x => x.name && x.price != null).sort((a, b) => (a.order ?? 999) - (b.order ?? 999)).map(x => ({ id: x.id, name: x.name, price: x.price, tiers: x.tiers || null })), shipping: (st.shipping || []).map(s => ({ name: s.name, charge: s.charge })), squareFeePct: st.squareFeePct ?? 0.05, company: (st.company || {}).name || 'Zemo' }); }
  if (p === '/api/public/order' && req.method === 'POST') {
    if (!portalOn) return json(res, 404, { error: 'off' });
    if (tooMany('order:' + ip)) return json(res, 429, { error: 'Too many submissions. Try again later.' });
    let d; try { d = JSON.parse(await body(req) || '{}'); } catch (e) { return json(res, 400, { error: 'bad json' }); }
    const s = v => String(v ?? '').slice(0, 300).trim();
    const lines = Array.isArray(d.lines) ? d.lines.slice(0, 40).map(l => ({ product: s(l.product), qty: Math.max(1, Math.min(999, parseInt(l.qty, 10) || 1)) })).filter(l => db.products.find(x => x.name === l.product)) : [];
    if (!s(d.clinic) || !s(d.contact) || !(s(d.email) || s(d.phone)) || !lines.length) { failed('order:' + ip); return json(res, 400, { error: 'Clinic, contact name, email or phone, and at least one product are required.' }); }
    const r = { id: 'req' + Date.now().toString(36) + crypto.randomBytes(3).toString('hex'), status: 'pending', submittedAt: new Date().toISOString(), clinic: s(d.clinic), contact: s(d.contact), email: s(d.email), phone: s(d.phone), address: s(d.address), shippingType: s(d.shippingType), payment: s(d.payment), notes: s(d.notes), lines, ip: String(ip).slice(0, 60) };
    db.requests.push(r); save(); return json(res, 200, { ok: true, ref: r.id.slice(-6).toUpperCase() });
  }
  if (p === '/api/public/ping') return json(res, 200, { ok: true });
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
    if (me.readOnly || !canWrite(me, col)) return json(res, 403, { error: 'not allowed for your role' });
    if (!id) return json(res, 400, { error: 'id required' });
    const b = await body(req); const i = db[col].findIndex(d => d.id === id);
    if (req.method === 'DELETE') { if (i >= 0) db[col].splice(i, 1); save(); return json(res, 204); }
    if (req.method === 'PUT') { let d; try { d = JSON.parse(b || '{}'); } catch (e) { return json(res, 400, { error: 'bad json' }); } if (typeof d !== 'object' || Array.isArray(d)) return json(res, 400, { error: 'bad doc' }); d.id = id; d._by = me.username; d._at = new Date().toISOString(); if (i >= 0) db[col][i] = d; else db[col].push(d); save(); return json(res, 200, d); }
    return json(res, 405, { error: 'method not allowed' });
  }
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
  fs.createReadStream(path.join(__dirname, 'index.html')).pipe(res);
}).listen(PORT, () => console.log(`Zemo Order Desk on http://localhost:${PORT}   data: ${DATA_DIR}`));
