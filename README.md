# Zemo Labs Order Desk — your own website

A single Node.js app: `server.js` (logins, roles, data API) + `index.html` (the Order Desk you've been using).
Data lives in `data.json` on a persistent disk, with daily backups in `backups/`. No database to run, no npm packages.

## What you get

- **Logins.** First visit creates the Owner account. Owner adds users at `/users`.
- **Roles.**
  - `owner` — everything (you).
  - `staff` — enters orders, purchases, inventory counts, clients. Cannot change pricing, fees, shipping rates, commission, or lock a month (Morgan).
  - `rep` — sees only their own commission statement; no costs, no clients, no other reps (Caitlyn, Laura).
- Same features as the Claude version: tiered pricing, card-fee pass-through, cash-basis revenue, rep tier bonus, Month Close, Receivables, price history, CSV exports.
- Your current data (71 products, 31 clients, 11 orders, settings) is pre-loaded in `data.json`.

---

## Option A — Render (recommended, ~15 minutes, ~$7/month)

1. Create a free account at **render.com**.
2. Put this folder in a GitHub repo (GitHub → New repository → upload these files), **or** skip GitHub: Render also accepts a Docker image, but the repo route is simpler.
3. Render dashboard → **New → Blueprint** → connect the repo. Render reads `render.yaml` and creates:
   - a web service running `node server.js`
   - a 1 GB persistent disk mounted at `/var/data` (where `data.json`, `users.json` and backups live)
4. Click **Apply**. In ~2 minutes you get `https://zemo-order-desk.onrender.com`.
5. Open it → create the Owner account (username + 12-character password). Done.

**Custom domain** (e.g. `orders.zemolabs.com`): Render → your service → Settings → Custom Domains → add it, then add the CNAME record it shows at your DNS provider (GoDaddy/Namecheap/Cloudflare). HTTPS is automatic.

Plan note: the free Render tier sleeps and has no disk — use **Starter** so data persists.

## Option B — Fly.io (~$5/month)

```
fly launch --no-deploy      # accept the existing fly.toml
fly volumes create zemo_data --size 1 --region mia
fly deploy
fly certs add orders.zemolabs.com   # optional custom domain
```

## Option C — any VPS / office PC with Docker

```
docker build -t zemo-desk .
docker run -d --name zemo -p 80:8080 -v zemo_data:/data --restart unless-stopped zemo-desk
```
Put it behind Caddy or nginx for HTTPS, or use Cloudflare Tunnel for a public address without opening ports.

## Option D — plain Node on a machine you own

```
DATA_DIR=/path/to/persistent/folder node server.js
```
Runs on port 8080 (set `PORT` to change). Make it start on boot with Task Scheduler (Windows) or `pm2` (Mac/Linux).

---

## After it's live

- **Add users:** sign in as owner → top-right **Users** → add Morgan (staff), Caitlyn & Laura (rep, pick their rep name).
- **Reps sign in** at the same address and land directly on their statement.
- **Backups:** `backups/data-YYYY-MM-DD.json` is written daily (last 60 kept). Download one occasionally. To restore, stop the app and copy it over `data.json`.
- **Updates:** when Claude gives you a new `index.html` / `server.js`, replace the files and redeploy (Render redeploys automatically on git push). Data is untouched.
- **Password reset:** owner can remove and re-add a user; the owner's own password is changed on the Users page. If the owner is locked out, delete `users.json` on the disk and the setup screen returns (data is not affected).

## Security notes

- Passwords are hashed (scrypt). Sessions are signed cookies (30 days). Login is rate-limited (10 tries / 15 min per IP).
- Always run behind HTTPS (Render/Fly do this for you).
- The Claude-hosted version and this site do **not** sync. Once this is live, use only this one.
