# straw licence server

Key store and live machine dashboard for straw. No client accounts: the cheat is
unlocked by a key, one key lives on exactly one machine, and every machine
reports what it is running on every 3 seconds.

```
license-server/
├─ server.js            client API + dashboard API + pages
├─ db.js                postgres pool + schema (keys, devices, panel users)
├─ auth.js              password hashing (panel), key generation, RSA signing
├─ views/               login + dashboard (ejs)
├─ public/              dashboard css/js (3 s live refresh)
├─ scripts/genkey.js    regenerate the signing keypair
├─ render.yaml          one web service + one postgres
└─ .github/workflows/   keepalive ping so the free instance stays awake
```

## how it works

| route | purpose |
|---|---|
| `POST /api/v1/session` | `{key, hwid, hw}` → binds the key to that machine, `403 banned` when a different machine already owns it |
| `POST /api/v1/ping` | every **3 s**: refreshes ip / hwid / hardware, answers `ok` or `{banned:true, reason}` |

Rules enforced server side:

- first machine that presents a key owns it (`keys.hwid`)
- **a second machine with the same key bans the key automatically**, reason
  `used on a second machine`, and the dashboard shows it in red
- a banned key is refused on the next ping (≤3 s), and the client exits
- if a machine stops pinging (cable pulled, process killed) the dashboard shows
  it **offline** after `LIVE_WINDOW_SEC` (10 s) while the client itself exits
  after 5 missed pings (~15 s)
- every answer carries an RSA-SHA256 ticket; the client verifies it against the
  public key compiled in, so a fake `ok` cannot be injected

The hardware blob the client sends (`hw`) contains: cpu, gpu, ram, physical disk
serial, c: volume serial, MachineGuid, computer name, mainboard, bios serial and
monitor name. The dashboard renders it next to the hwid and the ip.

## live offset pushes

The cs2 client reads its offsets from a runtime table (`src/sdk/live.hpp`), so a
patch that moves a static does not need a new binary:

1. dashboard → **offsets** → paste the table, e.g.

   ```json
   { "dwEntityList": "0x2709010", "dwLocalPlayerPawn": "0x2553D38", "version": 4 }
   ```

   any field name the table knows is accepted (`dw*`, `m_*`, `entity*`); missing
   keys keep their current value. The server assigns the next version, hashes the
   payload and stores it.
2. every connected client is told on its next ping (≤3 s) and the login window
   switches to **offset update vN available** with an install button.
3. the install downloads the payload over a signature-checked channel, verifies
   `sha256` against the signed ticket, writes `offsets.json` next to the exe and
   asks for a restart.
4. a client whose table is older than the newest push is refused with `426`, so
   it cannot log in until it installed the update. `-1` as version means "not
   managed" (the rblx build).

The client never trusts the payload blindly: the ticket is
`v=<version>;sha=<sha256>;e=<expiry>` signed with the same RSA key, so a MITM
cannot feed it offsets.


## deploy in 6 steps

### 1. keys

A signing keypair is **already generated** for this checkout:

- `.license-key.txt` holds the private half — paste that PEM into Render as
  `LICENSE_PRIVATE_KEY`. It is gitignored, never commit it.
- the client in `auth/auth.hpp` already carries the matching public modulus, so
  the binaries you have will verify tickets from that key.

Want a fresh pair instead?

```bash
npm install
node scripts/genkey.js     # prints PEM + the modulus/exponent to paste in auth.hpp
```

The cheat must be rebuilt after changing the modulus.

### 2. push the folder

```bash
cd license-server
git init
git add .
git commit -m "licence server"
git branch -M main
git remote add origin https://github.com/<you>/straw-license.git
git push -u origin main
```

`.env`, `node_modules` and `.license-key.txt` stay out of git.

### 3. import on render.com

1. Render dashboard → **New** → **Blueprint**
2. pick the repo, Render reads `render.yaml`
3. it asks for the secrets: paste `LICENSE_PRIVATE_KEY` (single-line form is
   fine), and choose `BOOTSTRAP_USER` / `BOOTSTRAP_PASS` — that is your first
   owner login
4. **Apply** — Render creates the web service and the Postgres database

### 4. keep it awake

Free web services sleep after ~15 min. Two ways:

- the included workflow: replace `REPLACE-WITH-YOUR-SERVICE` in
  `.github/workflows/keepalive.yml` with your URL, push. GitHub pings every
  10 minutes for free.
- or a paid Render cron job hitting `/api/v1/ping`.

### 5. configure the cheat

Either type the URL into the login window once (it is stored next to the token),
or hardcode it in `auth/auth.hpp` and rebuild:

```cpp
inline constexpr const char* kBaseUrl = "https://your-service.onrender.com";
```

### 6. hand out access

1. dashboard → **keys** → create (days, count, note) → copy the code
2. send the customer the key
3. the cheat asks for the key once; after that it reconnects on its own

### dashboard

- **live** — every machine, refreshed every 3 s: key, hwid, cpu/gpu/ram/disk/
  monitor, ip, last ping age, state. One button bans the key instantly.
- **keys** — create/list/ban/unban/**reset** (forget the machine so the key can
  move to a new pc)/delete
- **panel users** — who may open the dashboard (`staff`/`admin`/`owner`)

A machine that stops answering turns `offline` after 10 s; a key used from a
second pc turns `banned: used on a second machine` and the client drops within
one ping.


## local test

```bash
DATABASE_URL=postgres://user:pass@localhost:5432/straw \
BOOTSTRAP_USER=admin BOOTSTRAP_PASS=test1234 \
node server.js
```

`http://localhost:3000` → login → create a key → point `kBaseUrl` at it.

## notes and honest limits

- Postgres keeps state; the free Render database is time limited — export or
  move to the paid tier before it expires, or point `DATABASE_URL` at any
  Postgres (Supabase, Neon, your own) and keep using the same code.
- The client verifies an RSA-SHA256 signature over
  `u=<user>;k=<key>;h=<hwid>;e=<expiry>`. It never sees the private key, so it
  cannot mint its own tickets.
- HWID is bound on first login and checked on every heartbeat; a second machine
  is refused with `hwid mismatch`.
- A patched binary can still skip the gate. That is true for every client-side
  licence check ever shipped — server authority (kick, expiry, disable) is what
  keeps a leaked build from being useful for long, plus the fact that the
  signature check is not a simple `if`.
