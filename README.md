# Token Limit Explorer

A tiny, zero-dependency tool to **monitor the plan usage limits of your Claude (Anthropic) subscription tokens**,
plus an optional **rotating proxy** that lets Claude Code (CLI or IDE) route across several tokens you control —
with usage-aware selection and automatic failover, so a long workflow never stops on a single token's rate limit.

It's a single `server.js` (Node 18+, no npm install) serving a dashboard and a small HTTP proxy.

> **Responsible use.** Only add tokens/keys you are authorized to use. Pooling or sharing subscription
> credentials may violate your provider's terms of service — check them. This project is a usage monitor and a
> load-balancing proxy; how you use it is your responsibility.

---

## Features

- **Usage dashboard** — paste up to 100 tokens (each with an optional holder name) and see every token's
  **5‑hour session** and **weekly** utilization, status, and reset countdown, at a glance. Tokens are shown in
  full with a copy button. Auto-refreshes (every 30 min, toggleable) plus "Refresh all" and per-token refresh.
- **Rotating proxy (optional)** — your apps use one **master token** and a base URL; the proxy forwards each
  request to `api.anthropic.com` on whichever pooled token is currently best, and **fails over automatically**
  on `429` / `401` / `403` / `5xx` so work never stops.
- **Smart selection** — spends soon-to-reset budget first (use-it-or-lose-it), leaves owners daytime headroom,
  drains fully at night, learns each owner's daily/weekly rhythm over time, and supports per-account caps, a
  manual pin/hold, exemptions and priority chains. All configurable from the dashboard.
- **Always-on** — ships a systemd unit (start on boot, 2s restart on crash) and a resilient server (catches
  stray errors instead of dying). Tiny footprint (~25–30 MB RAM, capped CPU).
- **No database, no dependencies** — state is a single `data/tokens.json` (mode 0600), written atomically with a
  `.bak`. Restarts keep your list.

---

## Quick start

```bash
git clone https://github.com/<you>/token-limit-explorer.git
cd token-limit-explorer
cp .env.example .env     # set TLE_USER / TLE_PASS (login) — do not leave the defaults
./start.sh               # starts on port 8740 (PORT=xxxx ./start.sh to change)
# open http://<host>:8740  and log in
./stop.sh
tail -f logs/server.log
```

Requires only **Node 18+** (for `fetch`) and **Python 3** (used by a couple of helper scripts).

### Configuration (environment variables)

| Var | Default | Meaning |
|-----|---------|---------|
| `TLE_USER` / `TLE_PASS` | `admin` / `admin` | Dashboard login. **Change these.** |
| `PORT` | `8740` | Listen port |
| `HOST` | `0.0.0.0` | Listen address |
| `TLE_PREMIUM` | *(empty)* | Comma-separated holder names to auto-tag as "premium" (bigger windows) |
| `PROBE_MODEL` | `claude-haiku-4-5-20251001` | Model used for the tiny 1-token limit probe |
| `TLE_DATA_DIR` | `./data` | Where `tokens.json` is stored |

---

## How limits are read

For each token the server sends **one 1-token request** to a small model (`PROBE_MODEL`) at `/v1/messages`. The
`anthropic-ratelimit-unified-*` response headers carry each window's utilization, status and reset time. A token
that has hit its limit answers `429` and the headers still carry the figures. (It also tries `/api/oauth/usage`
for richer data where the token's scope allows it; subscription tokens usually can't, so it backs off.)

---

## Rotating proxy (optional)

Turn it on from the dashboard. The dashboard shows a **master token** and a **base URL** (`http://<host>:8740/proxy`).
Point an app at them:

```bash
export ANTHROPIC_BASE_URL=http://<host>:8740/proxy
export CLAUDE_CODE_OAUTH_TOKEN=<master token>
claude
```

Requests go out on the pooled token the proxy picks, and fail over on any limit/auth/server error — the app never
sees the error. For Claude Code machine-wide, you can set `apiKeyHelper` (→ `master-key.sh`, which prints the live
master token) and `env.ANTHROPIC_BASE_URL` in `~/.claude/settings.json`, so every `claude` invocation uses the proxy.
The `claude-master` wrapper does the same for one-off runs.

### Selection logic (auto-cycle)

Each request, the proxy orders eligible tokens:

1. **Perishable first** — any token whose 5h or weekly window resets soon with budget left (use-it-or-lose-it).
2. **Soft fallback** — a different-org fallback token below a 30% soft cap is used up to 30%, then held in reserve.
3. **Primary** — otherwise the token with the most headroom (spreads the fleet).
4. **Fallback** — different-org tokens, last.

On top of that: **daytime caps** leave each owner headroom (standard ≤ 80% session, premium ≤ 90%), **night**
drains sessions fully, the **weekly** window is protected (never night-boosted — a weekly reset is days away), and
a **usage-pattern learner** adapts the daytime reserve to each owner's observed rhythm. Caps are for auto mode;
a manual **Use** (hold) or **pin** overrides them. All of this is per-account configurable in the dashboard.

### Overrides

- **Role** per token: `premium` / `standard` / `fallback` / `off`.
- **Per-account caps**: a hard 5h and weekly ceiling (percent).
- **Exempt**: hold a token out of auto-cycle.
- **Pin**: force a token to the front (numeric priority for a chain), e.g. "token A full → token B 50% → cycle".
- **Use** (manual): in any mode, stick to one token until its session hits ~75%, ignoring caps, then resume auto.

Failover applies in every mode, so work never stops.

---

## Always on (systemd)

```bash
sudo ./install-service.sh          # generates + enables the unit for the current dir/user
sudo systemctl status token-explorer
sudo systemctl restart token-explorer
```

Starts on boot, restarts within ~2s on crash. The unit caps the service (`Nice=10`, `CPUQuota=40%`,
`MemoryMax=384M`) so it never hogs the box.

---

## Security notes

- **Change the default login** (`TLE_USER`/`TLE_PASS`). Anyone who can reach the port and log in can read and copy
  every token.
- The dashboard shows tokens **in full** by design (so you can copy them). Serve it on localhost or behind TLS +
  auth; it speaks plain HTTP itself.
- The **master token** grants access to the whole pool through the proxy. Regenerate it ("New") if it leaks.
- `data/` (tokens, session secret, learned profile) and `logs/` are git-ignored and never committed.

---

## Files

| File | What |
|------|------|
| `server.js` | The whole server: dashboard API, limit probing, proxy, selection logic. |
| `public/index.html` | The dashboard (single file, no build). |
| `start.sh` / `stop.sh` | Start (idempotent, safe as a watchdog) / stop. |
| `install-service.sh` | Install the systemd unit (generated for your dir/user). |
| `master-key.sh` | Prints the live master token (for `apiKeyHelper`). |
| `claude-master` | Run `claude` through the proxy on the master token. |

## License

MIT — see [LICENSE](LICENSE).
