# snapshrinkimg.com — drop watcher

Watches the **authoritative registry (RDAP)** for `snapshrinkimg.com` and alerts the
moment it drops, so it can be re-registered at normal price (~$10–15) instead of
paying Hostinger's $118.23 redemption invoice.

No registrar account, no Hostinger API key, no scraping. RDAP is the public,
authoritative source the registry itself publishes.

## Where the domain stands

| Event | Date (UTC) | Source |
|---|---|---|
| Registered | 2025-09-07 | registry |
| Expired | 2026-09-07 | registry |
| **Entered redemption** | **2026-09-17** | registry (`last changed`) |
| Restore deadline (Hostinger, $118.23) | **~2026-10-17** | redemption = 30 days |
| → `pendingDelete` begins | ~2026-10-17 | predicted |
| → **DROPS / registrable** | **~2026-10-22, 18:00–20:00 UTC** | predicted |

Current registry status: `client transfer prohibited, redemption period`.
DNS does not resolve; the site is down.

The predicted drop date firms up to **high confidence** the moment the status
flips to `pendingDelete` — from that point the drop is exactly 5 days later.
The watcher recalculates this on every run.

## Read this before relying on it

Waiting for the drop is **not guaranteed to work**. When a `.com` is released,
automated drop-catching services fire thousands of registration attempts in the
first milliseconds. A human clicking "add to cart" cannot win a contested drop.

- If **nobody backorders it**, you will get it easily. Likely for a small
  1-year-old domain — but not certain.
- If **anyone backorders it**, you lose, and the domain is gone permanently.

Three options, honestly:

1. **Pay the $118.23 before ~2026-10-17.** Guaranteed, boring, keeps the name.
2. **Place a backorder** at Dynadot / Namecheap / DropCatch (~$15–60, usually
   only charged if they actually catch it). Vastly better odds than hand-
   registering, far cheaper than $118. **This is the best value if you want to
   gamble.**
3. **Just this watcher.** Free. Works if the domain is uncontested.

Options 2 and 3 combine well — run both. The watcher costs nothing either way,
and it also tells you if someone else takes the name.

## Setup (GitHub Actions — runs without your computer)

1. Push this folder to a **public** GitHub repo.
   Public repos get unlimited free Actions minutes; a private repo would blow
   through the 2,000-minute monthly cap at this polling rate.
2. Repo → **Settings → Secrets and variables → Actions → New repository secret**:
   - `NTFY_TOPIC` — any hard-to-guess string, e.g. `snapshrink-drop-x7k2p9`
3. Install the free **ntfy** app (iOS / Android), subscribe to that exact topic.
   Phone push, no account needed. Anyone who guesses the topic can read it, so
   make it random.
4. Done. Check Actions → "Domain drop watch" → Run workflow to test it now.

Alerts also arrive as **GitHub issues** (which GitHub emails you) for the three
events that matter: `PENDING_DELETE`, `AVAILABLE`, `REREGISTERED`. That path
needs zero configuration — it works even if you skip ntfy entirely.

Optional email: set `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `MAIL_TO`
as secrets.

### Polling schedule

| Cron | Why |
|---|---|
| `*/30 * * * *` | baseline, around the clock |
| `*/5 17-21 * * *` | the daily Verisign drop window, padded |

GitHub's scheduled runs can lag 5–20 minutes under load — fine for watching a
status change, which is why you also want a backorder if you truly need the name.
The workflow commits a daily heartbeat so GitHub won't auto-disable it after 60
days of repo inactivity.

## Setup (local Mac — backup)

```bash
./install-local-macos.sh
```

Runs every 20 minutes while the Mac is awake, with a macOS notification (and it
speaks out loud if the domain goes available). Uninstall with
`./install-local-macos.sh uninstall`. Only runs when the machine is on — treat it
as a secondary.

## Manual use

```bash
python3 watch_domain.py --domain snapshrinkimg.com     # one check
python3 watch_domain.py --force-notify                 # test alert channels
```

Exit code `42` means the domain is available — useful for shell scripting.

## How false alarms are avoided

A single RDAP `404` could in principle be a registry hiccup. Before firing the
"AVAILABLE" alert the script re-queries after 8 seconds **and** cross-checks with
`whois`. If the two disagree it reports `UNKNOWN` and stays quiet.

## Files

| File | Purpose |
|---|---|
| `watch_domain.py` | the watcher (stdlib only, no dependencies) |
| `.github/workflows/domain-watch.yml` | scheduled cloud runner |
| `install-local-macos.sh` | optional launchd agent |
| `state.json` | last seen stage + transition history |
