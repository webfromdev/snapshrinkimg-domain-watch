#!/usr/bin/env python3
"""
Domain drop watcher.

Polls the authoritative registry (RDAP) for a domain and alerts when its
lifecycle stage changes -- most importantly when it finally DROPS and becomes
available to register again.

Stdlib only. No pip install, no API keys, no registrar account needed.

Usage:
    python3 watch_domain.py --domain snapshrinkimg.com
    python3 watch_domain.py --domain snapshrinkimg.com --force-notify   # test alerts
"""

import argparse
import datetime as dt
import json
import os
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

UA = "domain-watch/1.0 (+personal domain monitor)"
TIMEOUT = 25

# Verisign drops expired .com/.net names in a daily batch, historically
# ~2:00-2:30 PM US Eastern == 18:00-20:00 UTC depending on DST.
DROP_WINDOW_UTC = (18, 20)
REDEMPTION_DAYS = 30   # ICANN Redemption Grace Period
# Pay-on-success unless noted. GoDaddy retired backorders in Oct 2025.
BACKORDER_SERVICES = """  Dynadot   ~$24.99  pay-on-success  https://www.dynadot.com/market/backorder
  DropCatch ~$59     pay-on-success  https://www.dropcatch.com
  SnapNames ~$69-79  upfront         https://www.snapnames.com
Stack 2-3: each is an independent catch attempt, and you only pay the one
that actually wins."""
PENDING_DELETE_DAYS = 5  # ICANN Pending Delete

STAGE_ORDER = {
    "ACTIVE": 0,
    "GRACE": 1,
    "REDEMPTION": 2,
    "PENDING_DELETE": 3,
    "AVAILABLE": 4,
    "REREGISTERED": 5,
    "UNKNOWN": -1,
}


# ------------------------------------------------------- TLS trust resolution
# Some Python installs (notably python.org builds on macOS) ship without a
# usable CA bundle, which makes urllib fail where curl succeeds. Find one.

def _build_ssl_context():
    candidates = []
    try:
        import certifi
        candidates.append(certifi.where())
    except Exception:
        pass
    candidates += [
        os.environ.get("SSL_CERT_FILE"),
        "/etc/ssl/cert.pem",            # macOS
        "/etc/pki/tls/certs/ca-bundle.crt",  # RHEL
        "/etc/ssl/certs/ca-certificates.crt",  # Debian/Ubuntu
    ]
    for c in candidates:
        if c and os.path.exists(c):
            try:
                return ssl.create_default_context(cafile=c)
            except Exception:
                continue
    try:
        ctx = ssl.create_default_context()
        if ctx.get_ca_certs():
            return ctx
    except Exception:
        pass
    return None  # signals: use the curl fallback


SSL_CTX = _build_ssl_context()


def _http_get(url):
    """GET a URL. Returns (status, text). Falls back to the curl CLI if the
    interpreter has no usable CA bundle. Raises on transport failure."""
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Accept": "application/rdap+json, application/json",
    })
    if SSL_CTX is not None:
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT, context=SSL_CTX) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, ""
        except ssl.SSLError:
            pass  # fall through to curl
    # curl fallback -- uses the OS trust store
    proc = subprocess.run(
        ["curl", "-sS", "--max-time", str(TIMEOUT), "-w", "\n%{http_code}",
         "-H", f"User-Agent: {UA}",
         "-H", "Accept: application/rdap+json, application/json", url],
        capture_output=True, text=True, timeout=TIMEOUT + 10,
    )
    if proc.returncode != 0:
        raise OSError(f"curl failed ({proc.returncode}): {proc.stderr.strip()[:200]}")
    body, _, code = proc.stdout.rpartition("\n")
    return int(code.strip() or 0), body


# ---------------------------------------------------------------- RDAP lookup

def _rdap_endpoints(domain):
    tld = domain.rsplit(".", 1)[-1].lower()
    eps = []
    if tld in ("com", "net"):
        eps.append(f"https://rdap.verisign.com/{tld}/v1/domain/{domain}")
    eps.append(f"https://rdap.org/domain/{domain}")
    return eps


def rdap_lookup(domain):
    """
    Returns (found: bool|None, data: dict|None, note: str)
      found is True  -> domain exists in the registry
      found is False -> registry says it does NOT exist (i.e. AVAILABLE)
      found is None  -> we could not tell (network/transient error)
    """
    last_err = ""
    for url in _rdap_endpoints(domain):
        try:
            status, text = _http_get(url)
        except Exception as e:  # noqa: BLE001 - network layer is intentionally broad
            last_err = f"{type(e).__name__}: {e} ({url})"
            time.sleep(1)
            continue
        if status == 404:
            return False, None, f"404 from {url} (registry reports no such domain)"
        if status == 200:
            try:
                return True, json.loads(text), f"200 from {url}"
            except json.JSONDecodeError as e:
                last_err = f"bad JSON from {url}: {e}"
        else:
            last_err = f"HTTP {status} from {url}"
        time.sleep(1)
    return None, None, last_err or "all RDAP endpoints failed"


def whois_says_free(domain):
    """Secondary confirmation via the `whois` CLI, if present."""
    try:
        out = subprocess.run(
            ["whois", domain], capture_output=True, text=True, timeout=30
        ).stdout.lower()
    except Exception:
        return None
    if not out.strip():
        return None
    free_markers = ("no match for", "not found", "no data found", "status: free")
    if any(m in out for m in free_markers):
        return True
    if "domain name:" in out or "registry domain id" in out:
        return False
    return None


# ------------------------------------------------------------ stage detection

def parse_events(data):
    ev = {}
    for e in (data.get("events") or []):
        action = (e.get("eventAction") or "").lower()
        raw = e.get("eventDate")
        if not raw:
            continue
        try:
            ev[action] = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            continue
    return ev


def classify(found, data):
    """Map registry response -> (stage, statuses, events)."""
    if found is False:
        return "AVAILABLE", [], {}
    if found is None or not data:
        return "UNKNOWN", [], {}

    statuses = [s.lower() for s in (data.get("status") or [])]
    events = parse_events(data)
    joined = " ".join(statuses)

    if "pending delete" in joined or "pendingdelete" in joined:
        stage = "PENDING_DELETE"
    elif "redemption" in joined:
        stage = "REDEMPTION"
    elif "autorenew" in joined or "auto renew" in joined:
        stage = "GRACE"
    else:
        stage = "ACTIVE"

    # If it came back ACTIVE with a brand-new registration date, someone else
    # grabbed it after the drop.
    reg = events.get("registration")
    if stage == "ACTIVE" and reg:
        age = (dt.datetime.now(dt.timezone.utc) - reg).days
        if age < 30:
            stage = "REREGISTERED"
    return stage, statuses, events


def restore_deadline(stage, events):
    """Last day the owner can still pay the registrar to restore it."""
    if stage != "REDEMPTION":
        return None
    changed = events.get("last changed")
    return changed + dt.timedelta(days=REDEMPTION_DAYS) if changed else None


def predict_drop(stage, events):
    """Best-effort predicted drop date (UTC). Returns (date|None, confidence)."""
    changed = events.get("last changed") or events.get("last update of rdap database")
    if stage == "PENDING_DELETE" and changed:
        return changed + dt.timedelta(days=PENDING_DELETE_DAYS), "high"
    if stage == "REDEMPTION" and changed:
        return changed + dt.timedelta(
            days=REDEMPTION_DAYS + PENDING_DELETE_DAYS
        ), "medium"
    exp = events.get("expiration")
    if exp:
        return exp + dt.timedelta(days=75), "low"
    return None, "none"


# ------------------------------------------------------------- notifications

def _http_post(url, data, headers):
    """POST with the resolved trust store, falling back to the curl CLI."""
    if SSL_CTX is not None:
        try:
            req = urllib.request.Request(url, data=data, method="POST",
                                         headers={**headers, "User-Agent": UA})
            with urllib.request.urlopen(req, timeout=TIMEOUT, context=SSL_CTX) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")
        except ssl.SSLError:
            pass  # fall through to curl
    cmd = ["curl", "-sS", "--max-time", str(TIMEOUT), "-X", "POST",
           "-w", "\n%{http_code}", "-H", f"User-Agent: {UA}"]
    for k, v in headers.items():
        cmd += ["-H", f"{k}: {v}"]
    cmd += ["--data-binary", "@-", url]
    proc = subprocess.run(cmd, input=data, capture_output=True,
                          timeout=TIMEOUT + 10)
    if proc.returncode != 0:
        raise OSError(f"curl failed ({proc.returncode}): "
                      f"{proc.stderr.decode('utf-8', 'replace').strip()[:200]}")
    out = proc.stdout.decode("utf-8", "replace")
    body, _, code = out.rpartition("\n")
    return int(code.strip() or 0), body



def notify_ntfy(topic, title, body, priority, tags, click_url):
    if not topic:
        return "ntfy: skipped (no NTFY_TOPIC set)"
    url = topic if topic.startswith("http") else f"https://ntfy.sh/{topic}"
    try:
        status, _ = _http_post(url, body.encode("utf-8"), {
            "Title": title,
            "Priority": priority,
            "Tags": tags,
            "Click": click_url,
        })
        return f"ntfy: sent ({status})" if status < 300 else f"ntfy: HTTP {status}"
    except Exception as e:  # noqa: BLE001
        return f"ntfy: FAILED {type(e).__name__}: {e}"


def notify_github_issue(title, body):
    """Open a GitHub issue -> GitHub emails/pushes it to you for free."""
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not (token and repo):
        return "github: skipped (not running in Actions)"
    try:
        status, resp = _http_post(
            f"https://api.github.com/repos/{repo}/issues",
            json.dumps({"title": title, "body": body}).encode(),
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
            },
        )
        if status < 300:
            return f"github: issue created ({status})"
        return f"github: HTTP {status} {resp[:160]}"
    except Exception as e:  # noqa: BLE001
        return f"github: FAILED {type(e).__name__}: {e}"


def notify_email(subject, body):
    """Optional SMTP email. Set SMTP_HOST/SMTP_USER/SMTP_PASS/MAIL_TO."""
    host = os.environ.get("SMTP_HOST")
    user = os.environ.get("SMTP_USER")
    pw = os.environ.get("SMTP_PASS")
    to = os.environ.get("MAIL_TO")
    if not all([host, user, pw, to]):
        return "email: skipped (SMTP env not set)"
    import smtplib
    from email.message import EmailMessage
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = user
    msg["To"] = to
    msg.set_content(body)
    port = int(os.environ.get("SMTP_PORT", "587"))
    try:
        if port == 465:
            s = smtplib.SMTP_SSL(host, port, timeout=TIMEOUT,
                                 context=ssl.create_default_context())
        else:
            s = smtplib.SMTP(host, port, timeout=TIMEOUT)
            s.starttls(context=ssl.create_default_context())
        with s:
            s.login(user, pw)
            s.send_message(msg)
        return "email: sent"
    except Exception as e:  # noqa: BLE001
        return f"email: FAILED {type(e).__name__}: {e}"


def notify_macos(title, body, speak=False):
    if sys.platform != "darwin":
        return "macos: skipped (not darwin)"
    try:
        safe_t = title.replace('"', "'")
        safe_b = body.splitlines()[0][:200].replace('"', "'")
        subprocess.run(
            ["osascript", "-e",
             f'display notification "{safe_b}" with title "{safe_t}" sound name "Glass"'],
            capture_output=True, timeout=15,
        )
        if speak:
            subprocess.run(["say", "Domain is available. Register it now."],
                           capture_output=True, timeout=25)
        return "macos: shown"
    except Exception as e:  # noqa: BLE001
        return f"macos: FAILED {type(e).__name__}: {e}"


# --------------------------------------------------------------------- state

def load_state(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(path, state):
    with open(path, "w") as f:
        json.dump(state, f, indent=2, sort_keys=True)
        f.write("\n")


# ---------------------------------------------------------------------- main

def build_message(domain, stage, statuses, events, drop_at, confidence):
    now = dt.datetime.now(dt.timezone.utc)
    reg_links = (
        f"  Cloudflare : https://dash.cloudflare.com/?to=/:account/domains/register\n"
        f"  Porkbun    : https://porkbun.com/checkout/search?q={domain}\n"
        f"  Namecheap  : https://www.namecheap.com/domains/registration/results/?domain={domain}\n"
        f"  Hostinger  : https://www.hostinger.com/domain-name-search?domain={domain}\n"
    )
    if stage == "AVAILABLE":
        title = f"DOMAIN DROPPED: {domain} IS FREE"
        body = (
            f"{domain} is no longer in the registry. REGISTER IT RIGHT NOW.\n\n"
            f"{reg_links}\n"
            f"Checked at {now:%Y-%m-%d %H:%M} UTC.\n"
            f"Minutes matter -- drop-catchers move fast."
        )
        return title, body, "urgent", "rotating_light,tada", 5

    if stage == "PENDING_DELETE":
        when = f"{drop_at:%Y-%m-%d}" if drop_at else "in ~5 days"
        title = f"{domain}: PENDING DELETE -- drops {when}"
        body = (
            f"{domain} entered pendingDelete. It will be released in ~5 days.\n\n"
            f"Predicted drop: {when} between "
            f"{DROP_WINDOW_UTC[0]:02d}:00 and {DROP_WINDOW_UTC[1]:02d}:00 UTC.\n"
            f"Nobody can register it until then.\n\n"
            f"*** PLACE BACKORDERS NOW -- the name is listable from today. ***\n"
            f"{BACKORDER_SERVICES}\n\n"
            f"Hand-registering at the drop only works if nobody else wants it.\n"
            f"Restoring via your registrar is NO LONGER POSSIBLE at this stage.\n\n"
            f"{reg_links}"
        )
        return title, body, "high", "warning,hourglass", 4

    if stage == "REREGISTERED":
        title = f"{domain}: taken by someone else"
        body = (
            f"{domain} was re-registered by another party. "
            f"It is gone.\n\nRegistered: {events.get('registration')}"
        )
        return title, body, "high", "x", 4

    if stage == "REDEMPTION":
        drop_s = f"{drop_at:%Y-%m-%d}" if drop_at else "unknown"
        deadline = restore_deadline(stage, events)
        days_left = (deadline - now).days if deadline else None
        urgent = days_left is not None and days_left <= 4
        title = (f"{domain}: {days_left}d left to restore"
                 if urgent else f"{domain}: in redemption")
        body = (
            f"{domain} is in the Redemption Grace Period.\n"
            f"Still restorable via your registrar (with the redemption fee).\n"
            + (f"LAST DAY TO RESTORE: {deadline:%Y-%m-%d} ({days_left} days left).\n"
               if deadline else "")
            + f"Predicted public drop: ~{drop_s} (confidence: {confidence}).\n"
        )
        if urgent:
            body += (
                f"\nAfter the restore deadline the only routes are a backorder "
                f"or winning the open drop:\n{BACKORDER_SERVICES}\n"
            )
        return (title, body, "high" if urgent else "default",
                "rotating_light" if urgent else "hourglass", 4 if urgent else 2)

    title = f"{domain}: status {stage}"
    body = f"Registry status: {statuses or stage}\nChecked {now:%Y-%m-%d %H:%M} UTC."
    return title, body, "default", "mag", 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--domain", default=os.environ.get("WATCH_DOMAIN", "snapshrinkimg.com"))
    ap.add_argument("--state", default=os.environ.get("STATE_FILE", "state.json"))
    ap.add_argument("--force-notify", action="store_true",
                    help="send alerts even if nothing changed (test your channels)")
    ap.add_argument("--quiet-ok", action="store_true",
                    help="only notify on stage change or AVAILABLE")
    args = ap.parse_args()

    domain = args.domain.strip().lower()
    now = dt.datetime.now(dt.timezone.utc)

    found, data, note = rdap_lookup(domain)
    stage, statuses, events = classify(found, data)

    # Guard against a false "AVAILABLE" caused by a transient registry hiccup:
    # re-check, and cross-check with whois, before firing the big alert.
    if stage == "AVAILABLE":
        time.sleep(8)
        found2, data2, note2 = rdap_lookup(domain)
        stage2, _, _ = classify(found2, data2)
        w = whois_says_free(domain)
        if stage2 != "AVAILABLE" or w is False:
            print(f"[guard] first check said AVAILABLE but recheck={stage2} whois_free={w}"
                  f" -- treating as UNKNOWN, not alerting.")
            stage, statuses, events = "UNKNOWN", [], {}
            note = f"{note} | recheck: {note2} | whois_free={w}"

    drop_at, confidence = predict_drop(stage, events)
    deadline = restore_deadline(stage, events)

    prev = load_state(args.state)
    prev_stage = prev.get("stage", "NONE")
    changed = stage != prev_stage

    # --- console report -----------------------------------------------------
    print(f"=== {domain} @ {now:%Y-%m-%d %H:%M:%S} UTC ===")
    print(f"lookup      : {note}")
    print(f"stage       : {stage}" + (f"   (was {prev_stage})" if changed else ""))
    print(f"statuses    : {', '.join(statuses) if statuses else '-'}")
    for k, v in sorted(events.items()):
        print(f"  {k:<30} {v:%Y-%m-%d %H:%M} UTC")
    if deadline:
        print(f"restore deadline: {deadline:%Y-%m-%d} "
              f"({(deadline - now).days} days left to pay the registrar)")
    if drop_at:
        days = (drop_at - now).days
        print(f"predicted drop: {drop_at:%Y-%m-%d} "
              f"({days:+d} days, {DROP_WINDOW_UTC[0]:02d}:00-{DROP_WINDOW_UTC[1]:02d}:00 UTC, "
              f"confidence {confidence})")

    # --- decide whether to alert -------------------------------------------
    should = args.force_notify or stage == "AVAILABLE" or (
        changed and stage not in ("UNKNOWN",)
    )
    # Escalate daily once the restore window is nearly shut.
    if deadline and 0 <= (deadline - now).days <= 4:
        should = True
    # Daily heartbeat so you know the watcher is alive.
    if not should and not args.quiet_ok:
        last_beat = prev.get("last_heartbeat")
        if not last_beat or (now - dt.datetime.fromisoformat(last_beat)).days >= 1:
            should = True
            print("(sending daily heartbeat)")

    title, body, priority, tags, _urg = build_message(
        domain, stage, statuses, events, drop_at, confidence
    )
    if drop_at and stage in ("REDEMPTION", "PENDING_DELETE"):
        body += f"\nPredicted drop: {drop_at:%Y-%m-%d} ({(drop_at - now).days} days away)\n"

    if should:
        print("--- notifying ---")
        print(notify_ntfy(os.environ.get("NTFY_TOPIC"), title, body, priority, tags,
                          f"https://porkbun.com/checkout/search?q={domain}"))
        print(notify_macos(title, body, speak=(stage == "AVAILABLE")))
        print(notify_email(title, body))
        if stage in ("AVAILABLE", "PENDING_DELETE", "REREGISTERED"):
            print(notify_github_issue(title, body))
        prev["last_heartbeat"] = now.isoformat()
    else:
        print("(no change -- no alert)")

    # --- persist ------------------------------------------------------------
    prev.update({
        "domain": domain,
        "stage": stage,
        "statuses": statuses,
        "last_checked": now.isoformat(),
        "predicted_drop": drop_at.isoformat() if drop_at else None,
        "restore_deadline": deadline.isoformat() if deadline else None,
        "confidence": confidence,
        "lookup_note": note,
    })
    if changed:
        hist = prev.setdefault("history", [])
        hist.append({"at": now.isoformat(), "from": prev_stage, "to": stage})
        prev["history"] = hist[-50:]
    save_state(args.state, prev)

    # exit 0 normally; 42 == available (handy for shell scripting)
    return 42 if stage == "AVAILABLE" else 0


if __name__ == "__main__":
    sys.exit(main())
