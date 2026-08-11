#!/usr/bin/env python3
"""
ti.py -- threat-intel-lookup engine

A small, dependency-free (stdlib only) engine that AGGREGATES free / open-source
threat-intel feeds into a local SQLite cache and LOOKS UP indicators (IP, domain,
URL, CVE) against that cache. Built for fast, repeatable IOC triage.

Every feed shipped here is fetched ANONYMOUSLY -- no API keys, no registration, no
auth headers -- so the toolkit works out of the box and is safe to share openly.

Subcommands
-----------
  feeds                    List the curated feed registry.
  aggregate                Download + normalize + dedupe all feeds into the cache.
  lookup <ioc> [ioc ...]   Check one or more indicators against the cache.

Common examples
---------------
  python3 ti.py aggregate                       # build/refresh the local cache
  python3 ti.py aggregate --refresh             # force re-download of every feed
  python3 ti.py lookup 45.155.205.233           # single IP
  python3 ti.py lookup evil.example[.]com hxxp://bad.tld/x   # defanged input is handled
  python3 ti.py lookup CVE-2024-3400 --json     # machine-readable
  python3 ti.py lookup 1.2.3.4 evil.tld --report --out ./deliverables

Design notes
------------
- Stdlib only (urllib, sqlite3, ipaddress, csv, json) so it runs anywhere Python 3.8+ is.
- Raw feed bodies are cached under ~/.cache/ti-aggregator/raw with a TTL, so re-runs
  are cheap and reproducible; the parsed data lives in ~/.cache/ti-aggregator/ti.db.
- This is a DEFENSIVE tool: it reports which public feeds flag an indicator so a
  defender can prioritize. It does not attack, exploit, or contact the indicators.
"""

import argparse
import csv
import ipaddress
import json
import os
import re
import sqlite3
import sys
import time
import urllib.request
import urllib.error

# --------------------------------------------------------------------------------------
# Paths / config
# --------------------------------------------------------------------------------------
CACHE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "ti-aggregator")
RAW_DIR = os.path.join(CACHE_DIR, "raw")
DB_PATH = os.path.join(CACHE_DIR, "ti.db")
TTL = 12 * 3600  # re-download a feed at most twice a day by default
UA = {"User-Agent": "threat-intel-lookup/1.0 (+defensive-ioc-triage)"}

# --------------------------------------------------------------------------------------
# Feed registry -- all anonymous, all free, all with defensible open licenses
# --------------------------------------------------------------------------------------
# Each feed: key, name, type (primary ioc type), fmt (parser), url, category, license,
# attribution. `fmt` chooses the parser in parse_feed().
FEEDS = [
    # ---- CVE / exploited -------------------------------------------------------------
    {"key": "cisa_kev", "name": "CISA Known Exploited Vulnerabilities", "type": "cve",
     "fmt": "cisa_kev", "category": "exploited-in-the-wild", "license": "US Gov / public domain",
     "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
     "attr": "CISA KEV (US-CERT)"},
    # ---- IPv4 indicators -------------------------------------------------------------
    {"key": "feodo", "name": "abuse.ch Feodo Tracker (botnet C2)", "type": "ipv4",
     "fmt": "feodo_json", "category": "botnet-c2", "license": "CC0-1.0",
     "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
     "attr": "abuse.ch Feodo Tracker"},
    {"key": "blocklist_de", "name": "blocklist.de (attacking hosts)", "type": "ipv4",
     "fmt": "ip_lines", "category": "attacker", "license": "Free (defensive use)",
     "url": "https://lists.blocklist.de/lists/all.txt",
     "attr": "blocklist.de"},
    {"key": "ipsum", "name": "stamparm/ipsum (aggregated, >=3 lists)", "type": "ipv4",
     "fmt": "ipsum", "category": "aggregated-malicious", "license": "Unlicense",
     "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
     "attr": "stamparm/ipsum"},
    {"key": "et_compromised", "name": "Emerging Threats compromised IPs", "type": "ipv4",
     "fmt": "ip_lines", "category": "compromised", "license": "BSD (ET Open ruleset)",
     "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
     "attr": "Proofpoint Emerging Threats Open"},
    {"key": "greensnow", "name": "GreenSnow (attacking hosts)", "type": "ipv4",
     "fmt": "ip_lines", "category": "attacker", "license": "Free (defensive use)",
     "url": "https://blocklist.greensnow.co/greensnow.txt",
     "attr": "GreenSnow.co"},
    {"key": "tor_exit", "name": "Tor Project exit nodes (context)", "type": "ipv4",
     "fmt": "ip_lines", "category": "tor-exit", "license": "Free (Tor Project)",
     "url": "https://check.torproject.org/torbulkexitlist",
     "attr": "The Tor Project"},
    # ---- CIDR ranges -----------------------------------------------------------------
    {"key": "dshield", "name": "SANS DShield top attacker blocks", "type": "cidr",
     "fmt": "dshield", "category": "attacker", "license": "Free (SANS ISC)",
     "url": "https://www.dshield.org/block.txt",
     "attr": "SANS Internet Storm Center / DShield"},
    {"key": "spamhaus_drop", "name": "Spamhaus DROP (hijacked/leased netblocks)", "type": "cidr",
     "fmt": "spamhaus_drop", "category": "do-not-route", "license": "Free (Spamhaus DROP)",
     "url": "https://www.spamhaus.org/drop/drop_v4.json",
     "attr": "The Spamhaus Project (DROP)"},
    # ---- Domains ---------------------------------------------------------------------
    {"key": "phishdb", "name": "Phishing.Database active phishing domains", "type": "domain",
     "fmt": "domain_lines", "category": "phishing", "license": "MIT",
     "url": "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
     "attr": "mitchellkrogza/Phishing.Database"},
]
FEEDS_BY_KEY = {f["key"]: f for f in FEEDS}

# --------------------------------------------------------------------------------------
# Normalization / IOC typing
# --------------------------------------------------------------------------------------
_RE_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)
_RE_MD5 = re.compile(r"^[a-f0-9]{32}$", re.I)
_RE_SHA1 = re.compile(r"^[a-f0-9]{40}$", re.I)
_RE_SHA256 = re.compile(r"^[a-f0-9]{64}$", re.I)
_RE_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9_](-?[a-z0-9_])*\.)+[a-z]{2,63}$", re.I)


def defang(s):
    """Undo common IOC defanging so pasted-from-a-report indicators still match."""
    if not s:
        return s
    s = s.strip().strip("\"'<>()[] \t\r\n")
    s = s.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    s = s.replace("[dot]", ".").replace("(dot)", ".").replace(" dot ", ".")
    s = s.replace("[:]", ":").replace("[/]", "/")
    s = re.sub(r"^hxxp(s?)://", r"http\1://", s, flags=re.I)
    s = re.sub(r"^hxxp(s?)\[?:\]?//", r"http\1://", s, flags=re.I)
    s = s.replace("[at]", "@")
    return s.strip()


def classify(ioc):
    """Return (ioc_type, normalized_value) for an indicator string."""
    v = defang(ioc)
    if _RE_CVE.match(v):
        return "cve", v.upper()
    if _RE_MD5.match(v):
        return "md5", v.lower()
    if _RE_SHA1.match(v):
        return "sha1", v.lower()
    if _RE_SHA256.match(v):
        return "sha256", v.lower()
    # IP?
    try:
        ip = ipaddress.ip_address(v)
        return ("ipv4" if ip.version == 4 else "ipv6"), str(ip)
    except ValueError:
        pass
    # URL?
    if "://" in v or (("/" in v) and ("." in v.split("/")[0])):
        return "url", v.strip()
    # Domain?
    if _RE_DOMAIN.match(v):
        return "domain", v.lower().rstrip(".")
    return "unknown", v


def host_of(url):
    """Extract the host (domain or IP) from a URL for cross-type indexing."""
    m = re.sub(r"^[a-z0-9+.\-]+://", "", url, flags=re.I)
    host = m.split("/")[0].split("?")[0].split("#")[0]
    host = host.split("@")[-1]          # strip creds
    host = host.split(":")[0]           # strip port
    return host.lower().strip().rstrip(".")


# --------------------------------------------------------------------------------------
# Fetching (with TTL cache of raw bodies)
# --------------------------------------------------------------------------------------
def fetch(feed, refresh=False):
    """Return raw bytes for a feed, using an on-disk TTL cache. None on failure."""
    os.makedirs(RAW_DIR, exist_ok=True)
    path = os.path.join(RAW_DIR, feed["key"] + ".raw")
    fresh = (os.path.exists(path) and os.path.getsize(path) > 0
             and (time.time() - os.path.getmtime(path)) < TTL)
    if fresh and not refresh:
        with open(path, "rb") as f:
            return f.read()
    try:
        req = urllib.request.Request(feed["url"], headers=dict(UA))
        with urllib.request.urlopen(req, timeout=90) as r:
            data = r.read()
        if data:
            with open(path, "wb") as f:
                f.write(data)
        return data
    except Exception as e:  # noqa: BLE001 - want to keep going across feeds
        if os.path.exists(path):
            sys.stderr.write("  (%s: %s -- using stale cache)\n" % (feed["key"], e))
            with open(path, "rb") as f:
                return f.read()
        sys.stderr.write("  (%s unavailable: %s)\n" % (feed["key"], e))
        return None


# --------------------------------------------------------------------------------------
# Parsers -> yield normalized records
# --------------------------------------------------------------------------------------
# Two record kinds:
#   ("indicator", value, ioc_type, extra_dict)
#   ("cidr", network_str, extra_dict)
def parse_feed(feed, data):
    fmt = feed["fmt"]
    text = data.decode("utf-8", "replace") if isinstance(data, bytes) else data

    def clean_lines():
        for ln in text.splitlines():
            ln = ln.strip()
            if ln and not ln.startswith("#") and not ln.startswith(";"):
                yield ln

    if fmt == "ip_lines":
        for ln in clean_lines():
            tok = ln.split()[0].split(",")[0]
            try:
                ipaddress.ip_address(tok)
            except ValueError:
                continue
            yield ("indicator", tok, "ipv4" if ":" not in tok else "ipv6", {})

    elif fmt == "ipsum":
        for ln in clean_lines():
            parts = ln.split()
            tok = parts[0]
            try:
                ipaddress.ip_address(tok)
            except ValueError:
                continue
            score = parts[1] if len(parts) > 1 else ""
            yield ("indicator", tok, "ipv4", {"ipsum_lists": score})

    elif fmt == "feodo_json":
        try:
            arr = json.loads(text)
        except Exception:
            arr = []
        for o in arr:
            ip = o.get("ip_address")
            if ip:
                yield ("indicator", ip, "ipv4",
                       {"malware": o.get("malware"), "port": o.get("port"),
                        "first_seen": o.get("first_seen"), "last_online": o.get("last_online")})

    elif fmt == "dshield":
        # tab-separated: start<TAB>end<TAB>netmask<TAB>...
        for ln in clean_lines():
            p = ln.split()
            if len(p) >= 3:
                start, _end, mask = p[0], p[1], p[2]
                try:
                    prefix = ipaddress.IPv4Network("0.0.0.0/" + mask, strict=False).prefixlen \
                        if mask.count(".") == 3 else int(mask)
                    net = ipaddress.ip_network("%s/%d" % (start, prefix), strict=False)
                    yield ("cidr", str(net), {})
                except Exception:
                    continue

    elif fmt == "spamhaus_drop":
        # JSON-lines: {"cidr":"1.10.16.0/20","sblid":"...","rir":"..."}
        for ln in clean_lines():
            try:
                o = json.loads(ln)
            except Exception:
                continue
            if o.get("cidr"):
                yield ("cidr", o["cidr"], {"sblid": o.get("sblid")})

    elif fmt == "domain_lines":
        for ln in clean_lines():
            d = ln.lower().rstrip(".")
            if _RE_DOMAIN.match(d):
                yield ("indicator", d, "domain", {})

    elif fmt == "cisa_kev":
        try:
            obj = json.loads(text)
        except Exception:
            obj = {}
        for v in obj.get("vulnerabilities", []):
            cid = (v.get("cveID") or "").upper()
            if cid:
                yield ("indicator", cid, "cve",
                       {"name": v.get("vulnerabilityName"), "vendor": v.get("vendorProject"),
                        "product": v.get("product"), "dateAdded": v.get("dateAdded"),
                        "ransomware": v.get("knownRansomwareCampaignUse"),
                        "dueDate": v.get("dueDate")})


# --------------------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------------------
def db_connect():
    os.makedirs(CACHE_DIR, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("""CREATE TABLE IF NOT EXISTS indicators(
        value TEXT, ioc_type TEXT, feed TEXT, category TEXT,
        extra TEXT, updated_at TEXT, PRIMARY KEY(value, feed))""")
    con.execute("""CREATE TABLE IF NOT EXISTS cidrs(
        network TEXT, feed TEXT, category TEXT, extra TEXT,
        updated_at TEXT, PRIMARY KEY(network, feed))""")
    con.execute("""CREATE TABLE IF NOT EXISTS meta(
        feed TEXT PRIMARY KEY, name TEXT, ioc_type TEXT, count INTEGER,
        fetched_at TEXT, status TEXT, bytes INTEGER)""")
    con.execute("CREATE INDEX IF NOT EXISTS idx_ind_value ON indicators(value)")
    con.commit()
    return con


def aggregate(selected, refresh=False):
    con = db_connect()
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    totals = {}
    for feed in selected:
        data = fetch(feed, refresh=refresh)
        if data is None:
            con.execute("INSERT OR REPLACE INTO meta VALUES(?,?,?,?,?,?,?)",
                        (feed["key"], feed["name"], feed["type"], 0, now, "FAILED", 0))
            totals[feed["key"]] = ("FAILED", 0)
            con.commit()
            continue
        # wipe this feed's prior rows so the cache reflects the current feed state
        con.execute("DELETE FROM indicators WHERE feed=?", (feed["key"],))
        con.execute("DELETE FROM cidrs WHERE feed=?", (feed["key"],))
        ind_rows, cidr_rows = [], []
        for rec in parse_feed(feed, data):
            if rec[0] == "indicator":
                _, value, ioc_type, extra = rec
                ind_rows.append((value, ioc_type, feed["key"], feed["category"],
                                 json.dumps(extra) if extra else "", now))
            else:
                _, net, extra = rec
                cidr_rows.append((net, feed["key"], feed["category"],
                                  json.dumps(extra) if extra else "", now))
        if ind_rows:
            con.executemany("INSERT OR REPLACE INTO indicators VALUES(?,?,?,?,?,?)", ind_rows)
        if cidr_rows:
            con.executemany("INSERT OR REPLACE INTO cidrs VALUES(?,?,?,?,?)", cidr_rows)
        cnt = len(ind_rows) + len(cidr_rows)
        con.execute("INSERT OR REPLACE INTO meta VALUES(?,?,?,?,?,?,?)",
                    (feed["key"], feed["name"], feed["type"], cnt, now, "OK", len(data)))
        con.commit()
        totals[feed["key"]] = ("OK", cnt)
        sys.stderr.write("  [ok] %-14s %8d indicators\n" % (feed["key"], cnt))
    con.close()
    return totals


# --------------------------------------------------------------------------------------
# Lookup
# --------------------------------------------------------------------------------------
def lookup_one(con, ioc):
    ioc_type, value = classify(ioc)
    hits = []  # list of dict(feed, name, category, ioc_type, extra)
    cidr_hits = []

    # direct indicator match (also match url<->host cross indexing)
    candidates = {value}
    if ioc_type == "url":
        candidates.add(host_of(value))
    for cand in list(candidates):
        for row in con.execute(
                "SELECT value, ioc_type, feed, category, extra FROM indicators WHERE value=?",
                (cand,)):
            f = FEEDS_BY_KEY.get(row[2], {})
            hits.append({"feed": row[2], "name": f.get("name", row[2]),
                         "category": row[3], "matched": row[0], "ioc_type": row[1],
                         "attr": f.get("attr", ""),
                         "extra": json.loads(row[4]) if row[4] else {}})

    # CIDR membership for IPs
    if ioc_type in ("ipv4", "ipv6"):
        try:
            ip = ipaddress.ip_address(value)
            for row in con.execute("SELECT network, feed, category, extra FROM cidrs"):
                try:
                    if ip in ipaddress.ip_network(row[0], strict=False):
                        f = FEEDS_BY_KEY.get(row[1], {})
                        cidr_hits.append({"feed": row[1], "name": f.get("name", row[1]),
                                          "category": row[2], "network": row[0],
                                          "attr": f.get("attr", ""),
                                          "extra": json.loads(row[3]) if row[3] else {}})
                except ValueError:
                    continue
        except ValueError:
            pass

    feeds_flagged = sorted({h["feed"] for h in hits} | {c["feed"] for c in cidr_hits})
    verdict = verdict_for(ioc_type, hits, cidr_hits)
    return {"input": ioc, "ioc_type": ioc_type, "normalized": value,
            "hits": hits, "cidr_hits": cidr_hits,
            "feeds_flagged": feeds_flagged, "score": len(feeds_flagged),
            "verdict": verdict}


def verdict_for(ioc_type, hits, cidr_hits):
    n = len({h["feed"] for h in hits} | {c["feed"] for c in cidr_hits})
    cats = {h["category"] for h in hits} | {c["category"] for c in cidr_hits}
    only_context = cats and cats.issubset({"tor-exit"})
    if n == 0:
        return "CLEAN"
    if only_context:
        return "CONTEXT"            # e.g. Tor exit only -- notable, not inherently malicious
    if ioc_type == "cve":
        return "EXPLOITED"          # present in KEV
    if n >= 3:
        return "MALICIOUS"          # corroborated by 3+ independent feeds
    return "SUSPICIOUS"


# --------------------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------------------
VERDICT_EMOJI = {"MALICIOUS": "\U0001F534", "EXPLOITED": "\U0001F534",
                 "SUSPICIOUS": "\U0001F7E0", "CONTEXT": "\U0001F7E1", "CLEAN": "⚪"}


def cache_age(con):
    row = con.execute("SELECT MIN(fetched_at), MAX(fetched_at), SUM(count) FROM meta "
                      "WHERE status='OK'").fetchone()
    return row if row else (None, None, 0)


def print_result(r):
    em = VERDICT_EMOJI.get(r["verdict"], "")
    print("\n=== %s ===" % r["input"])
    print("Type: %s   Normalized: %s" % (r["ioc_type"], r["normalized"]))
    print("Verdict: %s %s   (feeds flagging: %d)" % (em, r["verdict"], r["score"]))
    if not r["hits"] and not r["cidr_hits"]:
        print("  No curated feed lists this indicator.")
        return
    for h in r["hits"]:
        extra = h["extra"]
        bits = []
        for k in ("malware", "name", "ransomware", "ipsum_lists", "via", "dateAdded"):
            if extra.get(k):
                bits.append("%s=%s" % (k, extra[k]))
        detail = ("  [" + ", ".join(bits) + "]") if bits else ""
        note = "" if h["matched"] == r["normalized"] else "  (via %s)" % h["matched"]
        print("  - %-13s %-22s %s%s%s" % (h["feed"], h["category"], h["name"], note, detail))
    for c in r["cidr_hits"]:
        sbl = ("  [%s]" % c["extra"].get("sblid")) if c["extra"].get("sblid") else ""
        print("  - %-13s %-22s %s  (netblock %s)%s" %
              (c["feed"], c["category"], c["name"], c["network"], sbl))


def recommendation(r):
    v = r["verdict"]
    return {
        "MALICIOUS": "Corroborated by multiple independent feeds -- block/quarantine and hunt for related activity.",
        "EXPLOITED": "On CISA KEV (exploited in the wild) -- prioritize patching/mitigation immediately.",
        "SUSPICIOUS": "Listed by 1-2 feeds -- investigate; confirm with a second source before acting.",
        "CONTEXT": "Infrastructure of note (e.g. Tor exit) -- not inherently malicious; weigh with other signals.",
        "CLEAN": "No curated feed lists it -- absence of a hit is not proof of safety; use other telemetry.",
    }[v]


def to_markdown(results, con):
    mn, mx, tot = cache_age(con)
    ts = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    L = ["# Threat Intel Lookup Report", "",
         "_Generated %s -- threat-intel-lookup_" % ts,
         "_Local cache last refreshed: %s (%s indicators across curated feeds)_" % (mx or "n/a", tot or 0),
         "",
         "| Indicator | Type | Verdict | Feeds | Categories |",
         "|---|---|---|---|---|"]
    for r in results:
        cats = sorted({h["category"] for h in r["hits"]} | {c["category"] for c in r["cidr_hits"]})
        L.append("| `%s` | %s | %s %s | %d | %s |" %
                 (r["input"], r["ioc_type"], VERDICT_EMOJI.get(r["verdict"], ""),
                  r["verdict"], r["score"], ", ".join(cats) or "-"))
    L += ["", "## Details"]
    for r in results:
        L += ["", "### `%s`" % r["input"], "",
              "- **Type / normalized:** %s / `%s`" % (r["ioc_type"], r["normalized"]),
              "- **Verdict:** %s %s (feeds flagging: %d)" %
              (VERDICT_EMOJI.get(r["verdict"], ""), r["verdict"], r["score"])]
        for h in r["hits"]:
            extra = ", ".join("%s=%s" % (k, v) for k, v in h["extra"].items() if v)
            L.append("- **%s** (%s) -- %s%s" %
                     (h["feed"], h["category"], h["name"], ("  [" + extra + "]") if extra else ""))
        for c in r["cidr_hits"]:
            L.append("- **%s** (%s) -- %s, netblock `%s`" %
                     (c["feed"], c["category"], c["name"], c["network"]))
        L.append("- **Recommendation:** %s" % recommendation(r))
    L += ["", "---",
          "_Sources: CISA KEV; abuse.ch Feodo Tracker; blocklist.de; stamparm/ipsum; "
          "Emerging Threats Open; GreenSnow; SANS DShield; Spamhaus DROP; Phishing.Database; "
          "Tor Project. Feeds lag real-world activity; a clean result is not proof of safety._"]
    return "\n".join(L)


def write_csv(results, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["indicator", "ioc_type", "normalized", "verdict", "feeds_flagged",
                    "feed_count", "categories", "recommendation"])
        for r in results:
            cats = sorted({h["category"] for h in r["hits"]} | {c["category"] for c in r["cidr_hits"]})
            w.writerow([r["input"], r["ioc_type"], r["normalized"], r["verdict"],
                        "; ".join(r["feeds_flagged"]), r["score"], "; ".join(cats),
                        recommendation(r)])


# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------
def select_feeds(args):
    feeds = FEEDS
    if getattr(args, "only", None):
        want = {k.strip() for k in args.only.split(",")}
        feeds = [f for f in feeds if f["key"] in want]
    if getattr(args, "exclude", None):
        drop = {k.strip() for k in args.exclude.split(",")}
        feeds = [f for f in feeds if f["key"] not in drop]
    return feeds


def cmd_feeds(args):
    print("Curated free / open-source threat-intel feeds (all anonymous, no API key):\n")
    print("%-14s %-8s %-24s %s" % ("KEY", "TYPE", "LICENSE", "NAME"))
    for f in FEEDS:
        print("%-14s %-8s %-24s %s" % (f["key"], f["type"], f["license"], f["name"]))
    print("\nEvery feed is fetched anonymously. Add or extend feeds via the FEEDS list "
          "in this file;\nsee references/feeds.md for the schema and license notes.")


def cmd_aggregate(args):
    feeds = select_feeds(args)
    sys.stderr.write("Aggregating %d feed(s) into %s ...\n" % (len(feeds), DB_PATH))
    t0 = time.time()
    totals = aggregate(feeds, refresh=args.refresh)
    ok = sum(1 for s, _ in totals.values() if s == "OK")
    total_ind = sum(c for s, c in totals.values() if s == "OK")
    dt = time.time() - t0
    print("Done: %d/%d feeds OK, %d indicators cached in %.1fs." %
          (ok, len(feeds), total_ind, dt))
    if args.json:
        print(json.dumps({k: {"status": s, "count": c} for k, (s, c) in totals.items()}, indent=2))


def cmd_lookup(args):
    if not os.path.exists(DB_PATH):
        sys.stderr.write("No cache found. Run:  python3 ti.py aggregate\n")
        sys.exit(2)
    con = db_connect()
    mn, mx, tot = cache_age(con)
    if mx:
        age_h = (time.time() - time.mktime(time.strptime(mx, "%Y-%m-%dT%H:%M:%SZ"))) / 3600
        if age_h > 36:
            sys.stderr.write("  (cache is %.0fh old -- consider 'aggregate --refresh')\n" % age_h)
    results = [lookup_one(con, ioc) for ioc in args.iocs]
    if args.report:
        os.makedirs(args.out, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        md = os.path.join(args.out, "ti-lookup-%s.md" % stamp)
        cf = os.path.join(args.out, "ti-lookup-%s.csv" % stamp)
        with open(md, "w", encoding="utf-8") as f:
            f.write(to_markdown(results, con))
        write_csv(results, cf)
        for r in results:
            print_result(r)
        print("\nReport written:\n  %s\n  %s" % (md, cf))
    elif args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print_result(r)
    con.close()


def build_parser():
    p = argparse.ArgumentParser(
        prog="ti.py", description="Aggregate free threat-intel feeds and look up IOCs.")
    sub = p.add_subparsers(dest="cmd", required=True)

    pf = sub.add_parser("feeds", help="list the curated feed registry")
    pf.set_defaults(func=cmd_feeds)

    pa = sub.add_parser("aggregate", help="download + normalize feeds into the local cache")
    pa.add_argument("--refresh", action="store_true", help="force re-download of every feed")
    pa.add_argument("--only", help="comma-separated feed keys to include (see 'feeds')")
    pa.add_argument("--exclude", help="comma-separated feed keys to skip")
    pa.add_argument("--json", action="store_true", help="print machine-readable per-feed status")
    pa.set_defaults(func=cmd_aggregate)

    pl = sub.add_parser("lookup", help="check indicators against the cache")
    pl.add_argument("iocs", nargs="+", help="IP, domain, URL, or CVE (defanged OK)")
    pl.add_argument("--json", action="store_true", help="machine-readable output")
    pl.add_argument("--report", action="store_true", help="write a Markdown + CSV report")
    pl.add_argument("--out", default=".", help="output dir for --report (default: .)")
    pl.set_defaults(func=cmd_lookup)
    return p


def main():
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
