---
name: threat-intel-lookup
description: >-
  Aggregate free / open-source threat-intel feeds into a local cache and check indicators
  (IPs, domains, URLs, CVEs) against them. Trigger whenever the user drops an IP, domain,
  URL, or CVE and asks "is this malicious", "is this a known bad IP", "check this indicator
  / IOC", "is this domain on any blocklist", "who's flagging this", "enrich these
  indicators", or pastes a list of IOCs from an alert, SIEM, firewall log, phishing email,
  or incident. Also use to build or refresh a local blocklist from open feeds ("aggregate
  the threat feeds", "update my IOC cache", "pull the latest feeds", "give me a deduped
  blocklist"). Handles defanged indicators (1[.]2[.]3[.]4, hxxp://). Every feed is fetched
  anonymously — no API keys. Use proactively during alert triage, phishing analysis, log
  review, or IOC enrichment even if the user doesn't say "threat intel."
---

# Threat Intel Lookup

Answer one question fast and defensibly: **does any reputable free feed flag this indicator, and how strongly?** This is a defensive triage aid — it aggregates *already-public* open-source threat intel so a defender can prioritize. It never contacts, scans, or attacks an indicator; it only reports what public feeds already say.

The whole engine is one stdlib-only script: `scripts/ti.py`. It has three subcommands — `feeds`, `aggregate`, `lookup`. **Every feed is fetched anonymously — no API key, no registration** — so it works out of the box and is safe to share openly.

## Sources (curated core set, all anonymous & openly licensed)

| Feed | IOC types | Category | License |
|---|---|---|---|
| CISA KEV | CVE | exploited in the wild | public domain |
| abuse.ch Feodo Tracker | IP | botnet C2 | CC0 |
| blocklist.de | IP | attacking hosts | free (defensive) |
| stamparm/ipsum | IP | aggregated (≥3 lists) | Unlicense |
| Emerging Threats Open | IP | compromised hosts | BSD |
| GreenSnow | IP | attackers | free (defensive) |
| SANS DShield | CIDR | top attacker netblocks | free |
| Spamhaus DROP | CIDR | hijacked/leased netblocks | free |
| Phishing.Database | domain | active phishing | MIT |
| Tor Project | IP | exit nodes (context, not malicious) | free |

Run `python3 scripts/ti.py feeds` to print this registry with each feed's key and license.

**Coverage note.** This anonymous set covers **IPs, domains, URLs, and CVEs**. URLs are matched by their host (domain/IP), so a URL lookup catches domain and IP feed hits. **File hashes are not covered** — the reputable free hash feeds (abuse.ch MalwareBazaar/ThreatFox) now require an API key, which this toolkit deliberately avoids. If a team wants hash lookups, `references/feeds.md` explains how to add an abuse.ch key-based feed locally.

To extend beyond the core set (e.g. the Bert-JanP or kraloveckey feed hubs), see `references/feeds.md` — adding a feed is a one-line registry entry.

## Workflow

### 1. Make sure the cache is fresh

The cache lives at `~/.cache/ti-aggregator/ti.db`. Lookups read it; they don't hit the network. Build/refresh it with:

```bash
python3 scripts/ti.py aggregate            # ~13s, ~435k indicators; re-uses feed bodies cached for 12h
python3 scripts/ti.py aggregate --refresh  # force re-download of every feed
```

If `lookup` reports no cache, run `aggregate` first. If the cache is >36h old the script warns you — refresh it before triaging fresh alerts. For a quick single-source build use `--only feodo,cisa_kev` or skip the large phishing list with `--exclude phishdb`.

### 2. Look up indicators

Pass any mix of IPs, domains, URLs, and CVEs. Defanged input (`1[.]2[.]3[.]4`, `hxxp://bad[.]tld/x`, `evil(dot)com`) is normalized automatically, so paste straight from an email or report.

```bash
python3 scripts/ti.py lookup 45.155.205.233
python3 scripts/ti.py lookup "evil[.]tld" "hxxp://bad.tld/x" CVE-2024-3400
python3 scripts/ti.py lookup 1.2.3.4 --json                    # machine-readable
python3 scripts/ti.py lookup 1.2.3.4 evil.tld --report --out ./deliverables
```

The engine cross-indexes URLs to their host and checks IPs for membership in the DShield/Spamhaus CIDR ranges.

### 3. Read the verdict, then add judgment

The script assigns a verdict from how many *independent* feeds flag the indicator:

- 🔴 **MALICIOUS** — 3+ independent feeds agree. High confidence; block and hunt for related activity.
- 🔴 **EXPLOITED** — a CVE present on CISA KEV (exploited in the wild). Prioritize patching now.
- 🟠 **SUSPICIOUS** — 1–2 feeds. Real signal, but confirm with a second source before acting — single-feed hits include stale entries and the occasional false positive.
- 🟡 **CONTEXT** — only "context" infrastructure (e.g. a Tor exit node). Notable but not inherently malicious; weigh with other telemetry.
- ⚪ **CLEAN** — no curated feed lists it. **Not proof of safety** — feeds lag, and absence of a public hit means only that: no one has published it yet.

Add value beyond the raw count:
- **Weigh the feed to the context.** A phishing-domain hit matters most for a URL in a suspicious email; a botnet-C2 IP hit matters most for outbound firewall traffic. Say which feed fired and why it's relevant to what the user is investigating.
- **Recency.** abuse.ch Feodo and CISA KEV move fast; some IP blocklists carry stale entries. A single-feed hit on an old blocklist is weaker than a same-day Feodo/KEV hit. Re-`aggregate --refresh` for anything time-sensitive.
- **Tor and Spamhaus DROP are context, not conviction.** Traffic from a Tor exit or a DROP netblock is worth noting but isn't itself proof of compromise.

### 4. Output

**Default (chat triage):** lead with the verdict and which feeds fired, then a one-line "so what." For a batch, add a portfolio summary (how many malicious / suspicious / clean).

**Report deliverable (`--report`):** when the user wants an artifact for a ticket, IR timeline, or client folder, write `ti-lookup-<timestamp>.md` (summary table + per-indicator detail with recommendations) and a matching `.csv` (one row per indicator). In Cowork, write into the user's selected folder (or copy there) and present both files.

## Fallback (no shell)

If you can't run the script, fetch a single feed with your web tool and grep — e.g. Feodo `https://feodotracker.abuse.ch/downloads/ipblocklist.json`, CISA KEV `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`. The big aggregated feeds are best handled by the script.

## Guardrails

- Purpose is defensive prioritization: report which public feeds flag an indicator and how strongly, with the category and a recommendation. Do not contact, scan, probe, or attack any indicator.
- A CLEAN result never proves an indicator is safe; a single-feed SUSPICIOUS hit should be corroborated before blocking production traffic.
- Feeds carry their own licenses (see `references/feeds.md`); all shipped feeds are free for defensive use. The toolkit references feed URLs and fetches at runtime — it does not re-host or bundle feed data.
