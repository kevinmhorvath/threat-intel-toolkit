# Threat Intel Toolkit

A reusable, shareable bundle for **defensive IOC + vulnerability triage** built on free /
open-source intel. **Everything is fetched anonymously — no API keys, no registration** — so
any org can clone it and run it immediately. It ships a subagent and two complementary skills:

- **`agents/threat-intel-analyst.md`** — a subagent you invoke for multi-step investigations
  ("triage these 20 IOCs from the alert", "how bad is CVE-2024-3400?"). It routes each
  indicator to the right skill and layers analyst judgment on top of the raw results.
- **`skills/threat-intel-lookup/`** — *indicator-centric*. A single stdlib-only script
  (`ti.py`) that **aggregates** 10 curated free feeds into a local SQLite cache and **looks
  up** IPs, domains, URLs, and CVEs against it. Triggers on its own whenever you drop an IOC.
- **`skills/exploit-availability-check/`** — *vulnerability-centric*. Given a CVE, it rates
  **exploit/PoC maturity** and in-the-wild status via CISA KEV, EPSS, Metasploit, Nuclei,
  Exploit-DB, and the nomi-sec/trickest PoC aggregators. Answers "how weaponized is this?"

The two skills meet at the CVE: threat-intel-lookup gives a fast KEV verdict inside a mixed
IOC batch; exploit-availability-check goes deep on a specific CVE's exploit maturity. Use
either skill directly, or let the agent orchestrate both.

## What it covers

IPs, domains, URLs, and CVEs — checked against CISA KEV, abuse.ch Feodo Tracker, blocklist.de,
stamparm/ipsum, Emerging Threats Open, GreenSnow, SANS DShield, Spamhaus DROP,
Phishing.Database, and the Tor exit list. ~435k indicators, ~13s to build the cache. URLs are
matched by their host, so a URL lookup catches domain/IP hits.

**File hashes are not covered** — the reputable free hash feeds now require an API key, which
this toolkit deliberately avoids to stay key-free. `skills/threat-intel-lookup/references/feeds.md`
explains how a team can add a key-based hash feed locally if they want one.

## Feeds & licenses

All feeds are free for defensive use and fetched anonymously. The toolkit references feed URLs
and fetches at runtime — it does **not** re-host or bundle any feed's data.

| Feed | IOC | License / terms |
|---|---|---|
| CISA KEV | CVE | US gov, public domain |
| abuse.ch Feodo Tracker | IP | CC0-1.0 |
| stamparm/ipsum | IP | Unlicense |
| Emerging Threats Open | IP | BSD |
| Phishing.Database | domain | MIT |
| SANS DShield | CIDR | free |
| Spamhaus DROP | CIDR | free (published for filtering) |
| Tor Project exit list | IP | free (context) |
| blocklist.de | IP | free for use (no formal license text) |
| GreenSnow | IP | free for use (no formal license text) |

`blocklist.de` and `greensnow` are free and standard in open blocklist tooling but publish no
formal license file; if your legal review requires an explicit license on every source, drop
them: `python3 ti.py aggregate --exclude blocklist_de,greensnow`. Feeds intentionally excluded
(abuse.ch key-gated feeds, CINS Army, OpenPhish) and why are documented in `references/feeds.md`.

## Quick start

```bash
# Indicator triage (IPs / domains / URLs / CVEs)
cd skills/threat-intel-lookup/scripts
python3 ti.py feeds                 # see the feed registry + licenses
python3 ti.py aggregate             # build the local cache (~13s)
python3 ti.py lookup 45.155.205.233 "evil[.]tld" CVE-2024-3400
python3 ti.py lookup 1.2.3.4 evil.tld --report --out ./deliverables   # md + csv artifact
```

For a specific CVE's exploit maturity, use the second skill — the analyst agent does this
automatically for CVEs; to run it directly, follow `skills/exploit-availability-check/SKILL.md`
(it writes its bundled script to a temp file and runs it, e.g. `exploit_check.py CVE-2024-3400`).

Requires only Python 3.8+ (standard library — no pip installs). Defanged input
(`1[.]2[.]3[.]4`, `hxxp://`) is handled automatically.

## Verdicts

🔴 MALICIOUS (3+ independent feeds) · 🔴 EXPLOITED (CVE on CISA KEV) · 🟠 SUSPICIOUS (1–2
feeds) · 🟡 CONTEXT (Tor/DROP) · ⚪ CLEAN (no feed lists it — *not* proof of safety).

## Install as a Claude Code plugin

This repo doubles as its own single-plugin marketplace (`.claude-plugin/marketplace.json` +
`.claude-plugin/plugin.json`), so an org can one-click install it:

```
/plugin marketplace add kevinmhorvath/threat-intel-toolkit
/plugin install threat-intel-toolkit@threat-intel-marketplace
```

(If you fork or rename the repo, update the path in the first command and `owner.name` in
`.claude-plugin/marketplace.json` to match.) You can also just zip the folder and share it, or
install the skill standalone.

New feeds and fixes are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for how to add a feed.

## Health checks (CI)

`.github/workflows/feed-healthcheck.yml` runs every Monday (and on demand / on script changes)
and smoke-tests **both skills' sources**, failing the run — and notifying you — if anything is
unreachable, empty, or no longer parses, before it reaches users:

- **threat-intel-lookup** — `skills/threat-intel-lookup/scripts/healthcheck.py` fetches and
  parses all 10 feeds, then an end-to-end `aggregate` + known-CVE lookup.
- **exploit-availability-check** — `skills/exploit-availability-check/scripts/healthcheck.py`
  verifies KEV, EPSS, Metasploit, Nuclei, Exploit-DB, nomi-sec, and trickest all return a
  known canary CVE (Log4Shell), then an end-to-end assessment.

Run either yourself any time: `python3 skills/<skill>/scripts/healthcheck.py`.

## Extending

To go beyond the curated set (e.g. the Bert-JanP or kraloveckey feed hubs, or a key-based hash
feed), see `skills/threat-intel-lookup/references/feeds.md` — adding a feed is a one-line
registry entry, and a new format is a small parser branch.

## Scope & license

Defensive prioritization only. It reports what public feeds already say; it never contacts,
scans, or attacks an indicator, and a CLEAN result is never a safety guarantee. The toolkit's
own code is released under the MIT License (see `LICENSE`). Each threat feed remains under its
own license/terms (table above and `references/feeds.md`).
