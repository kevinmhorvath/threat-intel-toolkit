# Feed catalog & how to extend

The engine's feed registry lives in `scripts/ti.py` as the `FEEDS` list. Each entry is a
small dict; adding a feed is a one-line append. This file explains the schema, the curated
core set and its licenses, and how to bolt on extra feeds (community hubs, or a key-based
hash feed) when you want broader coverage.

Design principle for this toolkit: **every shipped feed is fetched anonymously and carries a
license that permits free defensive use.** No API keys, no registration. That keeps the
plugin friction-free to install and clean for any org — including commercial — to adopt.

## Registry schema

```python
{
  "key": "feodo",                 # unique short id (used by --only/--exclude and in output)
  "name": "abuse.ch Feodo ...",   # human-readable
  "type": "ipv4",                 # primary IOC type: ipv4 | domain | url | cidr | cve
  "fmt": "feodo_json",            # parser in parse_feed(); see "Adding a parser" below
  "category": "botnet-c2",        # shown in verdicts; drives the CONTEXT special-case
  "license": "CC0-1.0",           # license / terms summary
  "url":  "https://...",          # the raw feed URL (fetched anonymously)
  "attr": "abuse.ch Feodo"        # attribution
}
```

Built-in parsers (`fmt` values): `ip_lines`, `ipsum`, `feodo_json`, `dshield`,
`spamhaus_drop`, `domain_lines`, `cisa_kev`.

## Curated core set (the default 10) and licenses

Chosen for reliability, active maintenance, low false-positive noise, and — critically for an
openly shared plugin — a license that permits free defensive use without registration.

| key | source | IOC | license / terms |
|---|---|---|---|
| `cisa_kev` | CISA Known Exploited Vulnerabilities | CVE | US gov work, public domain |
| `feodo` | abuse.ch Feodo Tracker | IP | CC0-1.0 |
| `blocklist_de` | blocklist.de | IP | free for use; no formal license text, widely used defensively |
| `ipsum` | stamparm/ipsum (level 3) | IP | Unlicense (public domain) |
| `et_compromised` | Emerging Threats Open — compromised IPs | IP | BSD (ET Open ruleset) |
| `greensnow` | GreenSnow | IP | free for use; no formal license text |
| `dshield` | SANS ISC / DShield block | CIDR | free for use |
| `spamhaus_drop` | Spamhaus DROP v4 | CIDR | free; published expressly for filtering |
| `phishdb` | mitchellkrogza/Phishing.Database | domain | MIT |
| `tor_exit` | Tor Project exit list | IP | free (context only) |

Note on `blocklist_de` and `greensnow`: both are free, widely used (FireHOL, CrowdSec, etc.),
and intended for exactly this defensive use, but neither publishes a formal license file — they
simply state the data is free to use. If your org's legal review requires an explicit license
on every dependency, drop them with `--exclude blocklist_de,greensnow` (or remove them from the
`FEEDS` list); the other eight all have explicit permissive terms.

### Feeds deliberately NOT included

- **abuse.ch URLhaus / ThreatFox / MalwareBazaar** — excellent feeds, but abuse.ch now
  requires an Auth-Key for these. Excluded to keep the toolkit key-free. See "Adding a
  key-based hash feed" below to opt back in locally.
- **CINS Army / CI Army** — the public text file says "use as you see fit," but it is a
  commercial vendor (Sentinel IPS) product whose EULA restricts distributing it "with other
  products (commercial or otherwise) without prior written permission." Excluded to avoid
  license ambiguity for downstream orgs.
- **OpenPhish community feed** — its terms prohibit commercial use and redistribution/
  derivative works without written consent. Excluded for the same reason; Phishing.Database
  (MIT) covers phishing with a clean license.

## ipsum confidence levels

`stamparm/ipsum` publishes `levels/1.txt` … `levels/8.txt`, where the number is how many
underlying blocklists agree. The registry uses **level 3** (a good precision/recall balance).
For a tighter, higher-confidence set change the `ipsum` URL to `levels/5.txt` or higher; for
broader coverage drop to `levels/2.txt`.

## Adding a key-based hash feed (optional, opt-in)

The toolkit ships key-free, so hashes aren't covered by default. A team that wants hash and
malware-URL lookups can add abuse.ch back locally:

1. Create a free account at abuse.ch and generate an Auth-Key.
2. Append a feed to `FEEDS`, e.g. ThreatFox recent CSV:
   `{"key":"threatfox","name":"abuse.ch ThreatFox","type":"cve","fmt":"threatfox_csv", ...
     "url":"https://threatfox.abuse.ch/export/csv/recent/", "license":"CC0 (Auth-Key req.)"}`
3. Add an Auth-Key header in `fetch()` when the feed needs it (read the key from an env var so
   it never lands in the repo), and add a `threatfox_csv` branch to `parse_feed()`.

Keeping this out of the default build is intentional — it preserves the "clone and run, no
signup" experience for everyone who just wants IP/domain/URL/CVE coverage.

## Extending to the big community hubs

Two well-known GitHub hubs aggregate hundreds of feeds. They're higher-coverage but noisier
(stale mirrors, dead links, inconsistent formats), so treat them as an opt-in expansion.

- **Bert-JanP/Open-Source-Threat-Intel-Feeds** — a clean CSV index (`ThreatIntelFeeds.csv`)
  of feed URLs by type. To ingest: fetch that CSV, and for each row whose type is IP/Domain/
  URL, append a `FEEDS` entry with `fmt` = `ip_lines` / `domain_lines`. Check each source's
  license before shipping it in a redistributed build.
- **kraloveckey / the `threat-intelligence-feeds` GitHub topic** — 300+ feeds; useful as a
  discovery source. Cherry-pick maintained, clearly-licensed ones rather than ingesting
  wholesale.

Recommended pattern for a broad build: keep the curated core as the trusted tier (drives the
MALICIOUS "3+ feeds" threshold), and add hub feeds as a separate lower-weight tier so a hit
that *only* appears in noisy hubs reads as SUSPICIOUS, not MALICIOUS. A simple way to do that
today is to tag added feeds with a distinct `category` and note in the verdict that the hit
came from the broad tier.

## Adding a parser

If a new feed's format isn't covered, add a branch to `parse_feed(feed, data)` keyed on a new
`fmt` string. A parser is a generator that yields either:

- `("indicator", value, ioc_type, extra_dict)` — a single IOC, or
- `("cidr", "1.2.3.0/24", extra_dict)` — a network range (matched by IP membership at lookup).

Keep parsers defensive: skip comment/blank lines, wrap JSON/CSV parsing in try/except, and
validate IPs with `ipaddress` so one malformed line can't break a whole feed.
