# Contributing

Thanks for helping improve the Threat Intel Toolkit. The plugin ships two skills —
`threat-intel-lookup` (indicator feeds) and `exploit-availability-check` (CVE exploit
maturity) — plus the `threat-intel-analyst` agent that routes between them. The most common
contribution is **adding a feed** to `threat-intel-lookup`, so that's covered in full below.
Bug fixes, parser improvements, and doc tweaks are equally welcome — open a PR.

## Ground rules

- **Defensive use only.** This toolkit reports what public feeds already say so defenders can
  prioritize. It must never contact, scan, probe, or attack indicators, and must not include
  offensive tooling.
- **Key-free by default.** The shipped feed set is fetched anonymously — no API keys, no
  registration. That's what makes it friction-free to adopt. A feed that requires a key can be
  documented as an optional local add-on (see `references/feeds.md`) but should not be in the
  default `FEEDS` list.
- **License matters.** Only add a feed whose terms permit free defensive use and — ideally —
  redistribution-by-reference. We fetch feed URLs at runtime and never re-host feed data, but
  a feed with a restrictive or ambiguous license (e.g. non-commercial only, "no redistribution"
  clauses, or a vendor EULA) should be left out. When in doubt, ask in an issue first.

## How to add a feed

Everything lives in `skills/threat-intel-lookup/scripts/ti.py`.

### 1. Add a registry entry

Append a dict to the `FEEDS` list:

```python
{
  "key": "my_feed",                 # unique short id (used by --only/--exclude and in output)
  "name": "My Feed (what it tracks)",
  "type": "ipv4",                   # primary IOC type: ipv4 | domain | url | cidr | cve
  "fmt": "ip_lines",                # a parser in parse_feed() — reuse one if the format matches
  "category": "attacker",           # shown in verdicts; use an existing category where sensible
  "license": "MIT",                 # the feed's license / terms summary
  "url":  "https://example.com/badips.txt",   # the raw feed URL (must be fetchable anonymously)
  "attr": "Example Project"         # attribution
}
```

Reuse an existing `fmt` when the format matches — most IP blocklists are one-IP-per-line
(`ip_lines`), most domain lists are `domain_lines`. If your feed's format is new, add a parser
(step 2).

### 2. (Only if needed) add a parser

If no existing `fmt` fits, add a branch to `parse_feed(feed, data)` keyed on a new `fmt`
string. A parser is a generator that yields either:

- `("indicator", value, ioc_type, extra_dict)` — a single IOC, or
- `("cidr", "1.2.3.0/24", extra_dict)` — a network range (matched by IP membership at lookup).

Keep parsers defensive so one malformed line can't break a whole feed:

- skip blank and comment lines (`clean_lines()` already does this for text feeds),
- wrap `json.loads` / `csv` parsing in `try/except`,
- validate IPs with `ipaddress` before yielding them.

### 3. Test it

From `skills/threat-intel-lookup/scripts/`:

```bash
python3 ti.py feeds                        # confirm your feed shows up with the right license
python3 healthcheck.py --only my_feed      # confirm it fetches AND parses to > 0 records
python3 ti.py aggregate --only my_feed     # build a cache from just your feed
python3 ti.py lookup <a-known-value-from-your-feed>   # confirm it resolves
```

`healthcheck.py` is what CI runs weekly — if your feed passes it locally, it'll pass in CI.

### 4. Document & open a PR

- Add a row to the feed table in `references/feeds.md` (and the README table if it's a
  default feed), including the license.
- If you're deliberately *not* defaulting it on (e.g. it's noisy or key-based), note that.
- In the PR description, link the feed's terms/license page and say what it adds that the
  existing feeds don't.

## Reporting a feed problem

If a feed is dead, changed format, or should be removed on license grounds, open an issue using
the **Feed request / problem** template and include the feed URL and what you're seeing.
