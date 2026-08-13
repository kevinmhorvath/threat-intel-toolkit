# Changelog

All notable changes to the Threat Intel Toolkit are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.1.0] - 2026-08-13

### Fixed

- **exploit-availability-check: fail-open on unreachable feeds.** When a source (CISA KEV, and
  now Metasploit, Exploit-DB, and Nuclei) could not be reached and no local cache existed, its
  empty index was indistinguishable from "checked, nothing found." A report could therefore show
  `In the wild: CISA KEV no` for a CVE whose KEV status was never actually verified, with the
  only warning going to stderr and never reaching the exported report. The index builders now
  track a per-feed availability flag that `assess()` propagates, and every output surface — chat,
  Markdown report, CSV, and `--json` — plus the recommendation text now distinguish three states:
  present, not-listed, and **unknown (feed unreachable)**. An unreachable source can no longer be
  rendered as a negative finding. Thanks to the reviewer who caught the KEV case during a run.

### Changed

- Synced the two copies of `exploit_check.py` (the standalone `exploit-availability-check` skill
  and the bundled copy in this toolkit) to byte-identical content, so a fix in one no longer
  drifts from the other. Standardized the presentation (emoji tier badges, star/`★` and em-dash
  usage) and completed the `--report` usage line in the script docstring.

## [1.0.0] - 2026-08-11

### Added

- Initial release: the `threat-intel-analyst` subagent plus two skills.
  - **threat-intel-lookup** — indicator reputation for IPs, domains, and URLs against ~435k
    entries from ten curated free feeds, aggregated into a local SQLite cache by a standard-library
    Python script, with a fast CISA KEV verdict for CVEs.
  - **exploit-availability-check** — CVE exploit/PoC maturity and in-the-wild status from CISA KEV,
    FIRST EPSS, Metasploit, Nuclei, Exploit-DB, and the nomi-sec / trickest PoC aggregators.
- Weekly GitHub Actions health check that smoke-tests every source for both skills and fails
  loudly if a feed becomes unreachable, empty, or unparseable.
- Single-plugin marketplace metadata for one-click install as a Claude Code plugin.
- Key-free by design — all feeds fetched anonymously; defensive use only.
