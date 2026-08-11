#!/usr/bin/env python3
"""
healthcheck.py -- smoke-test every feed in the registry.

Fetches each feed fresh, parses it, and counts the records produced. Exits non-zero
if any feed fails to download or parses to zero records -- so a scheduled CI run
(see .github/workflows/feed-healthcheck.yml) catches dead URLs or format changes
before they reach users.

Usage:
  python3 healthcheck.py            # check all feeds, human-readable table
  python3 healthcheck.py --json     # machine-readable summary
  python3 healthcheck.py --only feodo,cisa_kev

Exit codes: 0 = all feeds healthy, 1 = one or more feeds failed.
"""
import argparse
import json
import sys

import ti  # same directory: reuse the registry, fetch(), and parsers


def check_feed(feed):
    try:
        data = ti.fetch(feed, refresh=True)
    except Exception as e:  # noqa: BLE001
        return {"key": feed["key"], "status": "FETCH_ERROR", "records": 0,
                "bytes": 0, "detail": str(e)}
    if not data:
        return {"key": feed["key"], "status": "NO_DATA", "records": 0,
                "bytes": 0, "detail": "empty or unreachable"}
    try:
        records = sum(1 for _ in ti.parse_feed(feed, data))
    except Exception as e:  # noqa: BLE001
        return {"key": feed["key"], "status": "PARSE_ERROR", "records": 0,
                "bytes": len(data), "detail": str(e)}
    status = "OK" if records > 0 else "ZERO_RECORDS"
    return {"key": feed["key"], "status": status, "records": records,
            "bytes": len(data), "detail": ""}


def main():
    ap = argparse.ArgumentParser(description="Smoke-test the threat-intel feed registry.")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--only", help="comma-separated feed keys to check")
    args = ap.parse_args()

    feeds = ti.FEEDS
    if args.only:
        want = {k.strip() for k in args.only.split(",")}
        feeds = [f for f in feeds if f["key"] in want]

    results = [check_feed(f) for f in feeds]
    failed = [r for r in results if r["status"] != "OK"]

    if args.json:
        print(json.dumps({"results": results, "failed": [r["key"] for r in failed]}, indent=2))
    else:
        print("%-14s %-13s %10s %12s  %s" % ("FEED", "STATUS", "RECORDS", "BYTES", "DETAIL"))
        for r in results:
            print("%-14s %-13s %10d %12d  %s" %
                  (r["key"], r["status"], r["records"], r["bytes"], r["detail"]))
        print("\n%d/%d feeds healthy." % (len(results) - len(failed), len(results)))

    if failed:
        sys.stderr.write("FAILED: " + ", ".join(r["key"] for r in failed) + "\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
