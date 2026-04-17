#!/usr/bin/env python3
"""
fail_check.py — Exit 1 when the normalised JSON contains vulnerabilities
                at or above the configured FAIL_ON_SEVERITY threshold.

Called as the last step of scan-and-triage.yml to gate the build.

Usage:
    python scripts/fail_check.py normalised.json
    python scripts/fail_check.py normalised.json --threshold high
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

# Ensure the vuln-remediation root is on sys.path so this script can be called
# as "python vuln-remediation/scripts/fail_check.py" from any working directory.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scripts.utils.config import SEVERITY_ORDER, FAIL_ON_SEVERITY

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")


def _severity_index(sev: str) -> int:
    try:
        return SEVERITY_ORDER.index(sev.lower())
    except ValueError:
        return len(SEVERITY_ORDER)


def check(norm: dict, threshold: str) -> list[str]:
    """Return list of failure descriptions (empty = pass)."""
    threshold_idx = _severity_index(threshold)
    failures: list[str] = []

    for pkg in norm.get("dependency_vulnerabilities", []):
        for v in pkg.get("vulnerabilities", []):
            if _severity_index(v.get("severity", "low")) <= threshold_idx:
                cves = ", ".join(v.get("cve", [])) or "no CVE"
                failures.append(
                    f"{v['id']} [{v['severity'].upper()}] "
                    f"in {pkg['package']} ({cves})"
                )

    for v in norm.get("code_vulnerabilities", []):
        if _severity_index(v.get("severity", "low")) <= threshold_idx:
            files = ", ".join(o["file"] for o in v.get("occurrences", []))
            failures.append(
                f"{v['rule_id']} [{v['severity'].upper()}] in {files}"
            )

    return failures


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("normalised_json")
    parser.add_argument("--threshold", default=FAIL_ON_SEVERITY)
    args = parser.parse_args()

    norm     = json.loads(Path(args.normalised_json).read_text())
    failures = check(norm, args.threshold)

    if failures:
        log.error(
            "Build FAILED — %d vulnerability(s) at or above '%s':",
            len(failures), args.threshold,
        )
        for f in failures:
            log.error("  ✗ %s", f)
        sys.exit(1)

    log.info("Severity gate PASSED — no vulnerabilities at or above '%s'.",
             args.threshold)
    sys.exit(0)


if __name__ == "__main__":
    main()
