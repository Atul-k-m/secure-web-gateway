"""Run a policy test suite: expected decisions for a policy, checked offline.

    python -m swg check-policy                       # tests/policy_cases.yaml
    python -m swg check-policy my_cases.yaml

Change config/policy.yaml, run this, and see which expectations broke before
any user does. Each case gives a user, a URL and optionally an upload or a
download; see tests/policy_cases.yaml for the format.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from . import dlp, filetypes
from .directory import ANONYMOUS, Directory
from .policy import Policy

# Minimal byte strings with the right signatures (they do nothing).
SAMPLES = {
    "exe": b"MZ\x90\x00\x03\x00\x00\x00",
    "elf": b"\x7fELF\x02\x01\x01\x00",
    "zip": b"PK\x03\x04\x14\x00",
    "pdf": b"%PDF-1.7\n",
}
DEFAULT_CONTENT_TYPE = {"exe": "application/octet-stream", "elf": "application/octet-stream",
                        "zip": "application/zip", "pdf": "application/pdf"}

# A 12-digit number with a valid Verhoeff check digit, built here so the
# suite never contains anyone's real Aadhaar number.
SYNTHETIC_AADHAAR = "23456789012" + dlp.verhoeff_digit("23456789012")


@dataclass
class CaseResult:
    name: str
    expected: str
    actual: str
    reason: str  # the rule or exemption that produced `actual`

    @property
    def passed(self) -> bool:
        return self.expected == self.actual


def evaluate(policy: Policy, directory: Directory, case: dict) -> tuple[str, str]:
    """What the gateway would do with this case: (result, reason)."""
    user = case.get("user", "anonymous")
    identity = ANONYMOUS if user == "anonymous" else directory.lookup(user)
    url = urlsplit(case["url"])
    host = url.hostname or ""

    decision = policy.decide(host, identity)
    if decision.action == "block":
        return "block", decision.rule or "default action"
    if url.scheme == "https" and not decision.inspect:
        return "no-inspect", decision.inspect_reason or ""
    if decision.action == "caution":
        return "caution", decision.rule or "default action"

    if "download" in case:
        kind = case["download"]
        file_type = filetypes.detect(case.get("content_type", DEFAULT_CONTENT_TYPE[kind]), SAMPLES[kind])
        verdict = policy.check_file_type(host, identity, file_type, "download")
        return verdict.action, verdict.rule or "default action"
    if "upload_file" in case:
        file_type = filetypes.detect(None, SAMPLES[case["upload_file"]])
        verdict = policy.check_file_type(host, identity, file_type, "upload")
        return verdict.action, verdict.rule or "default action"
    if "upload_text" in case:
        text = case["upload_text"].replace("{aadhaar}", SYNTHETIC_AADHAAR)
        found = {f.detector for f in dlp.scan_text(text)}
        verdict = policy.check_dlp(host, identity, found)
        return verdict.action, verdict.rule or ("no sensitive data" if not found else "default action")
    return decision.action, decision.rule or "default action"


def run(
    cases_path: Path,
    policy_path: Path = Path("config/policy.yaml"),
    categories_path: Path = Path("config/categories.yaml"),
    directory_path: Path = Path("config/directory.yaml"),
) -> list[CaseResult]:
    policy = Policy.load(policy_path, categories_path)
    directory = Directory.load(directory_path)
    cases = yaml.safe_load(Path(cases_path).read_text(encoding="utf-8")) or []
    results = []
    for case in cases:
        actual, reason = evaluate(policy, directory, case)
        results.append(CaseResult(case["name"], case["expect"], actual, reason))
    return results


def report(results: list[CaseResult]) -> str:
    lines = []
    for r in results:
        mark = "PASS" if r.passed else "FAIL"
        detail = f"{r.actual}" if r.passed else f"expected {r.expected}, got {r.actual}"
        lines.append(f"{mark}  {r.name}  [{detail}; {r.reason}]")
    passed = sum(r.passed for r in results)
    lines.append(f"\n{passed}/{len(results)} cases passed ({100 * passed / max(len(results), 1):.1f}%)")
    return "\n".join(lines)
