"""Phase 3: the shipped policy decides every case in tests/policy_cases.yaml
the way the case expects."""

from pathlib import Path

import pytest
import yaml

from swg import policytest
from swg.directory import Directory
from swg.policy import Policy

ROOT = Path(__file__).resolve().parent.parent
CASES = yaml.safe_load((ROOT / "tests/policy_cases.yaml").read_text(encoding="utf-8"))
POLICY = Policy.load(ROOT / "config/policy.yaml", ROOT / "config/categories.yaml")
DIRECTORY = Directory.load(ROOT / "config/directory.yaml")


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_shipped_policy(case):
    actual, reason = policytest.evaluate(POLICY, DIRECTORY, case)
    assert actual == case["expect"], f"{case['name']}: got {actual} ({reason})"
