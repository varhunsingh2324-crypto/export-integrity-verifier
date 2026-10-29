from pathlib import Path

import pytest

from eguard.config import load_policy
from eguard.models import Verdict


def test_policy_has_required_keys() -> None:
    policy = load_policy()
    assert {"l3", "l4", "l5", "exit_codes"} <= policy.keys()
    assert 0 < policy["l5"]["detect_fraction"] < 1
    assert 0 < policy["l5"]["confidence"] < 1
    assert policy["l4"]["chunk_rows"] > 0


def test_policy_exit_codes_match_verdicts() -> None:
    codes = load_policy()["exit_codes"]
    assert codes == {v.value: v.exit_code for v in Verdict}


def test_missing_policy_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_policy(tmp_path / "nope.yaml")
