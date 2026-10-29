"""Loading of policy configuration (thresholds live in config/policy.yaml)."""

from pathlib import Path
from typing import Any

import yaml

DEFAULT_POLICY = Path(__file__).resolve().parents[2] / "config" / "policy.yaml"


def load_policy(path: Path = DEFAULT_POLICY) -> dict[str, Any]:
    with path.open(encoding="utf-8") as fh:
        policy = yaml.safe_load(fh)
    if not isinstance(policy, dict):
        raise ValueError(f"{path}: policy must be a mapping")
    return policy
