from __future__ import annotations

from typing import Any, Dict
import yaml


class RuleLoadError(ValueError):
    pass


def load_rule_file(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except FileNotFoundError as e:
        raise RuleLoadError(f"Rule file not found: {path}") from e
    except Exception as e:
        raise RuleLoadError(f"Failed to parse YAML: {path} ({e})") from e

    if not isinstance(data, dict):
        raise RuleLoadError(f"Rule file root must be a dict/object: {path}")
    return data
