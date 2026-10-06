"""Load workflow, atomic and guardrail files from the repository."""
from __future__ import annotations

import copy
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

COMMON_INPUTS = {"incident_id", "dry_run"}


def find_root(start: Path | None = None) -> Path:
    here = (start or Path(__file__)).resolve()
    for candidate in [here, *here.parents]:
        if (candidate / "workflows").is_dir() and (candidate / "atomic").is_dir():
            return candidate
    raise FileNotFoundError("repository root (with workflows/ and atomic/) not found")


ROOT = find_root()


def load_yaml(path: Path) -> Any:
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


@lru_cache(maxsize=1)
def atomics() -> dict[str, dict]:
    return {p.parent.name: load_yaml(p) for p in sorted((ROOT / "atomic").glob("*/atomic.yaml"))}


def workflow_ids() -> list[str]:
    return sorted(p.parent.name for p in (ROOT / "workflows").glob("*/workflow.yaml"))


def load_workflow(workflow_id: str) -> dict:
    return load_yaml(ROOT / "workflows" / workflow_id / "workflow.yaml")


def scenario_paths(workflow_id: str) -> list[Path]:
    return sorted((ROOT / "workflows" / workflow_id / "scenarios").glob("*.yaml"))


def atomic_fields(atomic_id: str) -> set[str]:
    """Names a result record of this atomic may contain: its inputs and outputs."""
    spec = atomics()[atomic_id]
    names = {i["name"] for i in spec.get("inputs", [])} | {o["name"] for o in spec.get("outputs", [])}
    return names - COMMON_INPUTS


def workflow_atomics_by_phase(spec: dict) -> dict[str, list[str]]:
    phases: dict[str, list[str]] = {}
    for step in spec.get("steps", []):
        if "atomic" in step:
            phases.setdefault(step["phase"], [])
            if step["atomic"] not in phases[step["phase"]]:
                phases[step["phase"]].append(step["atomic"])
    return phases


def deep_merge(base: Any, override: Any) -> Any:
    if isinstance(base, dict) and isinstance(override, dict):
        out = copy.deepcopy(base)
        for key, value in override.items():
            out[key] = deep_merge(out.get(key), value) if key in out else copy.deepcopy(value)
        return out
    return copy.deepcopy(override)


def load_guardrails(override: dict | None = None) -> dict:
    base = load_yaml(ROOT / "docs" / "deployment" / "guardrails.example.yaml")
    return deep_merge(base, override or {})
