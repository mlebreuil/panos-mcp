"""Scenarios: named worlds composed of samples, with `extends` and `default_response`.

Lookup order for a request key: own `responses` -> parent chain (nearest first) ->
nearest `default_response` in the chain -> `default_on_miss`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from panos_mcp.samples.layout import key_for_request
from panos_mcp.samples.metadata import SampleRequest


class ScenarioError(Exception):
    pass


class ScenarioResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request: SampleRequest
    sample: str


class Scenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    description: str
    panos_version: str
    extends: str | None = None
    responses: list[ScenarioResponse] = Field(default_factory=list)
    default_response: str | None = None
    default_on_miss: Literal["error_not_found", "fail_test"] = "error_not_found"


def scenario_path(root: Path, name: str) -> Path:
    return root / "scenarios" / f"{name}.json"


def load_scenario(root: Path, name: str) -> Scenario:
    path = scenario_path(root, name)
    if not path.is_file():
        raise ScenarioError(f"unknown scenario {name!r} (no {path})")
    return Scenario.model_validate(json.loads(path.read_text("utf-8")))


class ResolvedScenario:
    """A scenario with its `extends` chain flattened into one lookup table."""

    def __init__(self, root: Path, name: str) -> None:
        chain: list[Scenario] = []
        seen: list[str] = []
        current: str | None = name
        while current is not None:
            if current in seen:
                raise ScenarioError(f"scenario inheritance cycle: {' -> '.join([*seen, current])}")
            seen.append(current)
            scenario = load_scenario(root, current)
            chain.append(scenario)
            current = scenario.extends
        self.name = name
        self.chain = chain
        self.root_scenario = chain[0]
        self.table: dict[str, str] = {}
        for scenario in reversed(chain):  # parents first, children override
            for response in scenario.responses:
                key = key_for_request(response.request.model_dump(exclude_none=True))
                self.table[key] = response.sample
        self.default_response = next(
            (s.default_response for s in chain if s.default_response), None
        )
        self.default_on_miss = chain[0].default_on_miss

    def lookup(self, key: str) -> str | None:
        return self.table.get(key, self.default_response)

    def sample_ids(self) -> set[str]:
        ids = set(self.table.values())
        if self.default_response:
            ids.add(self.default_response)
        return ids


def list_scenarios(root: Path) -> list[str]:
    folder = root / "scenarios"
    return sorted(p.stem for p in folder.glob("*.json")) if folder.is_dir() else []
