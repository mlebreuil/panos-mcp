"""SC-002: answers for the question set match the web interface in >= 95% of cases (live)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tests.integration.live.conftest import LiveServer

pytestmark = pytest.mark.anyio
QUESTIONS = json.loads((Path(__file__).parent / "questions.json").read_text())["questions"]


def test_question_set_shape() -> None:
    areas = [q["area"] for q in QUESTIONS]
    assert len(QUESTIONS) >= 30
    assert all(areas.count(a) >= 10 for a in ("inventory", "policy", "objects"))


def _dig(data: Any, path: str) -> Any:
    for part in path.split("."):
        data = data[int(part)] if isinstance(data, list) else data[part]
    return data


def matches(data: dict[str, Any], expected: dict[str, Any]) -> bool:
    if "total" in expected:
        return bool(data.get("total") == expected["total"])
    if "field" in expected:
        return bool(_dig(data, expected["field"]) == expected["equals"])
    if "items_contain" in expected:
        want = expected["items_contain"]
        items = data["items"] if isinstance(data["items"], list) else [data["items"]]
        return any(all(item.get(k) == v for k, v in want.items()) for item in items)
    raise ValueError(f"unknown expectation {expected}")


async def test_match_rate(live: LiveServer) -> None:
    answered = [q for q in QUESTIONS if q["expected_answer"] is not None]
    if not answered:
        pytest.skip("no expected answers filled in yet (see questions.json)")
    hits = 0
    for q in answered:
        result = await live.call(q["tool"], **q["expected_args"])
        if not result.is_error and result.structured_content is not None:
            hits += matches(result.structured_content, q["expected_answer"])
    rate = hits / len(answered)
    print(f"SC-002 match rate: {rate:.0%} ({hits}/{len(answered)})")
    assert rate >= 0.95
