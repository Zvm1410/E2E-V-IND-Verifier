"""Election configuration loader (A3)."""

from __future__ import annotations

import json
from pathlib import Path

from app.models.candidate import Candidate
from app.models.election_config import ElectionConfig


class ElectionConfigError(Exception):
    """Raised when election.json is missing or invalid."""


def _require_mapping(data: object, path: str) -> dict:
    if not isinstance(data, dict):
        raise ElectionConfigError(f"Invalid field '{path}': expected an object.")
    return data


def _require_string(data: dict, key: str, path: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ElectionConfigError(f"Missing or invalid field '{path}'.")
    return value.strip()


def _require_int(data: dict, key: str, path: str) -> int:
    value = data.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ElectionConfigError(f"Missing or invalid field '{path}'.")
    return value


def _require_positive_int(data: dict, key: str, path: str) -> int:
    value = _require_int(data, key, path)
    if value <= 0:
        raise ElectionConfigError(f"Invalid field '{path}': must be a positive integer.")
    return value


def load_election_config(path: str | Path) -> ElectionConfig:
    config_path = Path(path)
    if not config_path.is_file():
        raise ElectionConfigError(f"Configuration file not found: {config_path}")

    try:
        with config_path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except json.JSONDecodeError as exc:
        raise ElectionConfigError(
            f"Configuration file is not valid JSON: {config_path}"
        ) from exc

    data = _require_mapping(raw, "root")

    election_id = _require_string(data, "election_id", "election_id")
    booth_id = _require_string(data, "booth_id", "booth_id")

    candidates_raw = data.get("candidates")
    if not isinstance(candidates_raw, list) or not candidates_raw:
        raise ElectionConfigError("Missing or invalid field 'candidates'.")

    candidates: list[Candidate] = []
    seen_indices: set[int] = set()
    for position, item in enumerate(candidates_raw):
        entry = _require_mapping(item, f"candidates[{position}]")
        index = _require_int(entry, "index", f"candidates[{position}].index")
        candidate_id = _require_string(
            entry, "candidate_id", f"candidates[{position}].candidate_id"
        )
        if index in seen_indices:
            raise ElectionConfigError(
                f"Duplicate candidate index in 'candidates': {index}."
            )
        seen_indices.add(index)
        candidates.append(Candidate(index=index, candidate_id=candidate_id))

    candidates.sort(key=lambda candidate: candidate.index)
    expected_indices = list(range(len(candidates)))
    actual_indices = [candidate.index for candidate in candidates]
    if actual_indices != expected_indices:
        raise ElectionConfigError(
            "Candidate indices must be contiguous from 0 to m-1 in configuration order."
        )

    if candidates[-1].candidate_id != "NOTA":
        raise ElectionConfigError(
            "Last candidate in 'candidates' must be NOTA."
        )

    trustees = _require_mapping(data.get("trustees"), "trustees")
    trustees_n = _require_positive_int(trustees, "n", "trustees.n")
    trustees_t = _require_positive_int(trustees, "t", "trustees.t")
    if trustees_t > trustees_n:
        raise ElectionConfigError("Invalid field 'trustees.t': threshold exceeds n.")

    authorities = _require_mapping(data.get("authorities"), "authorities")
    agents = _require_positive_int(authorities, "agents", "authorities.agents")
    agent_k = _require_positive_int(authorities, "k", "authorities.k")
    if agent_k > agents:
        raise ElectionConfigError("Invalid field 'authorities.k': k exceeds agents.")

    test_rate = _require_mapping(data.get("test_rate"), "test_rate")
    test_rate_num = _require_int(test_rate, "num", "test_rate.num")
    test_rate_den = _require_positive_int(test_rate, "den", "test_rate.den")
    if test_rate_num < 0 or test_rate_num > test_rate_den:
        raise ElectionConfigError(
            "Invalid field 'test_rate': numerator must satisfy 0 <= num <= den."
        )

    ballots_expected = _require_positive_int(data, "ballots_expected", "ballots_expected")
    seed = _require_int(data, "seed", "seed")

    return ElectionConfig(
        election_id=election_id,
        booth_id=booth_id,
        candidates=candidates,
        trustees_n=trustees_n,
        trustees_t=trustees_t,
        agents=agents,
        agent_k=agent_k,
        test_rate_num=test_rate_num,
        test_rate_den=test_rate_den,
        ballots_expected=ballots_expected,
        seed=seed,
    )
