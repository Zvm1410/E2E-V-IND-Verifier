"""Admin-panel benchmark (A11), real measurements only.

Times the machine's own cast path through the real basket B pipeline:
`encrypt_and_prove` (encryption and all proofs together, as the ballot
service measures it), building the board record, and the whole cast.
Memory is the process's peak resident set from the OS.

The paper's numbers come from `python -m harness.bench`, which separates
encryption from proving and reports percentiles per candidate count; this
panel is the on-device spot check.
"""

from __future__ import annotations

import random
import resource
import sys
from dataclasses import dataclass, field

from app.models.election_config import ElectionConfig
from app.services.ballot_service import BallotService


@dataclass
class BenchmarkRun:
    candidate_count: int
    ballot_count: int
    encrypt_prove_times_ms: list[float] = field(default_factory=list)
    record_times_ms: list[float] = field(default_factory=list)
    cast_times_ms: list[float] = field(default_factory=list)
    peak_memory_mb: float = 0.0


def _peak_rss_mb() -> float:
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return rss / (1024 * 1024) if sys.platform == "darwin" else rss / 1024


def run_benchmark(
    config: ElectionConfig,
    ballot_service: BallotService,
    ballot_count: int = 500,
) -> BenchmarkRun:
    run = BenchmarkRun(candidate_count=config.candidate_count, ballot_count=ballot_count)
    rng = random.Random(config.seed)
    for _ in range(ballot_count):
        candidate_index = rng.randrange(config.candidate_count)
        ballot_service.poll_state.begin_ballot()
        ballot_service.poll_state.mark_selection(candidate_index)
        ballot_service.poll_state.confirm_selection()
        artifacts = ballot_service.encrypt_and_prove(candidate_index)
        ballot_service.append_ballot(artifacts)
        ballot_service.poll_state.finish_ballot()

        run.encrypt_prove_times_ms.append(artifacts.encryption_ms)
        run.record_times_ms.append(artifacts.cast_ms)
        run.cast_times_ms.append(artifacts.encryption_ms + artifacts.cast_ms)
    run.peak_memory_mb = _peak_rss_mb()
    return run
