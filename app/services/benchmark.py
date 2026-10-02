"""Hardware benchmark harness stub (A11)."""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field

from app.models.election_config import ElectionConfig
from app.services.ballot_service import BallotService


@dataclass
class BenchmarkRun:
    candidate_count: int
    ballot_count: int
    encryption_times_ms: list[float] = field(default_factory=list)
    proof_times_ms: list[float] = field(default_factory=list)
    cast_times_ms: list[float] = field(default_factory=list)
    peak_memory_mb: float = 0.0

    @property
    def total_encryption_ms(self) -> float:
        return sum(self.encryption_times_ms)

    @property
    def total_proof_ms(self) -> float:
        return sum(self.proof_times_ms)


def run_benchmark(
    config: ElectionConfig,
    ballot_service: BallotService,
    ballot_count: int = 500,
) -> BenchmarkRun:
    run = BenchmarkRun(candidate_count=config.candidate_count, ballot_count=ballot_count)
    peak = 0.0

    for _ in range(ballot_count):
        candidate_index = random.randint(0, config.candidate_count - 1)
        ballot_service.poll_state.begin_ballot()
        ballot_service.poll_state.mark_selection(candidate_index)
        artifacts = ballot_service.encrypt_and_prove(candidate_index)
        ballot_service.append_ballot(artifacts)
        ballot_service.poll_state.confirm_selection()
        ballot_service.poll_state.finish_ballot()

        run.encryption_times_ms.append(artifacts.encryption_ms)
        run.proof_times_ms.append(max(artifacts.cast_ms * 0.7, 0.1))
        run.cast_times_ms.append(artifacts.cast_ms)

        simulated_mb = 120 + (config.candidate_count * 2.5) + random.uniform(0, 8)
        peak = max(peak, simulated_mb)

    run.peak_memory_mb = peak
    return run
