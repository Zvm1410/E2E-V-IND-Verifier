from dataclasses import dataclass

from app.models.candidate import Candidate


@dataclass(frozen=True)
class ElectionConfig:
    election_id: str
    booth_id: str
    candidates: list[Candidate]
    trustees_n: int
    trustees_t: int
    agents: int
    agent_k: int
    test_rate_num: int
    test_rate_den: int
    ballots_expected: int
    seed: int

    @property
    def candidate_count(self) -> int:
        return len(self.candidates)
