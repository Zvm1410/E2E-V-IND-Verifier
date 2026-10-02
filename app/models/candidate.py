from dataclasses import dataclass


@dataclass(frozen=True)
class Candidate:
    index: int
    candidate_id: str

    @property
    def display_name(self) -> str:
        if self.candidate_id == "NOTA":
            return "None of the Above"
        return self.candidate_id.replace("-", " ")
