"""Poll register and ballot lifecycle state (A6)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class BallotSession:
    serial: int
    candidate_index: "int | None" = None
    selection_confirmed_at: datetime | None = None
    selection_started_at: datetime | None = None
    input_device: str = "touchscreen"
    spoiled: bool = False


@dataclass
class PollState:
    poll_opened_at: datetime | None = None
    current_ballot: BallotSession | None = None
    ballots_issued: int = 0
    ballots_spoiled: int = 0
    sessions: list[BallotSession] = field(default_factory=list)

    @property
    def ballots_counted(self) -> int:
        return self.ballots_issued - self.ballots_spoiled

    @property
    def next_serial(self) -> int:
        return self.ballots_issued + 1

    @property
    def elapsed_seconds(self) -> float:
        if self.poll_opened_at is None:
            return 0.0
        now = datetime.now(timezone.utc)
        return (now - self.poll_opened_at).total_seconds()

    def open_poll(self) -> None:
        if self.poll_opened_at is None:
            self.poll_opened_at = datetime.now(timezone.utc)

    def begin_ballot(self) -> BallotSession:
        self.open_poll()
        session = BallotSession(serial=self.next_serial)
        self.current_ballot = session
        self.ballots_issued += 1
        self.sessions.append(session)
        return session

    def mark_selection(self, candidate_index: int) -> None:
        if self.current_ballot is None:
            return
        self.current_ballot.selection_started_at = datetime.now(timezone.utc)
        self.current_ballot.candidate_index = candidate_index

    def confirm_selection(self) -> None:
        if self.current_ballot is None:
            return
        self.current_ballot.selection_confirmed_at = datetime.now(timezone.utc)

    def spoil_current_ballot(self) -> None:
        if self.current_ballot is None:
            return
        self.current_ballot.spoiled = True
        self.ballots_spoiled += 1

    def finish_ballot(self) -> None:
        self.current_ballot = None

    def poll_register(self) -> dict[str, int]:
        return {
            "ballots_issued": self.ballots_issued,
            "ballots_spoiled": self.ballots_spoiled,
            "ballots_counted": self.ballots_counted,
        }
