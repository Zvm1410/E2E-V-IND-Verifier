"""Adversary feature interface for fingerprinting study (A10)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from app.services.poll_state import BallotSession, PollState


class AdversaryClass(str, Enum):
    A0_BLIND = "A0Blind"
    A1_TEMPORAL = "A1Temporal"
    A2_INTERACTION = "A2Interaction"
    A3_LEAKAGE = "A3Leakage"
    A_ORACLE = "AOracle"


@dataclass(frozen=True)
class AdversaryFeatures:
    elapsed_seconds: float
    ballot_index: int
    selection_to_confirm_ms: "float | None"
    input_device: str


def extract_features(poll_state: PollState, session: BallotSession | None) -> AdversaryFeatures:
    selection_to_confirm_ms = None
    if (
        session
        and session.selection_started_at
        and session.selection_confirmed_at
    ):
        delta = session.selection_confirmed_at - session.selection_started_at
        selection_to_confirm_ms = delta.total_seconds() * 1000

    return AdversaryFeatures(
        elapsed_seconds=poll_state.elapsed_seconds,
        ballot_index=session.serial if session else poll_state.next_serial,
        selection_to_confirm_ms=selection_to_confirm_ms,
        input_device=session.input_device if session else "touchscreen",
    )


def is_probably_test(
    features: AdversaryFeatures,
    adversary: AdversaryClass,
    scheduled_tests: set[int] | None = None,
    ground_truth: bool | None = None,
) -> bool:
    if adversary == AdversaryClass.A0_BLIND:
        return False

    if adversary == AdversaryClass.A_ORACLE:
        return bool(ground_truth)

    if adversary == AdversaryClass.A1_TEMPORAL:
        return features.ballot_index <= 5 or features.elapsed_seconds < 120

    if adversary == AdversaryClass.A2_INTERACTION:
        if features.selection_to_confirm_ms is not None:
            return features.selection_to_confirm_ms > 2500
        return features.input_device != "touchscreen"

    if adversary == AdversaryClass.A3_LEAKAGE and scheduled_tests is not None:
        return features.ballot_index in scheduled_tests

    return False


class A0Blind:
    def is_probably_test(self, features: AdversaryFeatures) -> bool:
        return False


class A1Temporal:
    def is_probably_test(self, features: AdversaryFeatures) -> bool:
        return features.ballot_index <= 5 or features.elapsed_seconds < 120


class A2Interaction:
    def is_probably_test(self, features: AdversaryFeatures) -> bool:
        if features.selection_to_confirm_ms is not None:
            return features.selection_to_confirm_ms > 2500
        return features.input_device != "touchscreen"


class A3Leakage:
    def __init__(self, leaked_set: set[int] | None = None):
        self.leaked = leaked_set or set()

    def is_probably_test(self, features: AdversaryFeatures) -> bool:
        return features.ballot_index in self.leaked


class AOracle:
    def __init__(self, ground_truth: set[int]):
        self.truth = ground_truth

    def is_probably_test(self, features: AdversaryFeatures) -> bool:
        return features.ballot_index in self.truth
