"""
record.py — SPEC.md v1 revision 2, section 14 (task B3c: ballot record shape).

Assembles the JSON ballot record and checks the structural half of P2 from
section 16: exactly m ciphertexts and m validity proofs, ordered by
candidate_index ascending, no gaps, every HEX384 field exactly 768 hex chars.

What this module deliberately does NOT do:

  - It does not check in_group(). That is section 2.1 and lives in membership.py.
  - It does not verify any proof. That is sections 8.3 and 9.3.
  - It does not sort or reindex its inputs. Silently repairing a caller's
    ordering mistake would hide exactly the failure section 14 warns about:
    candidate_index is bound into every challenge preimage (section 8.2), so a
    reordered ballot produces proofs that verify here and fail everywhere else.

The full P2 check is this module's shape check plus those other two. Splitting
them is intentional; duplicating them would violate section 0.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Sequence

HEX384_CHARS = 768          # section 3.5: I2B(x).hex(), 384 bytes
I2B_WIDTH = 384


class BallotShapeError(ValueError):
    """Raised when a ballot record violates section 14 or the P2 shape rules."""


def hex384(x: int) -> str:
    """Section 3.5. Group elements and exponents are lowercase hex of I2B(x).

    They are never JSON numbers. int.to_bytes raises OverflowError if the value
    does not fit in 384 bytes; that propagates deliberately, because a value too
    large for the field is a bug upstream, not something to truncate here.
    """
    if not isinstance(x, int) or isinstance(x, bool):
        raise TypeError(f"hex384 expects int, got {type(x).__name__}")
    if x < 0:
        raise ValueError("hex384 is not defined for negative integers")
    return x.to_bytes(I2B_WIDTH, "big").hex()


@dataclass(frozen=True)
class Ciphertext:
    """Section 7: alpha_i = g^{r_i}, beta_i = pk^{r_i} * g^{v_i}."""

    candidate_index: int
    alpha: int
    beta: int


@dataclass(frozen=True)
class ValidityProof:
    """Section 8: the published proof (c_0, c_1, f_0, f_1, a_0, b_0, a_1, b_1)."""

    candidate_index: int
    c0: int
    c1: int
    f0: int
    f1: int
    a0: int
    b0: int
    a1: int
    b1: int


@dataclass(frozen=True)
class SumProof:
    """Section 9: Chaum-Pedersen equality, published as (c, f, a, b)."""

    c: int
    f: int
    a: int
    b: int


VALIDITY_PROOF_FIELDS = ("c0", "c1", "f0", "f1", "a0", "b0", "a1", "b1")
SUM_PROOF_FIELDS = ("c", "f", "a", "b")


def build_ballot_record(
    *,
    booth_id: str,
    ballot_serial: int,
    m: int,
    ciphertexts: Sequence[Ciphertext],
    validity_proofs: Sequence[ValidityProof],
    sum_proof: SumProof,
) -> Dict[str, Any]:
    """Build the section 14 'ballot' record and validate its shape.

    There is no timestamp field, by design: section 14 keeps timing in the
    machine's private log because it is a fingerprinting feature for basket A's
    adversaries, and publishing it would leak the signal the paper studies.
    """
    record: Dict[str, Any] = {
        "record_type": "ballot",
        "booth_id": booth_id,
        "ballot_serial": ballot_serial,
        "ciphertexts": [
            {
                "candidate_index": c.candidate_index,
                "alpha": hex384(c.alpha),
                "beta": hex384(c.beta),
            }
            for c in ciphertexts
        ],
        "validity_proofs": [
            {
                "candidate_index": v.candidate_index,
                **{name: hex384(getattr(v, name)) for name in VALIDITY_PROOF_FIELDS},
            }
            for v in validity_proofs
        ],
        "sum_proof": {
            name: hex384(getattr(sum_proof, name)) for name in SUM_PROOF_FIELDS
        },
    }
    verify_ballot_shape(record, m)
    return record


def _check_hex384(value: Any, where: str) -> None:
    if not isinstance(value, str):
        raise BallotShapeError(
            f"{where}: HEX384 must be a string, got {type(value).__name__}. "
            f"Section 3.5: group elements are never JSON numbers."
        )
    if len(value) != HEX384_CHARS:
        raise BallotShapeError(
            f"{where}: HEX384 must be exactly {HEX384_CHARS} characters, "
            f"got {len(value)}"
        )
    if value != value.lower():
        raise BallotShapeError(f"{where}: HEX384 must be lowercase")
    try:
        bytes.fromhex(value)
    except ValueError:
        raise BallotShapeError(f"{where}: not valid hexadecimal") from None


def verify_ballot_shape(record: Dict[str, Any], m: int) -> None:
    """Structural half of section 16 P2. Raises BallotShapeError on failure."""
    if not isinstance(record, dict):
        raise BallotShapeError(f"ballot record must be an object, got {type(record).__name__}")

    if record.get("record_type") != "ballot":
        raise BallotShapeError(
            f"record_type must be 'ballot', got {record.get('record_type')!r}"
        )

    if not isinstance(record.get("booth_id"), str):
        raise BallotShapeError("booth_id must be a string")
    if len(record["booth_id"].encode("utf-8")) > 32:
        raise BallotShapeError("booth_id exceeds the 32-byte limit of section 3.3")

    serial = record.get("ballot_serial")
    if not isinstance(serial, int) or isinstance(serial, bool) or serial < 1:
        raise BallotShapeError(
            f"ballot_serial must be an integer >= 1 (section 7), got {serial!r}"
        )

    _check_indexed_array(record, "ciphertexts", m, ("alpha", "beta"))
    _check_indexed_array(record, "validity_proofs", m, VALIDITY_PROOF_FIELDS)

    sum_proof = record.get("sum_proof")
    if not isinstance(sum_proof, dict):
        raise BallotShapeError("sum_proof must be an object")
    for name in SUM_PROOF_FIELDS:
        if name not in sum_proof:
            raise BallotShapeError(f"sum_proof: missing field {name!r}")
        _check_hex384(sum_proof[name], f"sum_proof.{name}")
    extra = set(sum_proof) - set(SUM_PROOF_FIELDS)
    if extra:
        raise BallotShapeError(f"sum_proof: unexpected fields {sorted(extra)}")


def _check_indexed_array(
    record: Dict[str, Any], key: str, m: int, hex_fields: Sequence[str]
) -> None:
    items = record.get(key)
    if not isinstance(items, list):
        raise BallotShapeError(f"{key}: must be an array")
    if len(items) != m:
        raise BallotShapeError(
            f"{key}: expected exactly m={m} entries, got {len(items)} "
            f"(section 14: length exactly m, no gaps)"
        )
    for position, item in enumerate(items):
        if not isinstance(item, dict):
            raise BallotShapeError(f"{key}[{position}]: must be an object")
        if item.get("candidate_index") != position:
            raise BallotShapeError(
                f"{key}[{position}]: candidate_index={item.get('candidate_index')!r}, "
                f"expected {position} (section 14: ordered by candidate_index "
                f"ascending; the order is bound into every challenge)"
            )
        for name in hex_fields:
            if name not in item:
                raise BallotShapeError(f"{key}[{position}]: missing field {name!r}")
            _check_hex384(item[name], f"{key}[{position}].{name}")
        allowed = {"candidate_index", *hex_fields}
        extra = set(item) - allowed
        if extra:
            raise BallotShapeError(f"{key}[{position}]: unexpected fields {sorted(extra)}")


def candidate_indices(record: Dict[str, Any], key: str) -> List[int]:
    """Convenience accessor used by tests and by the vector generator."""
    return [item["candidate_index"] for item in record[key]]
