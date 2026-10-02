"""
SPEC.md section 3 -- encoding primitives (task B3).

Implements, exactly as specified, nothing more:
    I2B / B2I  -- section 3.1, fixed-width big-endian integer <-> bytes
    U64        -- section 3.2, 8-byte big-endian unsigned integer
    S32 / S64  -- section 3.3, UTF-8, right-padded with 0x00
    L          -- section 3.4, ASCII domain-separation label, right-padded with 0x00 to 32

Standard library only, per the project constraint (no external crypto deps
for this module; Ed25519 signing lives elsewhere and is out of scope here).
"""

from __future__ import annotations

# I2B/B2I are the fixed-length instance of I2OSP/OS2IP, RFC 8017 (PKCS #1 v2.2) section 4.1-4.2.
GROUP_ELEMENT_LEN = 384  # bytes; SPEC.md section 3.1 -- applies to group elements AND exponents
U64_LEN = 8               # bytes; SPEC.md section 3.2
S32_LEN = 32               # bytes; SPEC.md section 3.3 -- booth_id
S64_LEN = 64               # bytes; SPEC.md section 3.3 -- election_id, candidate_id
LABEL_LEN = 32             # bytes; SPEC.md section 3.4 -- domain separation labels


def I2B(x: int, length: int = GROUP_ELEMENT_LEN) -> bytes:
    """SPEC.md 3.1: big-endian, zero-padded on the left, exactly `length` bytes.

    Raises ValueError rather than silently truncating or growing -- the spec's
    "fixed width means fixed width" is a hard constraint, not a default.
    """
    if x < 0:
        raise ValueError(f"I2B: x must be non-negative, got {x}")
    if x >= (1 << (length * 8)):
        raise ValueError(
            f"I2B: x does not fit in {length} bytes "
            f"(x has {x.bit_length()} bits, capacity is {length * 8} bits)"
        )
    return x.to_bytes(length, "big")


def B2I(b: bytes) -> int:
    """SPEC.md 3.1: B2I(b) = int.from_bytes(b, "big"). No length restriction stated."""
    return int.from_bytes(b, "big")


def U64(x: int) -> bytes:
    """SPEC.md 3.2: counts, indices, serials, rates as unsigned 8-byte big-endian."""
    if x < 0:
        raise ValueError(f"U64: x must be non-negative, got {x}")
    return I2B(x, U64_LEN)


def _S(s: str, length: int, field_name: str) -> bytes:
    encoded = s.encode("utf-8")
    if len(encoded) > length:
        raise ValueError(
            f"{field_name}: UTF-8 encoding of {s!r} is {len(encoded)} bytes, "
            f"exceeds the {length}-byte limit"
        )
    return encoded + b"\x00" * (length - len(encoded))


def S32(s: str) -> bytes:
    """SPEC.md 3.3: booth_id -- ASCII, at most 32 bytes, UTF-8, right-padded with 0x00."""
    return _S(s, S32_LEN, "S32")


def S64(s: str) -> bytes:
    """SPEC.md 3.3: election_id / candidate_id -- UTF-8, at most 64 bytes, right-padded with 0x00."""
    return _S(s, S64_LEN, "S64")


def L(s: str) -> bytes:
    """SPEC.md 3.4: domain separation label -- ASCII, right-padded with 0x00 to exactly 32 bytes.

    Every label is used at exactly one place in the system (spec's own invariant,
    not enforced here -- that's a whole-system property, not a per-call one).
    """
    try:
        encoded = s.encode("ascii")
    except UnicodeEncodeError as e:
        raise ValueError(f"L: label {s!r} is not pure ASCII") from e
    if len(encoded) > LABEL_LEN:
        raise ValueError(f"L: label {s!r} is {len(encoded)} bytes, exceeds {LABEL_LEN}")
    return encoded + b"\x00" * (LABEL_LEN - len(encoded))
