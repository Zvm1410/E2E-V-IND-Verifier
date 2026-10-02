"""Byte encodings, SPEC section 3, and the membership and range checks of 2.1."""

import re

from verifier.group import G, P, Q, WIDTH


class EncodingError(ValueError):
    pass


def i2b(x):
    """I2B: big-endian, left zero-padded, exactly 384 bytes."""
    if not isinstance(x, int) or isinstance(x, bool) or x < 0:
        raise EncodingError(f"I2B needs a non-negative int, got {x!r}")
    if x.bit_length() > WIDTH * 8:
        raise EncodingError("integer does not fit in 384 bytes")
    return x.to_bytes(WIDTH, "big")


def b2i(b):
    return int.from_bytes(b, "big")


def u64(x):
    if not isinstance(x, int) or isinstance(x, bool) or not 0 <= x < 2**64:
        raise EncodingError(f"U64 needs an int in [0, 2^64), got {x!r}")
    return x.to_bytes(8, "big")


def _padded(s, width, what, ascii_only=False):
    if not isinstance(s, str):
        raise EncodingError(f"{what} must be a string")
    if ascii_only and not s.isascii():
        raise EncodingError(f"{what} must be ASCII")
    raw = s.encode("utf-8")
    if len(raw) > width:
        raise EncodingError(f"{what} is longer than {width} bytes")
    return raw.ljust(width, b"\x00")


def s32(s):
    """S32: booth_id, ASCII, right-padded with 0x00 to 32 bytes."""
    return _padded(s, 32, "booth_id", ascii_only=True)


def s64(s):
    """S64: election_id and candidate_id, UTF-8, right-padded to 64 bytes."""
    return _padded(s, 64, "S64 string")


def label(s):
    """L(s): ASCII label right-padded with 0x00 to 32 bytes."""
    return _padded(s, 32, "label", ascii_only=True)


def in_group(x):
    """SPEC 2.1: 0 < x < p and x^q == 1 mod p.

    The upper bound is load-bearing: pow() reduces mod p first, so without it
    x + p would pass. The lower bound is 0, not 1; the identity is a member.
    """
    return isinstance(x, int) and not isinstance(x, bool) and 0 < x < P and pow(x, Q, P) == 1


def in_exponent_range(x):
    """SPEC 2.1: challenges and responses lie in [0, q)."""
    return isinstance(x, int) and not isinstance(x, bool) and 0 <= x < Q


def inv(x):
    """Inverse of a group element mod p."""
    return pow(x, -1, P)


def g_pow(e):
    return pow(G, e, P)


_HEX384 = re.compile(r"[0-9a-f]{768}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX128 = re.compile(r"[0-9a-f]{128}")


def hex384_to_int(s):
    """HEX384, SPEC 3.5: exactly 768 lowercase hex characters."""
    if not isinstance(s, str) or not _HEX384.fullmatch(s):
        raise EncodingError("HEX384 field must be exactly 768 lowercase hex characters")
    return int(s, 16)


def hex32_to_bytes(s):
    """64-character lowercase hex of 32 raw bytes (hashes, nonces, Ed25519 keys)."""
    if not isinstance(s, str) or not _HEX64.fullmatch(s):
        raise EncodingError("field must be exactly 64 lowercase hex characters")
    return bytes.fromhex(s)


def hex64_to_bytes(s):
    """128-character lowercase hex of 64 raw bytes (Ed25519 signatures)."""
    if not isinstance(s, str) or not _HEX128.fullmatch(s):
        raise EncodingError("field must be exactly 128 lowercase hex characters")
    return bytes.fromhex(s)
