"""Digest, signatures and register cross-check (SPEC 12, 15, 16 P1 and P4)."""

import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from verifier.encoding import label
from verifier.hashes import base_hash
from verifier.result import CheckFailure


def canonical_bytes(board_obj):
    """SPEC 15.1."""
    return json.dumps(board_obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def board_digest(canonical):
    """SPEC 15.2: D = SHA-256(L("EVOTE-BOARD-v1") || canonical)."""
    return hashlib.sha256(label("EVOTE-BOARD-v1") + canonical).digest()


def _signature_valid(public_key, signature, message):
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def check_signed_digest(raw_bytes, board_obj, keys, signatures):
    """P1, byte level: canonical form, digest, officer and k agent signatures.
    Runs before the rest of the board is parsed, so a retroactive edit is
    named P1 even if it also left a record malformed. Returns the digest."""
    canonical = canonical_bytes(board_obj)
    if canonical != raw_bytes:
        raise CheckFailure("P1", "board", "file is not in canonical serialisation")
    digest = board_digest(canonical)
    if digest != signatures.digest:
        raise CheckFailure("P1", "signatures.digest",
                           "recomputed board digest differs from the signed digest")

    message = label("EVOTE-SIG-v1") + digest
    if not _signature_valid(keys.officer, signatures.officer_signature, message):
        raise CheckFailure("P1", "signatures.officer_signature", "officer signature invalid")
    valid_agents = set()
    for index, sig in signatures.agent_signatures:
        if index >= len(keys.agents):
            # SPEC 15.3: a signature from a key not on the list is a rejection,
            # not merely uncounted.
            raise CheckFailure("P1", f"signatures.agent_signatures[{index}]",
                               "signature from an agent not on the published list")
        if _signature_valid(keys.agents[index], sig, message):
            valid_agents.add(index)
    if len(valid_agents) < keys.k:
        raise CheckFailure("P1", "signatures.agent_signatures",
                           f"{len(valid_agents)} distinct valid agent signatures, need {keys.k}")
    return digest


def check_parameters(board):
    """P1, record level: config cross-references and Q recomputed."""
    c, ts, keys = board.config, board.trustee_setup, board.authority_keys
    if (ts.n, ts.t) != (c.n, c.t) or len(ts.commitments) != c.n:
        raise CheckFailure("P1", "trustee_setup", "n or t disagrees with election_config")
    if keys.k != c.k or len(keys.agents) != c.agents:
        raise CheckFailure("P1", "authority_keys", "k or agent count disagrees with election_config")
    q = base_hash(c.election_id, [x.candidate_id for x in c.candidates], c.n, c.t,
                  ts.public_key, ts.commitments, keys.k, keys.officer, keys.agents)
    if q != board.base_hash:
        raise CheckFailure("P1", "base_hash", "Q does not recompute from the published parameters")


def check_board_integrity(raw_bytes, board_obj, board, signatures):
    """All of P1 on an already parsed board. Returns the digest."""
    digest = check_signed_digest(raw_bytes, board_obj, board.authority_keys, signatures)
    check_parameters(board)
    return digest


def check_ballot_count(board):
    """P4: serials complete and unique, register consistent, every issued
    serial committed pre-poll, aggregate population equal to ballots_counted."""
    reg = board.poll_register
    booth = board.config.booth_id
    for name, rec in (("poll_register", reg), *((f"ballots[{i}]", b) for i, b in enumerate(board.ballots)),
                      *((f"spoils[{i}]", s) for i, s in enumerate(board.spoils))):
        if rec.booth_id != booth:
            raise CheckFailure("P4", name, f"booth_id {rec.booth_id!r} is not {booth!r}")

    serials = [b.ballot_serial for b in board.ballots]
    if len(set(serials)) != len(serials):
        raise CheckFailure("P4", "ballots", "repeated ballot serial")
    if serials != list(range(1, len(serials) + 1)):
        raise CheckFailure("P4", "ballots", "serials do not run 1, 2, 3, ... without a gap")
    if reg.ballots_issued != len(serials):
        raise CheckFailure("P4", "poll_register",
                           f"ballots_issued {reg.ballots_issued} but {len(serials)} ballot records")
    if reg.ballots_spoiled != len(board.spoils):
        raise CheckFailure("P4", "poll_register",
                           f"ballots_spoiled {reg.ballots_spoiled} but {len(board.spoils)} spoil records")
    if reg.ballots_counted != reg.ballots_issued - reg.ballots_spoiled:
        raise CheckFailure("P4", "poll_register", "ballots_counted != issued - spoiled")

    spoiled = [s.ballot_serial for s in board.spoils]
    if len(set(spoiled)) != len(spoiled) or not set(spoiled) <= set(serials):
        raise CheckFailure("P4", "spoils", "spoil serials repeat or name no issued ballot")
    if len(serials) - len(set(spoiled)) != reg.ballots_counted:
        raise CheckFailure("P4", "poll_register", "aggregate population differs from ballots_counted")

    committed = [s for s, _ in board.prepoll.randomness_commitments]
    if len(set(committed)) != len(committed):
        raise CheckFailure("P4", "prepoll", "repeated randomness commitment serial")
    if any(not 1 <= s <= board.config.ballots_expected for s in committed):
        raise CheckFailure("P4", "prepoll", "commitment for a serial outside 1..ballots_expected")
    missing = sorted(set(serials) - set(committed))
    if missing:
        raise CheckFailure("P4", "prepoll", f"issued serial {missing[0]} has no pre-poll commitment")
