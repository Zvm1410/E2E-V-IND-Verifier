"""Strict parsing of board records, SPEC sections 3.5, 5.1, 13.4, 14 and 15.3.

The parser enforces encoding, type and shape inside one record: exact key
sets, HEX384 width, subgroup membership for every group element, [0, q) for
every exponent, and candidate order inside a ballot. Relations between
records (serial sequences, counts, agreement with the configuration) are
checked by the later verification stages, because they belong to different
properties in SPEC section 16 and the parser must not decide attribution.

This module never imports from crypto/ or tally/ (SPEC section 0).
"""

import json
from dataclasses import dataclass

from verifier.encoding import (
    EncodingError,
    hex32_to_bytes,
    hex64_to_bytes,
    hex384_to_int,
    in_exponent_range,
    in_group,
)


class ParseError(ValueError):
    """A record that does not match its schema. `path` names the field."""

    def __init__(self, path, reason):
        super().__init__(f"{path}: {reason}")
        self.path = path
        self.reason = reason


# ---------------------------------------------------------------- raw JSON


def _reject_duplicate_keys(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ParseError(key, "duplicate JSON key")
        obj[key] = value
    return obj


def _reject_float(text):
    raise ParseError("json", f"floating point number {text} is not allowed")


def _reject_constant(text):
    raise ParseError("json", f"{text} is not allowed")


def load_json(data):
    """Parse JSON text or bytes with duplicate keys, floats and NaN rejected."""
    if isinstance(data, (bytes, bytearray)):
        try:
            data = bytes(data).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ParseError("json", "not valid UTF-8") from exc
    try:
        return json.loads(
            data,
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise ParseError("json", f"malformed JSON: {exc.msg}") from exc


# ------------------------------------------------------------- field types


def _obj(value, path, keys):
    if not isinstance(value, dict):
        raise ParseError(path, "expected a JSON object")
    actual = set(value)
    if actual != set(keys):
        missing = sorted(set(keys) - actual)
        extra = sorted(actual - set(keys))
        raise ParseError(path, f"wrong keys; missing {missing}, unexpected {extra}")
    return value


def _list(value, path, length=None):
    if not isinstance(value, list):
        raise ParseError(path, "expected a JSON array")
    if length is not None and len(value) != length:
        raise ParseError(path, f"expected exactly {length} entries, got {len(value)}")
    return value


def _small_int(value, path, minimum=0):
    """JSON number for counts, indices and thresholds: an int in 32 bits."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise ParseError(path, "expected a JSON integer")
    if not minimum <= value < 2**32:
        raise ParseError(path, f"integer {value} outside [{minimum}, 2^32)")
    return value


def _string(value, path, max_bytes, ascii_only=False):
    if not isinstance(value, str):
        raise ParseError(path, "expected a string")
    if ascii_only and not value.isascii():
        raise ParseError(path, "expected ASCII")
    if len(value.encode("utf-8")) > max_bytes:
        raise ParseError(path, f"longer than {max_bytes} bytes")
    return value


def _record_type(value, path, expected):
    if value != expected:
        raise ParseError(path + ".record_type", f"expected {expected!r}, got {value!r}")


def element(value, path):
    """A HEX384 group element: 768 hex chars and in_group (SPEC 2.1)."""
    try:
        x = hex384_to_int(value)
    except EncodingError as exc:
        raise ParseError(path, str(exc)) from exc
    if not in_group(x):
        raise ParseError(path, "group element fails subgroup membership 0 < x < p, x^q = 1")
    return x


def exponent(value, path):
    """A HEX384 exponent, challenge or response: 768 hex chars, in [0, q)."""
    try:
        x = hex384_to_int(value)
    except EncodingError as exc:
        raise ParseError(path, str(exc)) from exc
    if not in_exponent_range(x):
        raise ParseError(path, "exponent outside [0, q)")
    return x


def hash32(value, path):
    try:
        return hex32_to_bytes(value)
    except EncodingError as exc:
        raise ParseError(path, str(exc)) from exc


def signature64(value, path):
    try:
        return hex64_to_bytes(value)
    except EncodingError as exc:
        raise ParseError(path, str(exc)) from exc


def _indexed(entries, path, key, start, count):
    """Entries whose `key` must run start, start+1, ... in order with no gaps."""
    _list(entries, path, count)
    for pos, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ParseError(f"{path}[{pos}]", "expected a JSON object")
        idx = _small_int(entry.get(key), f"{path}[{pos}].{key}")
        if idx != start + pos:
            raise ParseError(f"{path}[{pos}].{key}", f"expected {start + pos}, got {idx}")
    return entries


# ------------------------------------------------------------ record types


@dataclass(frozen=True)
class Candidate:
    index: int
    candidate_id: str


@dataclass(frozen=True)
class ElectionConfig:
    election_id: str
    booth_id: str
    candidates: tuple
    n: int
    t: int
    agents: int
    k: int
    test_rate_num: int
    test_rate_den: int
    ballots_expected: int
    seed: int

    @property
    def m(self):
        return len(self.candidates)


def parse_election_config(obj, path="election_config"):
    _obj(obj, path, ["election_id", "booth_id", "candidates", "trustees",
                     "authorities", "test_rate", "ballots_expected", "seed"])
    election_id = _string(obj["election_id"], path + ".election_id", 64)
    booth_id = _string(obj["booth_id"], path + ".booth_id", 32, ascii_only=True)
    cands = _list(obj["candidates"], path + ".candidates")
    if not cands:
        raise ParseError(path + ".candidates", "empty candidate list")
    _indexed(cands, path + ".candidates", "index", 0, len(cands))
    candidates = []
    for pos, c in enumerate(cands):
        cp = f"{path}.candidates[{pos}]"
        _obj(c, cp, ["index", "candidate_id"])
        candidates.append(Candidate(pos, _string(c["candidate_id"], cp + ".candidate_id", 64)))
    trustees = _obj(obj["trustees"], path + ".trustees", ["n", "t"])
    n = _small_int(trustees["n"], path + ".trustees.n", 1)
    t = _small_int(trustees["t"], path + ".trustees.t", 1)
    if t > n:
        raise ParseError(path + ".trustees", "threshold t exceeds n")
    auth = _obj(obj["authorities"], path + ".authorities", ["agents", "k"])
    agents = _small_int(auth["agents"], path + ".authorities.agents", 1)
    k = _small_int(auth["k"], path + ".authorities.k", 1)
    if k > agents:
        raise ParseError(path + ".authorities", "k exceeds the number of agents")
    rate = _obj(obj["test_rate"], path + ".test_rate", ["num", "den"])
    num = _small_int(rate["num"], path + ".test_rate.num")
    den = _small_int(rate["den"], path + ".test_rate.den", 1)
    if num > den:
        raise ParseError(path + ".test_rate", "test rate exceeds 1")
    return ElectionConfig(
        election_id, booth_id, tuple(candidates), n, t, agents, k, num, den,
        _small_int(obj["ballots_expected"], path + ".ballots_expected"),
        _small_int(obj["seed"], path + ".seed"),
    )


@dataclass(frozen=True)
class TrusteeSetup:
    public_key: int
    n: int
    t: int
    commitments: tuple  # h_1 .. h_n, position j-1 holds trustee j


def parse_trustee_setup(obj, path="trustee_setup"):
    _obj(obj, path, ["record_type", "public_key", "n", "t", "commitments"])
    _record_type(obj["record_type"], path, "trustee_setup")
    n = _small_int(obj["n"], path + ".n", 1)
    t = _small_int(obj["t"], path + ".t", 1)
    if t > n:
        raise ParseError(path, "threshold t exceeds n")
    entries = _indexed(obj["commitments"], path + ".commitments", "trustee_index", 1, n)
    commitments = []
    for pos, e in enumerate(entries):
        ep = f"{path}.commitments[{pos}]"
        _obj(e, ep, ["trustee_index", "commitment"])
        commitments.append(element(e["commitment"], ep + ".commitment"))
    return TrusteeSetup(element(obj["public_key"], path + ".public_key"), n, t, tuple(commitments))


@dataclass(frozen=True)
class AuthorityKeys:
    k: int
    officer: bytes
    agents: tuple  # raw 32-byte keys, position i holds agent i


def parse_authority_keys(obj, path="authority_keys"):
    _obj(obj, path, ["record_type", "k", "officer", "agents"])
    _record_type(obj["record_type"], path, "authority_keys")
    raw = _list(obj["agents"], path + ".agents")
    _indexed(raw, path + ".agents", "agent_index", 0, len(raw))
    agents = []
    for pos, e in enumerate(raw):
        ep = f"{path}.agents[{pos}]"
        _obj(e, ep, ["agent_index", "public_key"])
        agents.append(hash32(e["public_key"], ep + ".public_key"))
    return AuthorityKeys(_small_int(obj["k"], path + ".k", 1),
                         hash32(obj["officer"], path + ".officer"), tuple(agents))


@dataclass(frozen=True)
class Prepoll:
    randomness_commitments: tuple  # (ballot_serial, 32-byte K_s), board order kept
    test_schedule_commitment: bytes


def parse_prepoll(obj, path="prepoll"):
    _obj(obj, path, ["record_type", "randomness_commitments", "test_schedule_commitment"])
    _record_type(obj["record_type"], path, "prepoll")
    commits = []
    for pos, e in enumerate(_list(obj["randomness_commitments"], path + ".randomness_commitments")):
        ep = f"{path}.randomness_commitments[{pos}]"
        _obj(e, ep, ["ballot_serial", "commitment"])
        commits.append((_small_int(e["ballot_serial"], ep + ".ballot_serial"),
                        hash32(e["commitment"], ep + ".commitment")))
    return Prepoll(tuple(commits),
                   hash32(obj["test_schedule_commitment"], path + ".test_schedule_commitment"))


@dataclass(frozen=True)
class ValidityProof:
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
    c: int
    f: int
    a: int
    b: int


@dataclass(frozen=True)
class Ballot:
    booth_id: str
    ballot_serial: int
    ciphertexts: tuple  # (alpha_i, beta_i) for i in 0..m-1
    validity_proofs: tuple
    sum_proof: SumProof


def _sum_proof(obj, path):
    _obj(obj, path, ["c", "f", "a", "b"])
    return SumProof(exponent(obj["c"], path + ".c"), exponent(obj["f"], path + ".f"),
                    element(obj["a"], path + ".a"), element(obj["b"], path + ".b"))


def parse_ballot(obj, m, path="ballot"):
    """B3c / SPEC 14 ballot record with exactly m ciphertexts and proofs in order."""
    _obj(obj, path, ["record_type", "booth_id", "ballot_serial", "ciphertexts",
                     "validity_proofs", "sum_proof"])
    _record_type(obj["record_type"], path, "ballot")
    booth_id = _string(obj["booth_id"], path + ".booth_id", 32, ascii_only=True)
    serial = _small_int(obj["ballot_serial"], path + ".ballot_serial", 1)
    cts = []
    for pos, e in enumerate(_indexed(obj["ciphertexts"], path + ".ciphertexts",
                                     "candidate_index", 0, m)):
        ep = f"{path}.ciphertexts[{pos}]"
        _obj(e, ep, ["candidate_index", "alpha", "beta"])
        cts.append((element(e["alpha"], ep + ".alpha"), element(e["beta"], ep + ".beta")))
    proofs = []
    for pos, e in enumerate(_indexed(obj["validity_proofs"], path + ".validity_proofs",
                                     "candidate_index", 0, m)):
        ep = f"{path}.validity_proofs[{pos}]"
        _obj(e, ep, ["candidate_index", "c0", "c1", "f0", "f1", "a0", "b0", "a1", "b1"])
        proofs.append(ValidityProof(
            *(exponent(e[f], f"{ep}.{f}") for f in ("c0", "c1", "f0", "f1")),
            *(element(e[f], f"{ep}.{f}") for f in ("a0", "b0", "a1", "b1")),
        ))
    return Ballot(booth_id, serial, tuple(cts), tuple(proofs),
                  _sum_proof(obj["sum_proof"], path + ".sum_proof"))


@dataclass(frozen=True)
class Spoil:
    booth_id: str
    ballot_serial: int
    opened_candidate_index: int
    randomness: tuple
    nonce: bytes


def parse_spoil(obj, m, path="spoil"):
    _obj(obj, path, ["record_type", "booth_id", "ballot_serial", "opened_candidate_index",
                     "randomness", "nonce"])
    _record_type(obj["record_type"], path, "spoil")
    opened = _small_int(obj["opened_candidate_index"], path + ".opened_candidate_index")
    if opened >= m:
        raise ParseError(path + ".opened_candidate_index", f"index {opened} is not below m = {m}")
    rand = _list(obj["randomness"], path + ".randomness", m)
    return Spoil(
        _string(obj["booth_id"], path + ".booth_id", 32, ascii_only=True),
        _small_int(obj["ballot_serial"], path + ".ballot_serial", 1),
        opened,
        tuple(exponent(r, f"{path}.randomness[{i}]") for i, r in enumerate(rand)),
        hash32(obj["nonce"], path + ".nonce"),
    )


@dataclass(frozen=True)
class PollRegister:
    booth_id: str
    ballots_issued: int
    ballots_spoiled: int
    ballots_counted: int


def parse_poll_register(obj, path="poll_register"):
    _obj(obj, path, ["record_type", "booth_id", "ballots_issued", "ballots_spoiled",
                     "ballots_counted"])
    _record_type(obj["record_type"], path, "poll_register")
    return PollRegister(
        _string(obj["booth_id"], path + ".booth_id", 32, ascii_only=True),
        _small_int(obj["ballots_issued"], path + ".ballots_issued"),
        _small_int(obj["ballots_spoiled"], path + ".ballots_spoiled"),
        _small_int(obj["ballots_counted"], path + ".ballots_counted"),
    )


def parse_tally_declaration(obj, m, path="tally_declaration"):
    """Returns the declared counts as a tuple indexed by candidate."""
    _obj(obj, path, ["record_type", "counts"])
    _record_type(obj["record_type"], path, "tally_declaration")
    counts = []
    for pos, e in enumerate(_indexed(obj["counts"], path + ".counts", "candidate_index", 0, m)):
        ep = f"{path}.counts[{pos}]"
        _obj(e, ep, ["candidate_index", "count"])
        counts.append(_small_int(e["count"], ep + ".count"))
    return tuple(counts)


@dataclass(frozen=True)
class Partial:
    trustee_index: int
    candidate_index: int
    partial: int
    proof: SumProof  # same (c, f, a, b) shape as the sum proof


@dataclass(frozen=True)
class DecryptionTranscript:
    subset: tuple
    lagrange_coefficients: dict  # trustee index -> published coefficient
    partials: tuple


def parse_decryption_transcript(obj, m, n, t, path="decryption_transcript"):
    """SPEC 13.4: partials ordered by trustee then candidate, no gaps."""
    _obj(obj, path, ["record_type", "subset", "lagrange_coefficients", "partials"])
    _record_type(obj["record_type"], path, "decryption_transcript")
    subset = [_small_int(j, f"{path}.subset[{i}]", 1)
              for i, j in enumerate(_list(obj["subset"], path + ".subset", t))]
    if any(j > n for j in subset):
        raise ParseError(path + ".subset", f"trustee index above n = {n}")
    if subset != sorted(set(subset)):
        raise ParseError(path + ".subset", "trustee indices must be distinct and ascending")
    lc = obj["lagrange_coefficients"]
    _obj(lc, path + ".lagrange_coefficients", [str(j) for j in subset])
    coeffs = {j: exponent(lc[str(j)], f"{path}.lagrange_coefficients.{j}") for j in subset}
    raw = _list(obj["partials"], path + ".partials", t * m)
    partials = []
    for pos, e in enumerate(raw):
        ep = f"{path}.partials[{pos}]"
        _obj(e, ep, ["trustee_index", "candidate_index", "partial", "proof"])
        want_j, want_i = subset[pos // m], pos % m
        j = _small_int(e["trustee_index"], ep + ".trustee_index")
        i = _small_int(e["candidate_index"], ep + ".candidate_index")
        if (j, i) != (want_j, want_i):
            raise ParseError(ep, f"expected trustee {want_j} candidate {want_i}, got {j}, {i}")
        partials.append(Partial(j, i, element(e["partial"], ep + ".partial"),
                                _sum_proof(e["proof"], ep + ".proof")))
    return DecryptionTranscript(tuple(subset), coeffs, tuple(partials))


@dataclass(frozen=True)
class Signatures:
    digest: bytes
    officer_signature: bytes
    agent_signatures: tuple  # (agent_index, 64-byte signature), file order kept


def parse_signatures(obj, path="signatures"):
    """SPEC 15.3 signature file. Duplicate or unknown agents are judged in P1."""
    _obj(obj, path, ["digest", "officer_signature", "agent_signatures"])
    sigs = []
    for pos, e in enumerate(_list(obj["agent_signatures"], path + ".agent_signatures")):
        ep = f"{path}.agent_signatures[{pos}]"
        _obj(e, ep, ["agent_index", "signature"])
        sigs.append((_small_int(e["agent_index"], ep + ".agent_index"),
                     signature64(e["signature"], ep + ".signature")))
    return Signatures(hash32(obj["digest"], path + ".digest"),
                      signature64(obj["officer_signature"], path + ".officer_signature"),
                      tuple(sigs))


def parse_schedule_opening(obj, path="schedule_opening"):
    """Shape not given in SPEC 14; taken from C's exported board."""
    _obj(obj, path, ["schedule_seed"])
    return hash32(obj["schedule_seed"], path + ".schedule_seed")


def parse_tally_aggregate(obj, m, path="tally_aggregate"):
    """Shape not given in SPEC 14; taken from C's exported board.
    Returns (A_i, B_i) per candidate. Never trusted, only compared (SPEC 13.1)."""
    _obj(obj, path, ["record_type", "columns"])
    _record_type(obj["record_type"], path, "tally_aggregate")
    cols = []
    for pos, e in enumerate(_indexed(obj["columns"], path + ".columns", "candidate_index", 0, m)):
        ep = f"{path}.columns[{pos}]"
        _obj(e, ep, ["candidate_index", "alpha", "beta"])
        cols.append((element(e["alpha"], ep + ".alpha"), element(e["beta"], ep + ".beta")))
    return tuple(cols)


BOARD_KEYS = [
    "election_config", "base_hash", "trustee_setup", "authority_keys", "prepoll",
    "ballots", "spoils", "poll_register", "schedule_opening", "tally_aggregate",
    "decryption_transcript", "tally_declaration",
]


@dataclass(frozen=True)
class Board:
    config: ElectionConfig
    base_hash: bytes
    trustee_setup: TrusteeSetup
    authority_keys: AuthorityKeys
    prepoll: Prepoll
    ballots: tuple
    spoils: tuple
    poll_register: PollRegister
    schedule_seed: bytes
    tally_aggregate: tuple
    decryption_transcript: DecryptionTranscript
    tally_declaration: tuple


def parse_board(obj):
    """SPEC 14: the whole board, every record parsed strictly."""
    _obj(obj, "board", BOARD_KEYS)
    config = parse_election_config(obj["election_config"])
    m = config.m
    return Board(
        config=config,
        base_hash=hash32(obj["base_hash"], "base_hash"),
        trustee_setup=parse_trustee_setup(obj["trustee_setup"]),
        authority_keys=parse_authority_keys(obj["authority_keys"]),
        prepoll=parse_prepoll(obj["prepoll"]),
        ballots=tuple(parse_ballot(b, m, f"ballots[{i}]")
                      for i, b in enumerate(_list(obj["ballots"], "ballots"))),
        spoils=tuple(parse_spoil(s, m, f"spoils[{i}]")
                     for i, s in enumerate(_list(obj["spoils"], "spoils"))),
        poll_register=parse_poll_register(obj["poll_register"]),
        schedule_seed=parse_schedule_opening(obj["schedule_opening"]),
        tally_aggregate=parse_tally_aggregate(obj["tally_aggregate"], m),
        decryption_transcript=parse_decryption_transcript(
            obj["decryption_transcript"], m, config.n, config.t),
        tally_declaration=parse_tally_declaration(obj["tally_declaration"], m),
    )
