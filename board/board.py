"""
board.py

Bulletin board serialisation
SPEC.md Section 14
"""

import json
import string
import hashlib
# NOTE (integration): the original C code imported ``LABELS`` here but never
# used it, and ``crypto.encoding`` does not export that name. Kept ``L`` only.
from crypto.encoding import L


def canonical_json(data):
    """
    Return canonical JSON.

    Requirements:
    - Sorted keys
    - No whitespace
    - ASCII escaping
    """

    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def serialize_board(board):
    """
    Serialize the complete bulletin board into
    canonical JSON.
    """

    return canonical_json(board)


def deserialize_board(serialized_board):
    """
    Parse a serialized bulletin board.
    """

    return json.loads(serialized_board)


def write_board(board, filename):
    """
    Write the bulletin board to disk.
    """

    serialized = serialize_board(board)

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(serialized)


def read_board(filename):
    """
    Read a bulletin board from disk.
    """

    with open(
        filename,
        "r",
        encoding="utf-8"
    ) as file:

        data = file.read()

    return deserialize_board(data)

def append_prepoll(
    board,
    randomness_commitments,
    test_schedule_commitment,
):
    """
    Append the pre-poll section to the
    bulletin board.

    Section 14:
    - randomness commitments
    - test schedule commitment
    """

    board["prepoll"] = {

        "record_type": "prepoll",

        "randomness_commitments":
            randomness_commitments,

        "test_schedule_commitment":
            test_schedule_commitment,
    }

    return board




def append_schedule_opening(
    board,
    schedule_seed,
):
    """
    Publish the revealed schedule seed
    after the poll closes.
    """

    board["schedule_opening"] = {

        "schedule_seed":
            schedule_seed,
    }

    return board

def append_ballot(
    board,
    ballot_record,
):
    """
    Append one ballot record to the
    bulletin board.

    Ballots are kept ordered by
    ballot_serial.
    """

    board["ballots"].append(
        ballot_record
    )

    board["ballots"].sort(
        key=lambda ballot:
        ballot["ballot_serial"]
    )

    return board


def append_spoil(
    board,
    spoil_record,
):
    """
    Append one spoiled ballot record.

    Spoils are kept ordered by
    ballot_serial.
    """

    board["spoils"].append(
        spoil_record
    )

    board["spoils"].sort(
        key=lambda spoil:
        spoil["ballot_serial"]
    )

    return board


def write_poll_register(
    board,
    issued,
    spoiled,
    counted,
    booth_id="BOOTH-001",
):
    """
    Write the poll register to the
    bulletin board.
    """

    board["poll_register"] = {

        "record_type":
            "poll_register",

        "booth_id":
            booth_id,

        "ballots_issued":
            issued,

        "ballots_spoiled":
            spoiled,

        "ballots_counted":
            counted,
    }

    return board

def append_decryption_transcript(
    board,
    subset,
    lagrange_coefficients,
    partials,
):
    """
    Append the threshold decryption
    transcript.

    SPEC Section 13.4
    """

    partials.sort(

        key=lambda record: (

            record["trustee_index"],

            record["candidate_index"],
        )
    )

    board["decryption_transcript"] = {

        "record_type":
            "decryption_transcript",

        "subset":
            subset,

        "lagrange_coefficients":
            lagrange_coefficients,

        "partials":
            partials,
    }

    return board

def append_threshold_transcript(
    board,
    transcript,
):
    """
    Append a threshold decryption
    transcript produced by
    threshold.py.
    """

    append_decryption_transcript(

        board,

        transcript["subset"],

        transcript["lagrange_coefficients"],

        transcript["partials"],
    )

    return board

def verify_board_structure(board):
    """
    Verify all mandatory top-level keys
    exist.
    """

    required_keys = [
        "election_config",
        "base_hash",
        "trustee_setup",
        "authority_keys",
        "prepoll",
        "ballots",
        "spoils",
        "poll_register",
        "schedule_opening",
        "tally_aggregate",
        "decryption_transcript",
        "tally_declaration",
    ]

    for key in required_keys:

        if key not in board:

            raise ValueError(
                f"Missing required key: {key}"
            )

    return True
def verify_ballot_order(board):
    """
    Verify ballots are sorted by ballot_serial.
    """

    ballots = board["ballots"]

    serials = [
        ballot["ballot_serial"]
        for ballot in ballots
    ]

    if serials != sorted(serials):

        raise ValueError(
            "Ballots are not ordered by ballot_serial."
        )

    return True

def verify_spoil_order(board):
    """
    Verify spoils are ordered by ballot_serial.
    """

    spoils = board["spoils"]

    serials = [
        spoil["ballot_serial"]
        for spoil in spoils
    ]

    if serials != sorted(serials):

        raise ValueError(
            "Spoils are not ordered by ballot_serial."
        )

    return True


def verify_candidate_order(board):
    """
    Verify ciphertexts and validity proofs
    are ordered by candidate_index.
    """

    ballots = board["ballots"]

    for ballot in ballots:

        ciphertexts = ballot["ciphertexts"]

        indices = [
            ct["candidate_index"]
            for ct in ciphertexts
        ]

        if indices != sorted(indices):

            raise ValueError(
                "Ciphertexts are not ordered by candidate_index."
            )

        proofs = ballot["validity_proofs"]

        proof_indices = [
            proof["candidate_index"]
            for proof in proofs
        ]

        if proof_indices != sorted(proof_indices):

            raise ValueError(
                "Validity proofs are not ordered by candidate_index."
            )

    return True

def is_hex384(value):
    """
    Check whether a value is a valid HEX384 string.

    A HEX384 value must:
    - be a string
    - contain exactly 768 lowercase hexadecimal characters
    """

    if not isinstance(value, str):
        return False

    if len(value) != 768:
        return False

    allowed = set(string.hexdigits.lower())

    return all(character in allowed for character in value)

def verify_hex384(board):
    """
    Verify that every HEX384 field
    has exactly 768 lowercase
    hexadecimal characters.
    """

    # Trustee commitments
    if "commitments" in board["trustee_setup"]:

        for commitment in board["trustee_setup"]["commitments"]:

            if not is_hex384(commitment["commitment"]):

                raise ValueError(
                    "Invalid trustee commitment."
                )

    # Ballot ciphertexts
    for ballot in board["ballots"]:

        for ciphertext in ballot["ciphertexts"]:

            if not is_hex384(ciphertext["alpha"]):

                raise ValueError(
                    "Invalid ciphertext alpha."
                )

            if not is_hex384(ciphertext["beta"]):

                raise ValueError(
                    "Invalid ciphertext beta."
                )

        # Validity proofs
        for proof in ballot["validity_proofs"]:

            fields = [
                "c0", "c1",
                "f0", "f1",
                "a0", "a1",
                "b0", "b1"
            ]

            for field in fields:

                if not is_hex384(proof[field]):

                    raise ValueError(
                        f"Invalid validity proof field: {field}"
                    )

        # Sum proof
        sum_proof = ballot["sum_proof"]

        for field in ["c", "f", "a", "b"]:

            if not is_hex384(sum_proof[field]):

                raise ValueError(
                    f"Invalid sum proof field: {field}"
                )

    return True

def verify_round_trip(board):
    """
    SPEC sanity check:

    serialize ->
    deserialize ->
    serialize

    must produce identical JSON.
    """

    first = serialize_board(board)

    recovered = deserialize_board(first)

    second = serialize_board(recovered)

    return first == second


def verify_board(board):
    """
    Run every bulletin-board validation.
    """

    verify_board_structure(board)
    verify_ballot_order(board)
    verify_spoil_order(board)
    verify_candidate_order(board)
    verify_hex384(board)

    if not verify_round_trip(board):

        raise ValueError(
            "Board serialization is not deterministic."
        )

    return True


'''if __name__ == "__main__":

    sample_board = {

        "election_config": {},
        "base_hash": "",
        "trustee_setup": {},
        "authority_keys": {},
        "prepoll": {},
        "ballots": [],
        "spoils": [],
        "poll_register": {},
        "schedule_opening": {},
        "tally_aggregate": {},
        "decryption_transcript": {},
        "tally_declaration": {}
    }

    print(
        serialize_board(sample_board)
    )

    print(
        verify_board(sample_board)
    )'''

    