import hashlib

from board.board import serialize_board
from crypto.encoding import L

def compute_board_digest(board):
    """
    Compute the bulletin board digest.

    D = SHA256(
        L("EVOTE-BOARD-v1") ||
        canonical bytes
    )
    """

    canonical = serialize_board(board).encode("utf-8")

    preimage = (
        L("EVOTE-BOARD-v1")
        + canonical
    )

    digest = hashlib.sha256(
        preimage
    ).hexdigest()

    return digest

'''if __name__ == "__main__":

    board = {

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

    digest1 = compute_board_digest(board)

    print("Original Digest:")
    print(digest1)
    #board["base_hash"] = "a" #sanity check

    digest2 = compute_board_digest(board)

    print("\nModified Digest:")
    print(digest2)

    print("\nDigest Changed:", digest1 != digest2)'''