"""Compatibility shim.

Basket A originally kept a copy of the bulletin-board serializer here so
its stub could run without Basket C. In the integrated project the real
implementation lives in ``board.board`` (from Basket C). This module
re-exports the public API so any A-side code that still imports
``app.services.board`` continues to work without a rewrite.

INTEGRATION NOTE: the original file imported ``LABELS`` from
``crypto.encoding``, which never existed in Basket B's encoder. That
import was dead and has been removed in ``board.board``.
"""

from board.board import (  # noqa: F401  (re-exports)
    canonical_json,
    serialize_board,
    deserialize_board,
    write_board,
    read_board,
    append_prepoll,
    append_schedule_opening,
    append_ballot,
    append_spoil,
    write_poll_register,
    append_decryption_transcript,
    append_threshold_transcript,
    verify_board,
    verify_board_structure,
    verify_ballot_order,
    verify_spoil_order,
    verify_candidate_order,
    verify_hex384,
    verify_round_trip,
    is_hex384,
)
