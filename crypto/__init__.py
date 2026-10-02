"""Ballot cryptography: group, encoding, ElGamal, proofs, base hash.

The modules here use flat absolute imports among themselves (``from group
import P``). This package puts its own directory on ``sys.path`` at import
time so that both forms resolve:

    from crypto.group import P, Q, G          # package form, used by tally/ and board/
    from group import P, Q, G                 # flat form, used inside crypto/

Python's import cache is keyed on the module name, so ``crypto.group`` and
``group`` are the same file loaded under two names.
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
