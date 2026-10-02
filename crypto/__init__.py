"""crypto/ package: Basket B (ballot cryptography).

INTEGRATION NOTE
----------------
Basket B was authored as a flat module tree with absolute imports
(``from group import P as p``, ``from encoding import I2B``, etc.).
The integrated project puts those modules under the ``crypto`` package
so Basket C can address them as ``crypto.group``, ``crypto.encoding``.

To keep Basket B's internal absolute imports working *without editing
Basket B's source*, this package inserts its own directory on
``sys.path`` at import time. That gives every module inside ``crypto/``
two valid import paths:

    from crypto.group import P, Q, G          # package form (C's convention)
    from group import P, Q, G                 # flat form (B's convention)

Both resolve to the same module object because Python's import cache is
keyed on the module name; ``crypto.group`` and ``group`` end up as the
same file loaded twice with two names. This is intentional: rather
than rewriting Basket B, we accept two module names for the same code.

DUPLICATE FILES ELIMINATED
--------------------------
Basket C originally shipped its own ``crypto/`` folder that was a
byte-identical copy of five Basket B files (group.py, encoding.py,
membership.py, elgamal.py, cp_proof.py). Diff confirmed. Rather than
carry two copies that will drift, this package holds the Basket B
originals and the Basket C code (tally/, board/) imports from here.
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
