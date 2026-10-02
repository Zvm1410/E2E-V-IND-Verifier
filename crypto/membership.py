"""
Subgroup membership, SPEC section 2.1. The group parameters (p, q, g), their
load-time assertions and the pinned digest checks live in group.py and are
imported, never redefined here.
"""

from group import P as p, Q as q  # group parameters

def in_group(x: int) -> bool:
    """
    SPEC.md 2.1 -- membership in G, the order-q subgroup of (Z/pZ)*.

        in_group(x)  :<=>  0 < x < p  and  x^q == 1 (mod p)

    Since q = (p-1)/2, the exponentiation is Euler's criterion, i.e. the
    Legendre symbol test: it returns 1 exactly when x is a quadratic
    residue mod p. For the safe prime p = 2q+1 the quadratic residues are
    exactly the elements of G, so one modular exponentiation decides
    membership.

    Two points the spec calls out explicitly, both easy to get wrong:

    1. The exponentiation alone rejects order 2. The unique order-2
       element is p-1; q is odd, so (p-1)^q = (-1)^q = -1 = p-1 != 1.
       The lower bound does no part of that work and must not be
       justified by it.

    2. The lower bound is 0 < x, NOT 1 < x. The identity is a legitimate
       member of G and honest values can equal it: the simulated-branch
       commitment a_d = g^{f_d} * alpha^{-c_d} is 1 whenever
       f_d = r*c_d (mod q), which no sampling range can exclude.
       Excluding the identity here would admit a nonzero clean-mode
       false rejection rate, which section 16 forbids outright.

    Where the identity is genuinely not acceptable -- a ciphertext
    component, where alpha = 1 means the encryption randomness was zero
    and the vote is readable off the board with no key -- it is rejected
    by the named check at section 8.3 check 2, NOT by folding the
    condition into this function. Do not "harden" in_group by tightening
    the lower bound; that reintroduces the false rejection in point 2.

    Reference for the number theory: Euler's criterion / Legendre symbol
    by exponentiation, Menezes, van Oorschot & Vanstone, Handbook of
    Applied Cryptography, fact 2.135 and section 4.5.2, CRC Press 1996.
    """
    return 0 < x < p and pow(x, q, p) == 1


def in_exponent_range(x: int) -> bool:
    """
    SPEC.md 2.1, final paragraph -- the range check the verifier applies
    to every challenge and every response it parses.

        0 <= x < q

    Kept here beside in_group because 2.1 specifies the two together and
    because mixing element-space and exponent-space values is, per
    section 1, the single most common bug in this kind of code. Note the
    bounds differ from in_group: exponents admit zero, elements do not.
    """
    return 0 <= x < q
