"""
authority.py

Basket C - Authority Key Initialization

Generates the official Ed25519 key pairs for
the presiding officer and party agents.

Only public keys are published on the bulletin board.
Private keys remain secret.
"""
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)
def generate_key_pair():
    """
    Generate one Ed25519 key pair.
    """

    private_key = Ed25519PrivateKey.generate()

    public_key = private_key.public_key()

    return private_key, public_key

def public_key_to_hex(public_key):
    """
    Convert an Ed25519 public key into
    a 64-character lowercase hexadecimal string.
    """

    public_bytes = public_key.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )

    return public_bytes.hex()

def public_key_from_hex(public_key_hex):
    """
    Convert a 64-character hexadecimal string
    into an Ed25519 public key object.
    """

    public_bytes = bytes.fromhex(public_key_hex)

    return Ed25519PublicKey.from_public_bytes(
        public_bytes
    )

def initialize_authority_keys(number_of_agents, k):
    """
    Generate the official authority keys for
    the presiding officer and party agents.
    """
    officer_private_key, officer_public_key = (
        generate_key_pair()
    )
    authority_keys = {

    "record_type": "authority_keys",

    "k": k,

    "officer": public_key_to_hex(
        officer_public_key
    ),

    "agents": []
    }
    private_keys = {

        "officer": officer_private_key,

        "agents": []
    }
    for agent_index in range(number_of_agents):

        private_key, public_key = generate_key_pair()

        private_keys["agents"].append(
            private_key
        )

        authority_keys["agents"].append(
            {

                "agent_index": agent_index,

                "public_key": public_key_to_hex(
                    public_key
                )
            }
        )
    return authority_keys, private_keys

'''if __name__ == "__main__":

    authority_keys, private_keys = initialize_authority_keys(
    number_of_agents=3,
    k=2,
    )

    print(authority_keys)
    print()

    print(type(private_keys["officer"]))

    print(len(private_keys["agents"]))'''