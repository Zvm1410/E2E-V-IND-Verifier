from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)

from crypto.encoding import L
from board.authority import (
    initialize_authority_keys,
    public_key_from_hex,
)
import json

def create_signature_message(digest):
    """
    Create the message to be signed.

    Message =
    L("EVOTE-SIG-v1") || digest
    """

    if isinstance(digest, str):
        digest = bytes.fromhex(digest)

    return L("EVOTE-SIG-v1") + digest



def sign_message(private_key, message):
    """
    Sign a message using an Ed25519 private key.
    """

    return private_key.sign(message)

def verify_signature(public_key, message, signature):
    """
    Verify an Ed25519 signature.

    Returns:
        True if the signature is valid.
        False otherwise.
    """

    try:
        public_key.verify(signature, message)
        return True

    except Exception:
        return False

def verify_multisignature(
    
    officer_public_key,
    officer_signature,
    agent_public_keys,
    agent_signatures,
    message,
    k,
):
    """
    Verify the officer signature and at least
    k valid agent signatures.
    """

    if not verify_signature(
        officer_public_key,
        message,
        officer_signature,
    ):
        return False

    valid_agents = 0

    for index in range(
        min(
            len(agent_public_keys),
            len(agent_signatures),
        )
    ):

        if verify_signature(
            agent_public_keys[index],
            message,
            agent_signatures[index],
        ):
            valid_agents += 1

    return valid_agents >= k

def create_signature_file(
    digest_hex,
    officer_signature,
    agent_signatures,
):
    """
    Create the signature record defined
    in Section 15.3.
    """

    return {

        "digest": digest_hex,

        "officer_signature": officer_signature.hex(),

        "agent_signatures": [

            {

                "agent_index": index,

                "signature": signature.hex()

            }

            for index, signature in enumerate(
                agent_signatures
            )

        ],
    }

def write_signature_file(signature_file, filename):
    """
    Write the signature file to JSON.
    """

    with open(
        filename,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            signature_file,
            file,
            indent=4,
        )

'''if __name__ == "__main__":

    digest = "a" * 64

    message = create_signature_message(digest)

    print("Message length:", len(message))
    print("Message:", message)

    # ----------------------------------
    # Generate authority keys
    # ----------------------------------

    keys, private_keys = initialize_authority_keys(
        number_of_agents=3,
        k=2,
    )

    # Officer

    officer_signature = sign_message(
        private_keys["officer"],
        message,
    )

    officer_public_key = public_key_from_hex(
        keys["officer"]
    )

    # Agents

    agent_public_keys = []
    agent_signatures = []

    for index, private_key in enumerate(
        private_keys["agents"]
    ):

        signature = sign_message(
            private_key,
            message,
        )

        agent_signatures.append(signature)

        public_key = public_key_from_hex(
            keys["agents"][index]["public_key"]
        )

        agent_public_keys.append(public_key)

    print(
        "Multisignature Valid:",
        verify_multisignature(
            officer_public_key,
            officer_signature,
            agent_public_keys,
            agent_signatures,
            message,
            k=2,
        ),
    )

    print(
        "Multisignature with one agent:",
        verify_multisignature(
            officer_public_key,
            officer_signature,
            agent_public_keys[:1],
            agent_signatures[:1],
            message,
            k=2,
        ),
    )
    print()

    signature_file = create_signature_file(

    digest,

    officer_signature,

    agent_signatures,

)
    write_signature_file(
    signature_file,
    "signatures.json",
)
    print(
    "Signature file written successfully."
)

print("Signature File:")

    print(
    json.dumps(
        signature_file,
        indent=4,
    )
)'''