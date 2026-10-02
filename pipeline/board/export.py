"""
export.py

Basket C - Export Verification

Verifies that the exported board and signature
files do not contain secret information before
they cross the air gap.
"""

import json


FORBIDDEN_FIELDS = {

    "private_key",
    "secret_key",
    "sk",
    "shares",
    "trustee_share",
    "polynomial_coefficients",
    "attack_log",
    "timing_log",
    "private_log",
}


def read_json_file(filename):
    """
    Read a JSON file.
    """

    with open(
        filename,
        "r",
        encoding="utf-8",
    ) as file:

        return json.load(file)


def write_json_file(data, filename):
    """
    Write a JSON file.
    """

    with open(
        filename,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            data,
            file,
            indent=4,
        )


def scan_for_secrets(data):
    """
    Recursively scan a JSON object for
    forbidden secret fields.
    """

    if isinstance(data, dict):

        for key, value in data.items():

            if key in FORBIDDEN_FIELDS:

                raise ValueError(
                    f"Forbidden field found: {key}"
                )

            scan_for_secrets(value)

    elif isinstance(data, list):

        for item in data:

            scan_for_secrets(item)


def export_files(
    board_filename,
    signature_filename,
):
    """
    Verify both exported files before
    crossing the air gap.
    """

    board = read_json_file(
        board_filename
    )

    signatures = read_json_file(
        signature_filename
    )

    scan_for_secrets(board)

    scan_for_secrets(signatures)

    print(
        "Export verification passed."
    )

    print(
        "Files ready for export."
    )


'''if __name__ == "__main__":

    print("Export module started")

    export_files(
        "board.json",
        "signatures.json",
    )'''