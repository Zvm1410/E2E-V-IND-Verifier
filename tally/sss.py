import random
from crypto.group import Q as q

PRIME = q


def generate_coefficients(secret, threshold, seed):
    """
    Generate the coefficients of the random polynomial.

    Parameters:
        secret (int): The secret to be shared.
        threshold (int): Minimum shares required to reconstruct.
        seed (int): Seed for deterministic randomness.

    Returns:
        list: Polynomial coefficients.
    """

    rng = random.Random(seed)

    coefficients = [secret]

    for _ in range(threshold - 1):
        coefficients.append(rng.randint(1, PRIME - 1))

    return coefficients


def evaluate_polynomial(coefficients, x):
    """
    Evaluate the polynomial at a given x value.
    """

    result = 0

    for power, coefficient in enumerate(coefficients):
        result += coefficient * (x ** power)

    return result % PRIME


def split_secret(secret, threshold, num_shares, seed):
    """
    Split the secret into shares.

    Parameters:
        secret (int): Secret to split.
        threshold (int): Minimum shares needed.
        num_shares (int): Total number of shares.
        seed (int): Seed for deterministic randomness.

    Returns:
        list: List of (x, y) shares.
    """

    coefficients = generate_coefficients(secret, threshold, seed)

    shares = []

    for x in range(1, num_shares + 1):
        y = evaluate_polynomial(coefficients, x)
        shares.append((x, y))

    return shares


def mod_inverse(number):
    """
    Compute the modular inverse of a number modulo PRIME.
    """
    return pow(number, -1, PRIME)


def lagrange_interpolation(shares):
    """
    Reconstruct the secret using Lagrange interpolation.
    """

    secret = 0

    for i, (x_i, y_i) in enumerate(shares):

        lagrange = 1

        for j, (x_j, _) in enumerate(shares):

            if i != j:

                numerator = -x_j
                denominator = x_i - x_j

                inverse = mod_inverse(denominator)

                lagrange *= numerator * inverse
                lagrange %= PRIME

        secret += y_i * lagrange
        secret %= PRIME

    return secret


def reconstruct_secret(shares):
    """
    Recover the original secret from the given shares.
    """
    return lagrange_interpolation(shares)


'''if __name__ == "__main__":

    # Step 1: Split the secret
    shares = split_secret(
        secret=1234,
        threshold=3,
        num_shares=5,
        seed=42
    )

    print("Generated Shares:\n")

    for share in shares:
        print(share)

    # Step 2: Select any 3 shares
    selected_shares = shares[:3]

    # Step 3: Recover the secret
    recovered_secret = reconstruct_secret(selected_shares)

    print("\nSelected Shares:")

    for share in selected_shares:
        print(share)

    print(f"\nRecovered Secret: {recovered_secret}")'''