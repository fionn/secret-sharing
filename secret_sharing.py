#!/usr/bin/env python3
"""Shamir's Secret Sharing"""

import secrets
from collections.abc import Sequence

from lagrange_polynomial import LagrangePolynomial

PRIME = 2 ** 31 - 1 # The 8th Mersenne prime.

class SplitSecret:
    """Split a secret using Shamir's secret sharing scheme"""

    def __init__(self, secret: bytes, threshold: int, total: int, prime: int = PRIME) -> None:
        self.secret = int.from_bytes(secret, "big")

        if threshold > total:
            raise RuntimeError("Threshold must be less than or equal to the total")
        if total >= PRIME:
            raise RuntimeError("Too many participants")
        if self.secret >= PRIME:
            raise RuntimeError("Secret is too big for finite field")

        self.m = total
        self.prime = prime
        self.coefficients = [self.secret] + [secrets.randbelow(prime)
                                             for _ in range(threshold - 1)]

    def poly(self, x: int) -> int:
        """Evaluate the polynomial"""
        value = 0
        for i, c in enumerate(self.coefficients):
            value += (c * x ** i) % self.prime
        return value % self.prime

    def sample(self) -> list[tuple[int, int]]:
        """Grab m points on the curve"""
        return [(x, self.poly(x)) for x in range(self.m)]

def combine(sample: Sequence[tuple[int, int]], prime: int = PRIME) -> bytes:
    """Solve for the secret"""
    xs, ys = zip(*sample)
    lagrange_poly = LagrangePolynomial(xs, ys, prime)
    return lagrange_poly(0).to_bytes(32, "big").replace(b"\x00", b"")

def main() -> None:
    """Entry point"""
    secret = b"yolo"

    ss = SplitSecret(secret, 3, 5)
    shares = ss.sample()

    recovered_secret = combine(shares)
    assert secret == recovered_secret

    print(recovered_secret.decode())

if __name__ == "__main__":
    main()
