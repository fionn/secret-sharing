#!/usr/bin/env python3
"""Shamir's Secret Sharing"""

import secrets
from typing import Sequence

from lagrange_polynomial import LagrangePolynomial # type: ignore

PRIME = 2 ** 31 - 1 # 8th Mersenne prime

class SplitSecret:
    """Split a secret using Shamir's secret sharing scheme"""

    def __init__(self, secret: bytes, threshold: int, total: int) -> None:
        self._secret = secret
        self._m = total
        self._coefficients = self._generate_coefficients(threshold - 1)

    def _generate_coefficients(self, degree: int) -> list:
        c = [int.from_bytes(self._secret, "big")]
        for _ in range(degree):
            c.append(secrets.randbelow(PRIME))
        return c

    def _poly(self, x: int) -> int:
        value = 0
        for i in range(len(self._coefficients)):
            value += self._coefficients[i] * x ** i
        return value

    def sample(self) -> list:
        """Grab a bunch of points on the curve"""
        samples = []
        for _ in range(self._m):
            x = secrets.randbelow(PRIME)
            samples.append((x, self._poly(x)))
        return samples

def combine(xs: Sequence[float], ys: Sequence[float]) -> int:
    """Solve for the secret"""
    lagrange_poly = LagrangePolynomial(xs, ys)
    return int(round(lagrange_poly(0)))

def main() -> None:
    """Entry point"""
    secret = b"yolo"
    ss = SplitSecret(secret, 2, 3)
    sample = ss.sample()

    xs, ys = zip(*sample)

    int_secret = combine(xs, ys)
    recovered_secret = int_secret.to_bytes(32, "big").replace(b"\x00", b"")
    print(recovered_secret)

if __name__ == "__main__":
    main()
