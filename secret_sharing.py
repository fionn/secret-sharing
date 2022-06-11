#!/usr/bin/env python3
"""Shamir's Secret Sharing"""

import secrets
from functools import cache
from collections.abc import Sequence

from lagrange_polynomial import LagrangePolynomial

ORDER = 256 # We default to GF(2⁸)

class SplitSecret:
    """Split a secret using Shamir's secret sharing scheme"""

    def __init__(self, secret: bytes, threshold: int, order: int = ORDER) -> None:
        self.secret = int.from_bytes(secret, "big")

        if self.secret.bit_length() >= order.bit_length():
            raise RuntimeError("Secret is too big for finite field")

        self.n = threshold
        self.order = order

    @cache
    def coefficients(self) -> list[int]:
        """Polynomial coefficients"""
        return [self.secret] + [secrets.randbelow(self.order)
                                for _ in range(self.n - 1)]

    def poly(self, x: int) -> int:
        """Evaluate the polynomial"""
        value = 0
        for i, c in enumerate(self.coefficients()):
            value += (c * x ** i) % self.order
        return value % self.order

    def sample(self, m: int) -> list[tuple[int, int]]:
        """Grab m points on the curve"""
        if m <= self.n:
            raise RuntimeError("Threshold must be less than or equal to the total")
        if m >= self.order:
            raise RuntimeError("Too many participants")

        return [(x, self.poly(x)) for x in range(1, m + 1)]


def combine(sample: Sequence[tuple[int, int]], order: int = ORDER) -> bytes:
    """Solve for the secret"""
    xs, ys = zip(*sample)
    lp = LagrangePolynomial(xs, ys, order)
    return lp(0).to_bytes(order.bit_length() // 8, "big").replace(b"\x00", b"")


def main() -> None:
    """Entry point"""
    secret = b"y"
    n, m = 3, 5

    ss = SplitSecret(secret, n)
    shares = ss.sample(m)

    recovered_secret = combine(shares[:n])
    assert secret == recovered_secret

    print(recovered_secret.decode())

if __name__ == "__main__":
    main()
