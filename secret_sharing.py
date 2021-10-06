#!/usr/bin/env python3
"""Shamir's Secret Sharing"""

import secrets
from collections.abc import Sequence

from lagrange_polynomial import LagrangePolynomial # type: ignore

PRIME = 131071  # 2 ** 17 - 1 is the 6th Mersenne prime.

class SplitSecret:
    """Split a secret using Shamir's secret sharing scheme"""

    def __init__(self, secret: bytes, threshold: int, total: int) -> None:
        int_secret = int.from_bytes(secret, "big")
        if int_secret >= PRIME:
            raise RuntimeError("Secret is too big for finite field")
        self._m = total
        self._coefficients = self._generate_coefficients(int_secret,
                                                         threshold - 1)

    @staticmethod
    def _generate_coefficients(secret: int, degree: int) -> list:
        c = [secret]
        for _ in range(degree):
            c.append(secrets.randbelow(PRIME))
        return c

    def poly(self, x: int) -> int:
        """Evaluate the polynomial"""
        value = 0
        for i, c in enumerate(self._coefficients):
            value += (c * x ** i) % PRIME
        return value % PRIME

    def sample(self) -> list:
        """Grab a bunch of points on the curve"""
        samples = []
        for _ in range(self._m):
            x = secrets.randbelow(PRIME)
            samples.append((x, self.poly(x)))
        return samples

def combine(xs: Sequence[float], ys: Sequence[float]) -> int:
    """Solve for the secret"""
    lagrange_poly = LagrangePolynomial(xs, ys, PRIME)
    return lagrange_poly(0)

def main() -> None:
    """Entry point"""
    secret = b"y"
    ss = SplitSecret(secret, 3, 5)
    sample = ss.sample()

    xs, ys = zip(*sample)

    lp = LagrangePolynomial(xs, ys, PRIME)
    print(lp(0), ss.poly(0), int.from_bytes(secret, "big"))
    assert lp(0) == ss.poly(0)

    int_secret = combine(xs, ys)
    recovered_secret = int_secret.to_bytes(32, "big").replace(b"\x00", b"")
    print(recovered_secret)

if __name__ == "__main__":
    main()
