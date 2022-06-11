#!/usr/bin/env python3
"""Test Shamir's secret sharing scheme"""

import unittest

from lagrange_polynomial import LagrangePolynomial

from secret_sharing import SplitSecret, combine, ORDER


SECRET = b"y"
N, M = 3, 5


class TestSecretSharing(unittest.TestCase):
    """Test secret sharing"""

    def test_poly_intersection(self) -> None:
        """Sanity-check that the curve matches the Lagrange polynomial"""
        # Flaky test, 120 != 121
        ss = SplitSecret(SECRET, N)
        shares = ss.sample(M)
        xs, ys = zip(*shares[:-1])
        lp = LagrangePolynomial(xs, ys)
        self.assertEqual(lp(1) % ss.order, ss.poly(1))

    def test_recover_secret_minimum_shares(self) -> None:
        """Split and recover a secret with n shares"""
        ss = SplitSecret(SECRET, N)
        shares = ss.sample(M)
        self.assertEqual(len(shares), M)
        for i in range(M - N):
            self.assertEqual(combine(shares[i:N + i]), SECRET)

    def test_secret_too_large(self) -> None:
        """Can't split a secret bigger than the order of the field"""
        secret = (ORDER + 5).to_bytes(32, "big")
        with self.assertRaises(RuntimeError):
            SplitSecret(secret, N)

    def test_threshold_too_large(self) -> None:
        """Can't have a threshold larger than the number of participants"""
        ss = SplitSecret(SECRET, M)
        with self.assertRaises(RuntimeError):
            ss.sample(N)

    def test_participants_too_large(self) -> None:
        """Can't have more participants than the order of the field"""
        ss = SplitSecret(SECRET, N)
        with self.assertRaises(RuntimeError):
            ss.sample(ORDER + 1)


if __name__ == "__main__":
    unittest.main(verbosity=2, buffer=True)
