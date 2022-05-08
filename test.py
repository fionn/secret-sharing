#!/usr/bin/env python3
"""Test Shamir's secret sharing scheme"""

import unittest

from lagrange_polynomial import LagrangePolynomial

from secret_sharing import SplitSecret, combine


PRIME = 2 ** 31 - 1
SECRET = b"yolo"
N, M = 3, 5


class TestSecretSharing(unittest.TestCase):
    """Test secret sharing"""

    def test_poly_intersection(self) -> None:
        """Sanity-check that the curve matches the Lagrange polynomial"""
        ss = SplitSecret(SECRET, N, M)
        shares = ss.sample()
        xs, ys = zip(*shares[:-1])
        lp = LagrangePolynomial(xs, ys, PRIME)
        self.assertEqual(lp(0), ss.poly(0))

    def test_recover_secret_all_shares(self) -> None:
        """Split and recover a secret with all but one share"""
        ss = SplitSecret(SECRET, N, M)
        shares = ss.sample()
        self.assertEqual(len(shares), M)
        self.assertEqual(combine(shares[:-1]), SECRET)

    def test_recover_secret_minimum_shares(self) -> None:
        """Split and recover a secret with n shares"""
        ss = SplitSecret(SECRET, N, M)
        shares = ss.sample()
        for i in range(M - N):
            self.assertEqual(combine(shares[i:N + i]), SECRET)

    def test_secret_too_large(self) -> None:
        """Can't split a secret bigger than the order of the field"""
        secret = (PRIME + 5).to_bytes(32, "big")
        with self.assertRaises(RuntimeError):
            SplitSecret(secret, N, M)

    def test_threshold_too_large(self) -> None:
        """Can't have a threshold larger than the number of participants"""
        with self.assertRaises(RuntimeError):
            SplitSecret(SECRET, M, N)

    def test_participants_too_large(self) -> None:
        """Can't have more participants than the order of the field"""
        with self.assertRaises(RuntimeError):
            SplitSecret(SECRET, N, PRIME + 1)


if __name__ == "__main__":
    unittest.main(verbosity=2, buffer=True)
