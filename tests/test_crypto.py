"""Tests for payload encryption helpers."""

import unittest

from daemon import crypto


class DeriveKeyTests(unittest.TestCase):
    def test_derived_keys_are_32_bytes_and_deterministic(self):
        first = crypto.derive_key(b"shared secret")
        second = crypto.derive_key(b"shared secret")
        self.assertEqual(len(first), 32)
        self.assertEqual(first, second)

    def test_salt_and_info_produce_different_keys(self):
        base = crypto.derive_key(b"secret")
        self.assertNotEqual(base, crypto.derive_key(b"secret", salt=b"other"))
        self.assertNotEqual(base, crypto.derive_key(b"secret", info=b"other"))

    def test_secret_must_not_be_empty(self):
        with self.assertRaises(ValueError):
            crypto.derive_key(b"")
        with self.assertRaises(ValueError):
            crypto.derive_key(None)


@unittest.skipUnless(crypto.available(), "cryptography package is not installed")
class AesGcmTests(unittest.TestCase):
    def setUp(self):
        self.cipher = crypto.PayloadCipher(crypto.derive_key(b"shared secret"))
        self.other = crypto.PayloadCipher(crypto.derive_key(b"another secret"))

    def test_round_trip(self):
        blob = self.cipher.seal(b"hello peers", aad=b"channel")
        self.assertTrue(blob.startswith(crypto.PREFIX))
        self.assertEqual(self.cipher.open(blob, aad=b"channel"), b"hello peers")

    def test_nonce_is_unique_per_message(self):
        first = self.cipher.seal(b"same")
        second = self.cipher.seal(b"same")
        self.assertNotEqual(first, second)

    def test_tampering_is_detected(self):
        blob = bytearray(self.cipher.seal(b"hello"))
        blob[-1] ^= 0xFF
        with self.assertRaises(ValueError):
            self.cipher.open(bytes(blob))

    def test_wrong_key_fails(self):
        blob = self.cipher.seal(b"hello")
        with self.assertRaises(ValueError):
            self.other.open(blob)

    def test_aad_must_match(self):
        blob = self.cipher.seal(b"hello", aad=b"one")
        with self.assertRaises(ValueError):
            self.cipher.open(blob, aad=b"two")

    def test_plaintext_is_rejected(self):
        with self.assertRaises(ValueError):
            self.cipher.open(b'{"not": "sealed"}')

    def test_truncated_blob_is_rejected(self):
        with self.assertRaises(ValueError):
            self.cipher.open(crypto.PREFIX + b"short")

    def test_key_length_is_validated(self):
        with self.assertRaises(ValueError):
            crypto.PayloadCipher(b"too short")


if __name__ == "__main__":
    unittest.main()
