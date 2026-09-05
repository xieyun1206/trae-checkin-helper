#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_crypto.py — byteCrypto 加解密单元测试（NIST 向量 + 回环 + 容错）。"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import crypto  # noqa: E402


class TestCrypto(unittest.TestCase):
    def test_nist_vector(self):
        self.assertTrue(crypto.self_test())

    def test_roundtrip_blob(self):
        for size in (1, 16, 64, 100, 1024):
            payload = os.urandom(size)
            blob = crypto.encrypt_blob(payload)
            self.assertEqual(crypto.decrypt_blob(blob), payload)

    def test_roundtrip_string(self):
        payload = '{"token":"abc"}'.encode("utf-8")
        s = crypto.encrypt_string(payload)
        self.assertEqual(crypto.decrypt_string(s), payload)

    def test_unknown_header(self):
        with self.assertRaises(crypto.CryptoError):
            crypto.decrypt_blob(b"xx" + os.urandom(64))

    def test_short_blob(self):
        with self.assertRaises(crypto.CryptoError):
            crypto.decrypt_blob(b"tc\x05\x10\x00\x00" + os.urandom(10))

    def test_tampered_ciphertext(self):
        payload = os.urandom(64)
        blob = bytearray(crypto.encrypt_blob(payload))
        blob[-1] ^= 0xFF  # 篡改最后一字节，校验前缀应失败
        with self.assertRaises(crypto.CryptoError):
            crypto.decrypt_blob(bytes(blob))

    def test_random_key_per_encrypt(self):
        payload = b"same payload"
        b1 = crypto.encrypt_blob(payload)
        b2 = crypto.encrypt_blob(payload)
        self.assertNotEqual(b1, b2)  # 随机 key，两次密文不同
        self.assertEqual(crypto.decrypt_blob(b1), payload)
        self.assertEqual(crypto.decrypt_blob(b2), payload)


if __name__ == "__main__":
    unittest.main()
