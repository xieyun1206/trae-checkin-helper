#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_ecdsa.py — ECDSA P-256 签名单元测试（自检 + 确定性 + 篡改检测）。"""

import base64
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import ecdsa  # noqa: E402


def _build_keypair(d: int) -> tuple[str, str]:
    """构造 (private_pem, public_pem)：与 ecdsa.self_test 相同的构造逻辑。"""
    d_bytes = d.to_bytes(32, "big")
    q = ecdsa._scalar_mult(d, ecdsa._G)
    qx = q[0].to_bytes(32, "big")
    qy = q[1].to_bytes(32, "big")
    pub_point = b"\x04" + qx + qy
    ec_priv = b"\x02\x01\x01" + b"\x04\x20" + d_bytes
    ec_priv += b"\xa1\x44" + b"\x03\x42\x00" + pub_point
    ec_seq = b"\x30" + ecdsa._der_len_bytes(len(ec_priv)) + ec_priv
    octet = b"\x04" + ecdsa._der_len_bytes(len(ec_seq)) + ec_seq
    alg = bytes.fromhex("301306072a8648ce3d020106082a8648ce3d030107")
    pkcs8 = b"\x02\x01\x00" + alg + octet
    pkcs8_der = b"\x30" + ecdsa._der_len_bytes(len(pkcs8)) + pkcs8
    priv_pem = "-----BEGIN PRIVATE KEY-----\n" + base64.b64encode(pkcs8_der).decode() + "\n-----END PRIVATE KEY-----\n"
    bitstr = b"\x03\x42\x00" + pub_point
    spki = alg + bitstr
    spki_der = b"\x30" + ecdsa._der_len_bytes(len(spki)) + spki
    pub_pem = "-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(spki_der).decode() + "\n-----END PUBLIC KEY-----\n"
    return priv_pem, pub_pem


class TestEcdsa(unittest.TestCase):
    def test_self_test(self):
        self.assertTrue(ecdsa.self_test())

    def test_sign_verify_roundtrip(self):
        priv_pem, pub_pem = _build_keypair(0xDEADBEEF)
        msg = os.urandom(64)
        sig = ecdsa.sign_sha256(msg, priv_pem)
        self.assertTrue(ecdsa.verify_sha256(msg, sig, pub_pem))

    def test_tamper_detection(self):
        priv_pem, pub_pem = _build_keypair(7)
        msg = b"message"
        sig = ecdsa.sign_sha256(msg, priv_pem)
        self.assertFalse(ecdsa.verify_sha256(msg + b"!", sig, pub_pem))
        self.assertFalse(ecdsa.verify_sha256(b"other", sig, pub_pem))

    def test_deterministic_signature(self):
        priv_pem, _ = _build_keypair(0x1234)
        msg = b"deterministic"
        self.assertEqual(
            ecdsa.sign_sha256(msg, priv_pem),
            ecdsa.sign_sha256(msg, priv_pem),
        )

    def test_der_signature_wellformed(self):
        priv_pem, _ = _build_keypair(42)
        sig_b64 = ecdsa.sign_sha256(b"der", priv_pem)
        der = base64.b64decode(sig_b64)
        self.assertEqual(der[0], 0x30)          # SEQUENCE
        self.assertEqual(der[1], len(der) - 2)  # 长度
        self.assertEqual(der[2], 0x02)          # INTEGER r
        self.assertGreater(len(der), 66)        # 两个 INTEGER 至少各 33 字节

    def test_bad_pem(self):
        with self.assertRaises(Exception):
            ecdsa.sign_sha256(b"x", "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----")


if __name__ == "__main__":
    unittest.main()
