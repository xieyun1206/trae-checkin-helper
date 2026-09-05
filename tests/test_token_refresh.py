#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_token_refresh.py — Token 刷新（登录态保持）单元测试。
覆盖：DeviceProof 消息格式、x-cloudide-token 请求头、Result 响应解析、
成功写回 / 401 / 缺凭据 / 业务错误 各分支。
"""

import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import config  # noqa: E402
import credentials  # noqa: E402
import crypto  # noqa: E402
import ecdsa  # noqa: E402
import token_refresh  # noqa: E402
from test_ecdsa import _build_keypair  # noqa: E402

AUTH_KEY = config.AUTH_KEY_MAIN

# 构造用测试密钥对（真实 ECDSA，便于验证签名可被公钥验证）
_TEST_PRIV, _TEST_PUB = _build_keypair(0x5EED)


def _make_storage() -> dict:
    auth = {
        "token": "tok-old",
        "refreshToken": "rf-xyz",
        "expiredAt": "2026-09-19T02:29:36.769Z",
        "userId": "u12345",
        "host": "https://api.trae.cn",
        "account": {"scope": "marscode"},
    }
    dev = {"privateKeyPEM": _TEST_PRIV, "publicKeyPEM": _TEST_PUB}
    return {
        AUTH_KEY: crypto.encrypt_string(json.dumps(auth).encode("utf-8")),
        config.DEVICE_KEY_PREFIX + "dev123": crypto.encrypt_string(
            json.dumps(dev).encode("utf-8")
        ),
        config.USERTAG_KEY: crypto.encrypt_string(b'{"u12345":"cn"}'),
    }


class ParseResponseTestCase(unittest.TestCase):
    def test_result_wrapped(self):
        body = {
            "ResponseMetadata": {"RequestId": "x"},
            "Result": {
                "Token": "new-tok",
                "RefreshToken": "new-rf",
                "TokenExpireAt": 1766134304000,
                "RefreshExpireAt": "2027-03-04T02:29:36.769Z",
            },
        }
        parsed = token_refresh._parse_exchange_response(body)
        self.assertEqual(parsed["token"], "new-tok")
        self.assertEqual(parsed["refresh_token"], "new-rf")
        # TokenExpireAt 毫秒时间戳 → 归一化为 ISO 格式
        self.assertRegex(parsed["expired_at"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")

    def test_data_wrapped(self):
        body = {"code": 0, "data": {"Token": "t2", "RefreshToken": "r2"}}
        parsed = token_refresh._parse_exchange_response(body)
        self.assertEqual(parsed["token"], "t2")

    def test_flat(self):
        body = {"Token": "t3"}
        parsed = token_refresh._parse_exchange_response(body)
        self.assertEqual(parsed["token"], "t3")
        self.assertEqual(parsed["refresh_token"], "")

    def test_missing_token(self):
        self.assertIsNone(token_refresh._parse_exchange_response({"Result": {}}))
        self.assertIsNone(token_refresh._parse_exchange_response({"code": 500}))
        self.assertIsNone(token_refresh._parse_exchange_response({"data": []}))

    def test_expire_iso_and_garbage(self):
        body = {"Result": {"Token": "t", "TokenExpireAt": "2026-10-01T00:00:00.000Z"}}
        self.assertEqual(
            token_refresh._parse_exchange_response(body)["expired_at"],
            "2026-10-01T00:00:00.000Z",
        )
        body = {"Result": {"Token": "t", "TokenExpireAt": "not-a-number"}}
        self.assertEqual(token_refresh._parse_exchange_response(body)["expired_at"], "")


class ResponseErrorTestCase(unittest.TestCase):
    def test_meta_error(self):
        body = {"ResponseMetadata": {"Error": {"Code": "20324", "Message": "boom"}}}
        self.assertEqual(token_refresh._response_error(body), "20324 boom")

    def test_no_error(self):
        self.assertEqual(token_refresh._response_error({"Result": {"Token": "t"}}), "")
        self.assertEqual(token_refresh._response_error({}), "")


class DeviceProofTestCase(unittest.TestCase):
    def test_message_signature_verifiable(self):
        cred = {
            "device_id": "dev123",
            "private_key_pem": _TEST_PRIV,
            "public_key_pem": _TEST_PUB,
            "access_token": "tok",
            "refresh_token": "rf-xyz",
        }
        proof = token_refresh._device_proof(cred, "rf-xyz")
        self.assertIsInstance(proof["Timestamp"], int)
        self.assertEqual(len(proof["Nonce"]), 32)  # 16 字节 hex
        message = "\n".join(
            ["POST", config.EXCHANGE_TOKEN_PATH, config.client_id(), "rf-xyz",
             str(proof["Timestamp"]), proof["Nonce"]]
        ).encode("utf-8")
        self.assertTrue(
            ecdsa.verify_sha256(message, proof["Signature"], _TEST_PUB)
        )

    def test_device_info_solo_pc(self):
        cred = {"device_id": "dev123", "public_key_pem": "pub"}
        info = token_refresh._device_info(cred)
        self.assertEqual(info["PlatformCode"], "SOLO_PC")
        self.assertEqual(info["DeviceType"], "PC")
        self.assertEqual(info["DeviceID"], "dev123")


class RefreshTokenTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmpdir = self._tmp.name
        self.path = os.path.join(self.tmpdir, "storage.json")
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(_make_storage(), f)
        self.env_patch = mock.patch.dict(
            os.environ, {"TRAE_CHECKIN_STORAGE": self.path}, clear=False
        )
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)

    def _ok_body(self):
        return {
            "ResponseMetadata": {},
            "Result": {
                "Token": "new-tok",
                "RefreshToken": "new-rf",
                "TokenExpireAt": 1766134304000,
                "RefreshExpireAt": "2027-03-04T02:29:36.769Z",
            },
        }

    def test_success_write_back(self):
        with mock.patch.object(
            token_refresh.http_client, "post_json", return_value=(200, self._ok_body())
        ) as req:
            result = token_refresh.refresh_token()
        self.assertEqual(result["status"], "ok")
        self.assertTrue(os.path.isfile(result["backup"]))
        # 请求头用 x-cloudide-token，不用 Authorization
        headers = req.call_args[1]["extra_headers"]
        self.assertEqual(headers["x-cloudide-token"], "tok-old")
        self.assertFalse(req.call_args[1]["use_auth_header"])
        # 写回后重新读取验证
        cred2 = credentials.load_credentials()
        self.assertEqual(cred2["access_token"], "new-tok")
        self.assertEqual(cred2["refresh_token"], "new-rf")

    def test_success_memory_only(self):
        with mock.patch.object(
            token_refresh.http_client, "post_json", return_value=(200, self._ok_body())
        ):
            result = token_refresh.refresh_token(write_back=False)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["cred"]["access_token"], "new-tok")
        # 未写回：storage.json 中仍是旧 token
        cred = credentials.load_credentials()
        self.assertEqual(cred["access_token"], "tok-old")

    def test_401(self):
        with mock.patch.object(
            token_refresh.http_client, "post_json", return_value=(401, {})
        ):
            result = token_refresh.refresh_token()
        self.assertEqual(result["status"], "failed")
        self.assertIn("401", result["reason"])

    def test_business_error_meta(self):
        body = {"ResponseMetadata": {"Error": {"Code": "20324", "Message": "too many"}}}
        with mock.patch.object(
            token_refresh.http_client, "post_json", return_value=(200, body)
        ):
            result = token_refresh.refresh_token()
        self.assertEqual(result["status"], "failed")
        self.assertIn("20324", result["reason"])

    def test_missing_token_field(self):
        with mock.patch.object(
            token_refresh.http_client, "post_json", return_value=(200, {"Result": {}})
        ):
            result = token_refresh.refresh_token()
        self.assertEqual(result["status"], "failed")
        self.assertIn("Token", result["reason"])

    def test_http_error(self):
        with mock.patch.object(
            token_refresh.http_client, "post_json", return_value=(500, {})
        ):
            result = token_refresh.refresh_token()
        self.assertEqual(result["status"], "failed")
        self.assertIn("500", result["reason"])

    def test_no_refresh_token(self):
        auth = {"token": "tok", "host": "h"}
        storage = {AUTH_KEY: crypto.encrypt_string(json.dumps(auth).encode("utf-8"))}
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(storage, f)
        result = token_refresh.refresh_token()
        self.assertEqual(result["status"], "skipped")
        self.assertIn("refreshToken", result["reason"])

    def test_no_private_key(self):
        auth = {"token": "tok", "refreshToken": "rf", "host": "h"}
        storage = {AUTH_KEY: crypto.encrypt_string(json.dumps(auth).encode("utf-8"))}
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(storage, f)
        result = token_refresh.refresh_token()
        self.assertEqual(result["status"], "skipped")
        self.assertIn("密钥", result["reason"])

    def test_transport_error(self):
        with mock.patch.object(
            token_refresh.http_client,
            "post_json",
            side_effect=token_refresh.http_client.HttpTransportError("timeout"),
        ):
            result = token_refresh.refresh_token()
        self.assertEqual(result["status"], "failed")
        self.assertIn("网络", result["reason"])


if __name__ == "__main__":
    unittest.main()
