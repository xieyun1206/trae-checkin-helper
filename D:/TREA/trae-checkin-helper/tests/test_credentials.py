#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_credentials.py — 登录态读取 / 解密 / device id / 刷新写回 单元测试。
构造临时 storage.json（crypto.encrypt_string 加密模拟数据），不依赖真实环境。
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

AUTH_KEY = config.AUTH_KEY_MAIN


def _make_storage(overrides: dict | None = None, device_id: str = "dev123") -> dict:
    auth = {
        "token": "tok-abc",
        "refreshToken": "rf-xyz",
        "expiredAt": "2026-09-19T02:29:36.769Z",
        "userId": "u12345",
        "host": "https://api.trae.cn",
        "account": {"scope": "marscode"},
    }
    dev = {"privateKeyPEM": "p", "publicKeyPEM": "q"}
    storage = {
        AUTH_KEY: crypto.encrypt_string(json.dumps(auth).encode("utf-8")),
        config.DEVICE_KEY_PREFIX + device_id: crypto.encrypt_string(json.dumps(dev).encode("utf-8")),
        config.USERTAG_KEY: crypto.encrypt_string(b'{"u12345":"cn"}'),
        "some.other.key": "plain-value",
    }
    if overrides:
        storage.update(overrides)
    return storage


def _write_storage(tmpdir: str, storage: dict) -> str:
    path = os.path.join(tmpdir, "storage.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(storage, f)
    return path


class CredentialsTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmpdir = self._tmp.name
        self.path = _write_storage(self.tmpdir, _make_storage())
        self.env_patch = mock.patch.dict(
            os.environ, {"TRAE_CHECKIN_STORAGE": self.path}, clear=False
        )
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)

    def test_load_full(self):
        cred = credentials.load_credentials()
        self.assertEqual(cred["access_token"], "tok-abc")
        self.assertEqual(cred["refresh_token"], "rf-xyz")
        self.assertEqual(cred["host"], "https://api.trae.cn")
        self.assertEqual(cred["user_id"], "u12345")
        self.assertEqual(cred["device_id"], "dev123")
        self.assertEqual(cred["private_key_pem"], "p")
        self.assertEqual(cred["public_key_pem"], "q")
        self.assertEqual(cred["source"], self.path)

    def test_missing_main_entry(self):
        path = _write_storage(self.tmpdir, {"other": "v"})
        with mock.patch.dict(os.environ, {"TRAE_CHECKIN_STORAGE": path}, clear=False):
            with self.assertRaises(credentials.CredentialError):
                credentials.load_credentials()

    def test_missing_file(self):
        with mock.patch.dict(
            os.environ, {"TRAE_CHECKIN_STORAGE": os.path.join(self.tmpdir, "nope.json")}, clear=False
        ):
            with self.assertRaises(credentials.CredentialError):
                credentials.load_credentials()

    def test_no_device_key(self):
        # 设备密钥缺失：签到可用，仅刷新不可用
        auth = {"token": "tok", "refreshToken": "rf", "host": "h"}
        storage = {AUTH_KEY: crypto.encrypt_string(json.dumps(auth).encode("utf-8"))}
        path = _write_storage(self.tmpdir, storage)
        with mock.patch.dict(os.environ, {"TRAE_CHECKIN_STORAGE": path}, clear=False):
            cred = credentials.load_credentials()
            self.assertEqual(cred["access_token"], "tok")
            self.assertEqual(cred["device_id"], "")
            self.assertEqual(cred["private_key_pem"], "")

    def test_is_token_expired(self):
        cred = credentials.load_credentials()
        # expiredAt = 2026-09-19T02:29:36.769Z（未来）
        self.assertFalse(credentials.is_token_expired(cred))
        cred["expired_at"] = "2020-01-01T00:00:00.000Z"
        self.assertTrue(credentials.is_token_expired(cred))
        cred["expired_at"] = ""
        self.assertFalse(credentials.is_token_expired(cred))
        cred["expired_at"] = "garbage"
        self.assertFalse(credentials.is_token_expired(cred))

    def test_save_refreshed_token(self):
        cred = credentials.load_credentials()
        result = credentials.save_refreshed_token(
            cred, new_token="new-tok", new_refresh_token="new-rf",
            expired_at="2027-01-01T00:00:00.000Z",
        )
        self.assertEqual(result["status"], "ok")
        self.assertTrue(os.path.isfile(result["backup"]))
        # 重新读取：token 已更新，其它条目保留
        cred2 = credentials.load_credentials()
        self.assertEqual(cred2["access_token"], "new-tok")
        self.assertEqual(cred2["refresh_token"], "new-rf")
        self.assertEqual(cred2["device_id"], "dev123")  # 其它条目不受影响

    def test_save_backup_keeps_other_keys(self):
        cred = credentials.load_credentials()
        credentials.save_refreshed_token(cred, "t2", "r2")
        with open(self.path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["some.other.key"], "plain-value")
        self.assertIn(config.USERTAG_KEY, data)

    def test_describe_masks_secrets(self):
        cred = credentials.load_credentials()
        d = credentials.describe(cred)
        self.assertNotIn("tok-abc", json.dumps(d))
        self.assertEqual(d["access_token"].startswith("<已读取"), True)


if __name__ == "__main__":
    unittest.main()
