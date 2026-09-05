#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_checkin.py — 签到状态机单元测试（mock HTTP，验证防重复 / 幂等 / 401 刷新重试）。"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import checkin  # noqa: E402
import credentials  # noqa: E402

CRED = {
    "access_token": "tok",
    "refresh_token": "rf",
    "host": "https://api.trae.cn",
    "user_id": "u1",
    "device_id": "dev123",
    "private_key_pem": "p",
    "public_key_pem": "q",
    "expired_at": "",
    "source": "",
}


def _status_body(enable=True, checked_in=False, credits=100):
    return {"code": 0, "data": {"enable": enable, "checked_in": checked_in, "credits": credits}}


class CheckinTestCase(unittest.TestCase):
    def test_checked_in_short_circuit(self):
        """防重复：checked_in=true 时不发起 claim。"""
        with mock.patch.object(
            checkin.http_client, "request_json",
            return_value=(200, _status_body(checked_in=True)),
        ) as req:
            result = checkin.run_checkin(CRED)
        self.assertEqual(result["status"], "already_checked")
        self.assertEqual(req.call_count, 1)  # 只调了 status，未调 claim
        url = req.call_args[0][1]
        self.assertTrue(url.endswith("/status"))

    def test_enable_false_skipped(self):
        with mock.patch.object(
            checkin.http_client, "request_json",
            return_value=(200, _status_body(enable=False)),
        ) as req:
            result = checkin.run_checkin(CRED)
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(req.call_count, 1)

    def test_claim_success(self):
        responses = [
            (200, _status_body(checked_in=False)),
            (200, {"code": 0, "credit": 100}),
        ]
        with mock.patch.object(
            checkin.http_client, "request_json", side_effect=responses
        ) as req:
            result = checkin.run_checkin(CRED)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["credit"], 100)
        self.assertEqual(req.call_count, 2)
        claim_url = req.call_args_list[1][0][1]
        self.assertTrue(claim_url.endswith("/claim"))

    def test_claim_already_checked_idempotent(self):
        """幂等兜底：claim 返回 code=10001 不视为失败。"""
        responses = [
            (200, _status_body(checked_in=False)),
            (200, {"code": 10001, "msg": "already checked"}),
        ]
        with mock.patch.object(checkin.http_client, "request_json", side_effect=responses):
            result = checkin.run_checkin(CRED)
        self.assertEqual(result["status"], "already_checked")

    def test_claim_business_error(self):
        responses = [
            (200, _status_body(checked_in=False)),
            (200, {"code": 10002, "msg": "biz error"}),
        ]
        with mock.patch.object(checkin.http_client, "request_json", side_effect=responses):
            result = checkin.run_checkin(CRED)
        self.assertEqual(result["status"], "failed")
        self.assertIn("10002", result["reason"])

    def test_status_protocol_error(self):
        """status 响应缺 enable/checked_in → 协议异常，不 claim。"""
        with mock.patch.object(
            checkin.http_client, "request_json",
            return_value=(200, {"code": 0, "data": {"foo": 1}}),
        ) as req:
            result = checkin.run_checkin(CRED)
        self.assertEqual(result["status"], "failed")
        self.assertIn("协议", result["reason"])
        self.assertEqual(req.call_count, 1)

    def test_status_http_error(self):
        with mock.patch.object(
            checkin.http_client, "request_json", return_value=(500, {})
        ):
            result = checkin.run_checkin(CRED)
        self.assertEqual(result["status"], "failed")
        self.assertIn("500", result["reason"])

    def test_network_error(self):
        with mock.patch.object(
            checkin.http_client, "request_json",
            side_effect=checkin.http_client.HttpTransportError("conn refused"),
        ):
            result = checkin.run_checkin(CRED)
        self.assertEqual(result["status"], "failed")
        self.assertIn("网络异常", result["reason"])

    def test_401_with_refresh_retry_success(self):
        """401 → 回调刷新成功 → 用新登录态重试并成功。"""
        new_cred = dict(CRED, access_token="new-tok")
        responses = [
            (401, {}),                      # status 401
            (200, _status_body(checked_in=False)),  # 重试 status
            (200, {"code": 0, "credit": 50}),       # claim
        ]
        with mock.patch.object(
            checkin.http_client, "request_json", side_effect=responses
        ) as req:
            result = checkin.run_checkin(CRED, on_token_expired=lambda: new_cred)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["credit"], 50)
        # 请求头应使用新 token
        for call in req.call_args_list[1:]:
            headers = call.kwargs.get("extra_headers") or {}
            self.assertNotIn("Authorization", headers)  # token 走 headers 参数，非 extra
        auths = [c.kwargs.get("token") for c in req.call_args_list]
        self.assertEqual(auths[1:], ["new-tok", "new-tok"])

    def test_401_refresh_failed(self):
        """401 且刷新回调失败 → 保留原失败结果。"""
        with mock.patch.object(
            checkin.http_client, "request_json", return_value=(401, {})
        ):
            result = checkin.run_checkin(CRED, on_token_expired=lambda: None)
        self.assertEqual(result["status"], "failed")
        self.assertIn("401", result["reason"])

    def test_401_no_callback(self):
        with mock.patch.object(
            checkin.http_client, "request_json", return_value=(401, {})
        ):
            result = checkin.run_checkin(CRED)
        self.assertEqual(result["status"], "failed")

    def test_credential_error(self):
        with mock.patch.object(
            credentials, "load_credentials",
            side_effect=credentials.CredentialError("no storage"),
        ):
            result = checkin.run_checkin(None)
        self.assertEqual(result["status"], "failed")
        self.assertIn("登录态读取失败", result["reason"])

    def test_query_status_readonly(self):
        with mock.patch.object(
            checkin.http_client, "request_json",
            return_value=(200, _status_body(checked_in=True, credits=200)),
        ) as req:
            result = checkin.query_status(CRED)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["checked_in"], True)
        self.assertEqual(result["credits"], 200)
        self.assertEqual(req.call_count, 1)
        self.assertTrue(req.call_args[0][1].endswith("/status"))


if __name__ == "__main__":
    unittest.main()
