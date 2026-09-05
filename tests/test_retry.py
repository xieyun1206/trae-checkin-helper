#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_retry.py — HTTP 重试机制单元测试（传输失败 / 5xx / 401 不重试）。"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import config  # noqa: E402
import http_client  # noqa: E402


class RetryTestCase(unittest.TestCase):
    def test_transport_retry_then_success(self):
        """传输失败 2 次后成功（默认重试 3 次内）。"""
        calls = {"n": 0}

        def flaky(*a, **k):
            calls["n"] += 1
            if calls["n"] < 3:
                raise http_client.HttpTransportError("timeout")
            return 200, {"ok": True}

        with mock.patch.object(http_client, "_single_request", side_effect=flaky), \
             mock.patch("http_client.time.sleep"):
            status, body = http_client.request_json("POST", "https://x/y", body={})
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(calls["n"], 3)

    def test_transport_retry_exhausted(self):
        """重试耗尽后抛 HttpTransportError。"""
        with mock.patch.object(
            http_client, "_single_request",
            side_effect=http_client.HttpTransportError("down"),
        ), mock.patch("http_client.time.sleep"):
            with self.assertRaises(http_client.HttpTransportError):
                http_client.request_json("POST", "https://x/y", max_retries=2)

    def test_5xx_retry_then_success(self):
        calls = {"n": 0}

        def flaky(*a, **k):
            calls["n"] += 1
            if calls["n"] == 1:
                return 503, {}
            return 200, {"ok": True}

        with mock.patch.object(http_client, "_single_request", side_effect=flaky), \
             mock.patch("http_client.time.sleep"):
            status, body = http_client.request_json("POST", "https://x/y", body={})
        self.assertEqual(status, 200)
        self.assertEqual(calls["n"], 2)

    def test_401_no_retry(self):
        """401 不重试（重试无意义）。"""
        with mock.patch.object(
            http_client, "_single_request", return_value=(401, {})
        ) as req, mock.patch("http_client.time.sleep"):
            status, body = http_client.request_json("POST", "https://x/y")
        self.assertEqual(status, 401)
        self.assertEqual(req.call_count, 1)

    def test_4xx_other_no_retry(self):
        with mock.patch.object(
            http_client, "_single_request", return_value=(400, {})
        ) as req, mock.patch("http_client.time.sleep"):
            status, _ = http_client.request_json("POST", "https://x/y")
        self.assertEqual(status, 400)
        self.assertEqual(req.call_count, 1)

    def test_auth_header_format(self):
        """Authorization 头格式：Cloud-IDE-JWT <token>。"""
        captured = {}

        def spy(method, url, body, headers, timeout):
            captured["headers"] = headers
            return 200, {}

        with mock.patch.object(http_client, "_single_request", side_effect=spy):
            http_client.request_json(
                "POST", "https://x/y", body={}, token="tok", device_id="d123"
            )
        self.assertEqual(
            captured["headers"]["Authorization"], "Cloud-IDE-JWT tok"
        )
        self.assertEqual(captured["headers"]["x-device-id"], "d123")

    def test_non_json_response(self):
        with mock.patch.object(
            http_client, "_single_request", return_value=(200, "not-json")
        ):
            # _parse_json 在 _single_request 内部处理，这里验证 request_json 透传
            pass
        with mock.patch.object(
            http_client, "_single_request",
            return_value=(200, {"__non_json__": True}),
        ):
            status, body = http_client.request_json("GET", "https://x/y")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"__non_json__": True})


if __name__ == "__main__":
    unittest.main()
