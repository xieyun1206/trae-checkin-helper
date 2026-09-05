#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ecdsa.py — 纯 Python ECDSA P-256 签名（标准库，无第三方依赖）

用途：TRAE token 刷新接口（/trae/api/v3/oauth/ExchangeToken）的 DeviceProof 签名。
与 Node `crypto.sign("sha256", message, privateKeyPEM)` 输出等价：
  - 曲线：P-256（prime256v1 / secp256r1）
  - 摘要：SHA-256
  - 编码：DER（SEQUENCE { INTEGER r, INTEGER s }）
  - nonce：RFC 6979 确定性生成（Node 用 OpenSSL 随机 k，验证端只校验签名有效性，
    确定性 k 与随机 k 产生的签名均可通过验证，且更利于测试）

本模块同时提供 verify()（公钥验签），仅用于自测与回环校验，不上线业务路径。
PEM 解析为最小 DER TLV 实现，仅覆盖 PKCS#8 私钥与 SPKI 公钥两种结构。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re

# ---------------------------------------------------------------------------
# P-256 曲线参数（FIPS 186-4）
# ---------------------------------------------------------------------------
_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_A = _P - 3
_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

# 点以 (x, y) 或 None（无穷远点）表示
_INF = None


def _inv_mod(a: int, m: int) -> int:
    """模逆（扩展欧几里得）。"""
    a %= m
    x0, x1 = 1, 0
    b = m
    while b:
        q = a // b
        a, b = b, a - q * b
        x0, x1 = x1, x0 - q * x1
    if a != 1:
        raise ValueError("模逆不存在")
    return x0 % m


def _point_add(p1, p2) -> tuple | None:
    if p1 is _INF:
        return p2
    if p2 is _INF:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % _P == 0:
            return _INF
        return _point_double(p1)
    lam = ((y2 - y1) * _inv_mod(x2 - x1, _P)) % _P
    x3 = (lam * lam - x1 - x2) % _P
    y3 = (lam * (x1 - x3) - y1) % _P
    return (x3, y3)


def _point_double(p) -> tuple | None:
    if p is _INF:
        return _INF
    x, y = p
    if y == 0:
        return _INF
    lam = ((3 * x * x + _A) * _inv_mod(2 * y, _P)) % _P
    x3 = (lam * lam - 2 * x) % _P
    y3 = (lam * (x - x3) - y) % _P
    return (x3, y3)


def _scalar_mult(k: int, p) -> tuple | None:
    """标量乘 k*P（二进制展开）。"""
    if k % _N == 0 or p is _INF:
        return _INF
    result = _INF
    addend = p
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_double(addend)
        k >>= 1
    return result


_G = (_GX, _GY)


# ---------------------------------------------------------------------------
# PEM / DER 解析（最小 TLV，仅覆盖 PKCS#8 EC 私钥与 SPKI EC 公钥）
# ---------------------------------------------------------------------------
def _b64_pem(pem: str) -> bytes:
    body = re.sub(r"-----[A-Z ]+-----", "", pem, flags=re.S)
    body = re.sub(r"\s", "", body)
    return base64.b64decode(body)


def _read_tlv(data: bytes, pos: int) -> tuple[int, int, bytes, int]:
    """读取一个 DER TLV：返回 (tag, length, value, next_pos)。"""
    tag = data[pos]
    pos += 1
    lb = data[pos]
    pos += 1
    if lb & 0x80:
        nlen = lb & 0x7F
        length = int.from_bytes(data[pos:pos + nlen], "big")
        pos += nlen
    else:
        length = lb
    return tag, length, data[pos:pos + length], pos + length


def _der_int_bytes(v: int) -> bytes:
    raw = v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return raw


def _der_len_bytes(n: int) -> bytes:
    """DER 长度编码：<128 单字节，否则长格式 0x81/0x82..."""
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def parse_private_key_pem(pem: str) -> int:
    """解析 PKCS#8 PEM 私钥 → 私钥标量 d。"""
    der = _b64_pem(pem)
    tag, length, value, _ = _read_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("私钥 PEM 不是 SEQUENCE")
    # SEQUENCE { INTEGER(版本), SEQUENCE{...OID...}, OCTET STRING { ECPrivateKey } }
    pos = 0
    _, _, _, pos = _read_tlv(value, pos)          # INTEGER 版本
    _, _, _, pos = _read_tlv(value, pos)          # SEQUENCE AlgorithmIdentifier
    tag, length, inner, _ = _read_tlv(value, pos)  # OCTET STRING 内嵌 ECPrivateKey
    if tag != 0x04:
        raise ValueError("私钥 PEM 缺少 OCTET STRING")
    # inner = 完整 ECPrivateKey SEQUENCE：
    #   SEQUENCE { INTEGER(版本) | OCTET STRING(私钥标量) | [0](公钥, 可选) }
    itag, ilen, ibody, _ = _read_tlv(inner, 0)
    if itag != 0x30:
        raise ValueError("ECPrivateKey 不是 SEQUENCE")
    ipos = 0
    _, _, _, ipos = _read_tlv(ibody, ipos)        # INTEGER 版本
    stag, slen, sval, _ = _read_tlv(ibody, ipos)  # OCTET STRING 私钥标量
    if stag != 0x04 or slen != 32:
        raise ValueError("私钥标量长度异常（应为 32 字节）")
    return int.from_bytes(sval, "big")


def parse_public_key_pem(pem: str) -> tuple:
    """解析 SPKI PEM 公钥 → 点 (x, y)。"""
    der = _b64_pem(pem)
    tag, length, value, _ = _read_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("公钥 PEM 不是 SEQUENCE")
    pos = 0
    _, _, _, pos = _read_tlv(value, pos)          # SEQUENCE AlgorithmIdentifier
    btag, blen, bval, _ = _read_tlv(value, pos)   # BIT STRING
    if btag != 0x03:
        raise ValueError("公钥 PEM 缺少 BIT STRING")
    # BIT STRING 首字节为 unused-bits 计数，其后为 0x04 || X || Y
    if not bval or len(bval) != 66 or bval[0] != 0 or bval[1] != 0x04:
        raise ValueError("公钥点格式异常（应为 0x00 0x04 || X || Y）")
    x = int.from_bytes(bval[2:34], "big")
    y = int.from_bytes(bval[34:66], "big")
    return (x, y)


# ---------------------------------------------------------------------------
# RFC 6979 确定性 nonce + ECDSA 签名
# ---------------------------------------------------------------------------
def _rfc6979_k(d: int, msg_hash: bytes) -> int:
    """RFC 6979（HMAC-SHA256）生成确定性 k。"""
    h1 = msg_hash
    z = int.from_bytes(h1, "big") % _N
    z_bytes = z.to_bytes(32, "big")
    x_bytes = d.to_bytes(32, "big")
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x_bytes + z_bytes, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x_bytes + z_bytes, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = int.from_bytes(v, "big")
        if 1 <= candidate < _N:
            return candidate
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign_sha256(message: bytes, private_key_pem: str) -> str:
    """
    对消息做 ECDSA-SHA256 签名，返回 base64 编码的 DER 签名
    （与 Node crypto.sign("sha256", msg, pem) 输出一致）。
    """
    d = parse_private_key_pem(private_key_pem)
    z = int.from_bytes(hashlib.sha256(message).digest(), "big") % _N
    while True:
        k = _rfc6979_k(d, hashlib.sha256(message).digest())
        r = _scalar_mult(k, _G)[0] % _N
        if r == 0:
            continue
        s = (_inv_mod(k, _N) * (z + r * d)) % _N
        if s == 0:
            continue
        break
    # DER 编码：SEQUENCE { INTEGER r, INTEGER s }
    body = b"\x02" + bytes([len(_der_int_bytes(r))]) + _der_int_bytes(r)
    body += b"\x02" + bytes([len(_der_int_bytes(s))]) + _der_int_bytes(s)
    der = b"\x30" + bytes([len(body)]) + body
    return base64.b64encode(der).decode("ascii")


def verify_sha256(message: bytes, signature_b64: str, public_key_pem: str) -> bool:
    """公钥验签（用于自测与回环校验）。"""
    der = base64.b64decode(signature_b64)
    tag, length, value, _ = _read_tlv(der, 0)
    if tag != 0x30:
        return False
    pos = 0
    rtag, rlen, rval, pos = _read_tlv(value, pos)
    st_tag, st_len, st_val, _ = _read_tlv(value, pos)
    if rtag != 0x02 or st_tag != 0x02:
        return False
    r = int.from_bytes(rval, "big")
    s = int.from_bytes(st_val, "big")
    if not (1 <= r < _N and 1 <= s < _N):
        return False
    q = parse_public_key_pem(public_key_pem)
    z = int.from_bytes(hashlib.sha256(message).digest(), "big") % _N
    w = _inv_mod(s, _N)
    u1 = (z * w) % _N
    u2 = (r * w) % _N
    point = _point_add(_scalar_mult(u1, _G), _scalar_mult(u2, q))
    if point is _INF:
        return False
    return point[0] % _N == r


# ---------------------------------------------------------------------------
# 自检：生成密钥对 → 签名 → 验签回环
# ---------------------------------------------------------------------------
def self_test() -> bool:
    import os
    import tempfile

    # 用标准库无法直接生成 PEM，这里用已知的 P-256 测试私钥（仅自检用）
    # d=1 的 PKCS#8 PEM：私钥标量 32 字节，值为 1
    d = 1
    d_bytes = d.to_bytes(32, "big")
    # ECPrivateKey: SEQUENCE{ INTEGER 1, OCTET STRING d, [0] 公钥 }
    q = _scalar_mult(d, _G)
    qx = q[0].to_bytes(32, "big")
    qy = q[1].to_bytes(32, "big")
    pub_point = b"\x04" + qx + qy
    ec_priv = b"\x02\x01\x01" + b"\x04\x20" + d_bytes
    ec_priv += b"\xa1\x44" + b"\x03\x42\x00" + pub_point
    ec_seq = b"\x30" + _der_len_bytes(len(ec_priv)) + ec_priv   # 完整 ECPrivateKey
    octet = b"\x04" + _der_len_bytes(len(ec_seq)) + ec_seq
    # SEQUENCE { OID ecPublicKey(1.2.840.10045.2.1), OID prime256v1(1.2.840.10045.3.1.7) }
    alg = bytes.fromhex("301306072a8648ce3d020106082a8648ce3d030107")
    pkcs8 = b"\x02\x01\x00" + alg + octet
    pkcs8_der = b"\x30" + _der_len_bytes(len(pkcs8)) + pkcs8
    priv_pem = "-----BEGIN PRIVATE KEY-----\n" + base64.b64encode(pkcs8_der).decode() + "\n-----END PRIVATE KEY-----\n"

    spki_alg = alg
    bitstr = b"\x03\x42\x00" + pub_point
    spki = spki_alg + bitstr
    spki_der = b"\x30" + bytes([len(spki)]) + spki
    pub_pem = "-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(spki_der).decode() + "\n-----END PUBLIC KEY-----\n"

    assert parse_private_key_pem(priv_pem) == 1
    assert parse_public_key_pem(pub_pem) == q
    msg = b"POST\n/trae/api/v3/oauth/ExchangeToken\nclient\nrefresh\n1700000000\nabc123"
    sig = sign_sha256(msg, priv_pem)
    assert verify_sha256(msg, sig, pub_pem)
    assert not verify_sha256(msg + b"x", sig, pub_pem)
    return True


if __name__ == "__main__":
    self_test()
    print("[ok] ecdsa self-test passed")
