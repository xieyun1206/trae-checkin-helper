#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
crypto.py — TRAE byteCrypto 纯 Python 实现（解密 + 加密）

TRAE 桌面端把登录态（iCubeAuthInfo://icube.cloudide 等）以自定义格式加密后
写入 storage.json。本模块用纯标准库（hashlib/base64）实现其 AES-128-CBC 加解密，
算法逐行对照 TRAE 主进程 out/main.js 中的 byteCrypto 模块验证：

  - blob 格式：头(6B) `tc\\x05\\x10\\x00\\x00` + 32B 随机 key + AES-128-CBC 密文
  - 密钥派生：SHA-512(key32) || (Ioe^Poe) → SHA-512 → 前 16B 为 AES key、次 16B 为 IV
  - 明文结构：64B SHA-512 校验前缀 + 载荷 JSON（WebCrypto AES-CBC 自动剥离 PKCS#7 填充）
  - 签名/验证：SHA-512(载荷) == 前缀

加密（写回刷新后的 token）与解密共用同一套原语。AES 实现通过 NIST FIPS-197
测试向量验证（密钥 000102..0f、明文 001122..eeff → 密文 69c4e0d86a7b0430d8cdb78070b4c55a）。

接口契约细节见 ../references/endpoints.md。
"""

from __future__ import annotations

import base64
import hashlib
import os

# ---------------------------------------------------------------------------
# AES-128（FIPS-197 列主序实现）
# ---------------------------------------------------------------------------
_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

_IOE = [
    82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251,
    124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203,
    84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78,
    8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37,
]
_POE = [
    31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95,
    96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239,
    160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97,
    23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125,
]

# blob 头固定字节：'tc' 0x05 0x10 0x00 0x00
_HEADER = bytes([116, 99, 5, 16, 0, 0])
_HEADER_LEN = 6
_KEY_LEN = 32
_HASH_LEN = 64
_SALT_LEN = 64
_BLOCK = 16


def _xtime(a: int) -> int:
    return ((a << 1) ^ (0x1b if a & 0x80 else 0)) & 0xff


def _key_expansion(key: bytes) -> list:
    w = [[key[4 * i + j] for j in range(4)] for i in range(4)]
    rcon = 1
    for i in range(4, 44):
        t = w[i - 1][:]
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    return w


def _add_round_key(s, w, rnd):
    for c in range(4):
        for r in range(4):
            s[r][c] ^= w[rnd * 4 + c][r]


def _sub_bytes(s):
    for r in range(4):
        for c in range(4):
            s[r][c] = _SBOX[s[r][c]]


def _inv_sub_bytes(s):
    inv = [0] * 256
    for i, v in enumerate(_SBOX):
        inv[v] = i
    for r in range(4):
        for c in range(4):
            s[r][c] = inv[s[r][c]]


def _shift_rows(s):
    for r in range(1, 4):
        s[r] = s[r][r:] + s[r][:r]


def _inv_shift_rows(s):
    for r in range(1, 4):
        s[r] = s[r][-r:] + s[r][:-r]


def _mix_columns(s):
    for c in range(4):
        a = [s[r][c] for r in range(4)]
        s[0][c] = _xtime(a[0]) ^ (_xtime(a[1]) ^ a[1]) ^ a[2] ^ a[3]
        s[1][c] = a[0] ^ _xtime(a[1]) ^ (_xtime(a[2]) ^ a[2]) ^ a[3]
        s[2][c] = a[0] ^ a[1] ^ _xtime(a[2]) ^ (_xtime(a[3]) ^ a[3])
        s[3][c] = (_xtime(a[0]) ^ a[0]) ^ a[1] ^ a[2] ^ _xtime(a[3])


def _gmul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return p


def _inv_mix_columns(s):
    for c in range(4):
        a = [s[r][c] for r in range(4)]
        s[0][c] = _gmul(a[0], 14) ^ _gmul(a[1], 11) ^ _gmul(a[2], 13) ^ _gmul(a[3], 9)
        s[1][c] = _gmul(a[0], 9) ^ _gmul(a[1], 14) ^ _gmul(a[2], 11) ^ _gmul(a[3], 13)
        s[2][c] = _gmul(a[0], 13) ^ _gmul(a[1], 9) ^ _gmul(a[2], 14) ^ _gmul(a[3], 11)
        s[3][c] = _gmul(a[0], 11) ^ _gmul(a[1], 13) ^ _gmul(a[2], 9) ^ _gmul(a[3], 14)


def _load_state(block: bytes):
    # FIPS-197：s[r][c] = in[r + 4c]（列主序填充）
    return [[block[r + 4 * c] for c in range(4)] for r in range(4)]


def _dump_state(s) -> bytes:
    return bytes(s[r][c] for c in range(4) for r in range(4))


def _aes_encrypt_block(block: bytes, w) -> bytes:
    s = _load_state(block)
    _add_round_key(s, w, 0)
    for rnd in range(1, 10):
        _sub_bytes(s)
        _shift_rows(s)
        _mix_columns(s)
        _add_round_key(s, w, rnd)
    _sub_bytes(s)
    _shift_rows(s)
    _add_round_key(s, w, 10)
    return _dump_state(s)


def _aes_decrypt_block(block: bytes, w) -> bytes:
    s = _load_state(block)
    _add_round_key(s, w, 10)
    for rnd in range(9, 0, -1):
        _inv_shift_rows(s)
        _inv_sub_bytes(s)
        _add_round_key(s, w, rnd)
        _inv_mix_columns(s)
    _inv_shift_rows(s)
    _inv_sub_bytes(s)
    _add_round_key(s, w, 0)
    return _dump_state(s)


def _aes_cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    w = _key_expansion(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), _BLOCK):
        blk = bytes(a ^ b for a, b in zip(data[i:i + _BLOCK], prev))
        e = _aes_encrypt_block(blk, w)
        out += e
        prev = e
    return bytes(out)


def _aes_cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    w = _key_expansion(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), _BLOCK):
        blk = data[i:i + _BLOCK]
        out += bytes(a ^ b for a, b in zip(_aes_decrypt_block(blk, w), prev))
        prev = blk
    return bytes(out)


# ---------------------------------------------------------------------------
# TRAE byteCrypto 派生与 blob 封装
# ---------------------------------------------------------------------------
def _salt() -> bytes:
    return bytes(_IOE[r] ^ _POE[r] for r in range(_SALT_LEN))


def _derive(key32: bytes) -> tuple[bytes, bytes]:
    """对应 JS _oe()：SHA-512(key32) || (Ioe^Poe) → SHA-512 → 取前 32B 拆 key/iv。"""
    n = bytearray(128)
    n[0:64] = hashlib.sha512(key32).digest()
    n[64:128] = _salt()
    n[0:64] = hashlib.sha512(bytes(n)).digest()
    return bytes(n[0:16]), bytes(n[16:32])


def _pkcs7_pad(data: bytes) -> bytes:
    pad = _BLOCK - (len(data) % _BLOCK)
    return data + bytes([pad]) * pad


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        return data
    pad = data[-1]
    if 1 <= pad <= _BLOCK and all(b == pad for b in data[-pad:]):
        return data[:-pad]
    return data


class CryptoError(ValueError):
    """解密/加密失败。"""


def decrypt_blob(raw: bytes) -> bytes:
    """解密完整 blob → 载荷 JSON 字节（已去 64B 校验前缀）。"""
    if len(raw) < _HEADER_LEN + _KEY_LEN + _BLOCK:
        raise CryptoError("blob 长度不足")
    if raw[0:_HEADER_LEN] != _HEADER:
        raise CryptoError("未知 blob 格式（头不匹配，可能非 AES 版本）")
    key32 = raw[_HEADER_LEN:_HEADER_LEN + _KEY_LEN]
    aes_key, iv = _derive(key32)
    plain = _aes_cbc_decrypt(raw[_HEADER_LEN + _KEY_LEN:], aes_key, iv)
    plain = _pkcs7_unpad(plain)
    if len(plain) <= _HASH_LEN:
        raise CryptoError("明文过短")
    if hashlib.sha512(plain[_HASH_LEN:]).digest() != plain[0:_HASH_LEN]:
        raise CryptoError("校验失败（密文损坏或 key 不匹配）")
    return plain[_HASH_LEN:]


def decrypt_string(value: str) -> bytes:
    """解密 storage.json 中的 base64 字符串 → 载荷字节。"""
    try:
        raw = base64.b64decode(value)
    except Exception as exc:
        raise CryptoError("base64 解码失败") from exc
    return decrypt_blob(raw)


def encrypt_blob(payload: bytes) -> bytes:
    """加密载荷字节 → 完整 blob（随机 key，与 TRAE 端格式一致）。"""
    key32 = os.urandom(_KEY_LEN)
    aes_key, iv = _derive(key32)
    body = hashlib.sha512(payload).digest() + payload
    cipher = _aes_cbc_encrypt(_pkcs7_pad(body), aes_key, iv)
    return _HEADER + key32 + cipher


def encrypt_string(payload: bytes) -> str:
    """加密载荷字节 → base64 字符串（可写回 storage.json）。"""
    return base64.b64encode(encrypt_blob(payload)).decode("ascii")


# ---------------------------------------------------------------------------
# 自检（NIST FIPS-197 向量 + CBC 回环）
# ---------------------------------------------------------------------------
def self_test() -> bool:
    k = bytes(range(16))
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct = _aes_encrypt_block(pt, _key_expansion(k))
    assert ct.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a", ct.hex()
    assert _aes_decrypt_block(ct, _key_expansion(k)) == pt
    data = os.urandom(80)
    assert _aes_cbc_decrypt(_aes_cbc_encrypt(data, k, k), k, k) == data
    blob = encrypt_blob(data)
    assert decrypt_blob(blob) == data
    return True


if __name__ == "__main__":
    self_test()
    print("[ok] crypto self-test passed")
