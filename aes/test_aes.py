# Ensure imports work when running directly
import os
import sys
import pytest


THIS_DIR = os.path.dirname(__file__)
WORKSPACE_ROOT = os.path.abspath(os.path.join(THIS_DIR, ".."))
sys.path.insert(0, WORKSPACE_ROOT)

from aes import AESCipher  # noqa: E402


def test_aes_example_vector():
    aes = AESCipher()
    key = b"Thats my Kung Fu"
    plaintext = b"Two One Nine Two"

    ciphertext = aes.encode_block(plaintext, key)
    assert ciphertext.hex() == "29c3505f571420f6402299b31a02d73a"

    recovered = aes.decode_block(ciphertext, key)
    assert recovered == plaintext


def test_aes_standard_vectors_encrypt():
    aes = AESCipher()

    test_vectors = [
        (
            "000102030405060708090a0b0c0d0e0f",
            "00112233445566778899aabbccddeeff",
            "69c4e0d86a7b0430d8cdb78070b4c55a",
        ),
        (
            "2b7e151628aed2a6abf7158809cf4f3c",
            "3243f6a8885a308d313198a2e0370734",
            "3925841d02dc09fbdc118597196a0b32",
        ),
        (
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "66e94bd4ef8a2c3b884cfa59ca342b2e",
        ),
        (
            "2b7e151628aed2a6abf7158809cf4f3c",
            "6bc1bee22e409f96e93d7e117393172a",
            "3ad77bb40d7a3660a89ecaf32466ef97",
        ),
        (
            "2b7e151628aed2a6abf7158809cf4f3c",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "f5d3d58503b9699de785895a96fdbaaf",
        ),
    ]

    for key_hex, pt_hex, expected_hex in test_vectors:
        key = bytes.fromhex(key_hex)
        pt = bytes.fromhex(pt_hex)
        ct = aes.encode_block(pt, key)
        assert ct.hex() == expected_hex


def test_aes_standard_vectors_roundtrip():
    aes = AESCipher()

    test_vectors = [
        (
            "000102030405060708090a0b0c0d0e0f",
            "00112233445566778899aabbccddeeff",
        ),
        (
            "2b7e151628aed2a6abf7158809cf4f3c",
            "3243f6a8885a308d313198a2e0370734",
        ),
        (
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
        ),
        (
            "2b7e151628aed2a6abf7158809cf4f3c",
            "6bc1bee22e409f96e93d7e117393172a",
        ),
        (
            "2b7e151628aed2a6abf7158809cf4f3c",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
        ),
    ]

    for key_hex, pt_hex in test_vectors:
        key = bytes.fromhex(key_hex)
        pt = bytes.fromhex(pt_hex)
        ct = aes.encode_block(pt, key)
        recovered = aes.decode_block(ct, key)
        assert recovered == pt


def test_aes_ctr_roundtrip_basic():
    aes = AESCipher()
    key = b"\x00" * 16
    nonce = b"12345678"  # 8-byte nonce
    plaintext = b"CTR mode test payload!"

    ciphertext = aes.encode(plaintext, key, nonce)
    assert ciphertext != plaintext

    recovered = aes.decode(ciphertext, key, nonce)
    assert recovered == plaintext


def test_aes_ctr_roundtrip_non_block_aligned():
    aes = AESCipher()
    key = b"\x01" * 16
    nonce = b"87654321"
    # Length not multiple of 16
    plaintext = b"Short and not aligned to block size"

    ciphertext = aes.encode(plaintext, key, nonce)
    assert len(ciphertext) == len(plaintext)
    assert ciphertext != plaintext

    recovered = aes.decode(ciphertext, key, nonce)
    assert recovered == plaintext
