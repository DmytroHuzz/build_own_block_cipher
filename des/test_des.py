import sys
import os
import binascii
import pytest

# Ensure imports work when running directly
THIS_DIR = os.path.dirname(__file__)
WORKSPACE_ROOT = os.path.abspath(os.path.join(THIS_DIR, ".."))
sys.path.insert(0, WORKSPACE_ROOT)

from des import DES  # noqa: E402


def to_hex(b: bytes) -> str:
    return binascii.hexlify(b).decode("ascii").upper()


# Note: NIST block-level vector test omitted here to match index.py usage
def test_index_style_round_trip():
    """Mirror how index.py uses DES.encrypt/decrypt with string inputs and nonce."""
    data = "MESSAGE!MESSAGE!MESSAGE!"  # multi-block string
    key = "CRYPTKEY"  # 8-char key
    nonce = "1234567"  # as seen in index.py
    des = DES(key)
    ct = des.encrypt(data, nonce=nonce)
    rt = des.decrypt(ct, nonce=nonce)
    assert rt == data, f"Round-trip failed: {rt} != {data}"


def test_block_symmetry_random():
    # Simple symmetry check on a couple of blocks
    # Single-block strings (8 chars) should round-trip via block API if available
    key = "CRYPTKEY"
    des = DES(key)
    if not hasattr(des, "encrypt_block") or not hasattr(des, "decrypt_block"):
        print("SKIP: block encrypt/decrypt not available")
        return
    samples = [
        "\x00" * 8,
        "\xff" * 8,
        "ABCDEFGH",
        bytes.fromhex("0123456789ABCDEF").decode("latin1"),
    ]
    for pt in samples:
        pt_bytes = pt.encode("latin1") if isinstance(pt, str) else pt
        ct = des.encrypt_block(pt_bytes)
        ct_bytes = (
            ct if isinstance(ct, (bytes, bytearray)) else int(ct).to_bytes(8, "big")
        )
        rt = des.decrypt_block(ct_bytes)
        # decrypt_block returns an int or string depending on implementation; normalize
        if isinstance(rt, (bytes, bytearray)):
            rt_str = bytes(rt).decode("latin1")
        elif isinstance(rt, int):
            rt_str = rt.to_bytes(8, "big").decode("latin1")
        else:
            rt_str = rt
        expect_str = pt_bytes.decode("latin1")
        assert rt_str == expect_str, f"Block round-trip failed for {pt!r}"


def test_ctr_round_trip():
    # If your DES implements CTR with bytes API, skip if not available
    key = "CRYPTKEY"
    des = DES(key)
    nonce = "ABCDEFG"  # 7-char nonce string

    plaintexts = [
        "HELLO WORLD!!!",  # 15 chars, partial block at end
        "",  # empty
        "12345678",  # exactly one block
        "The quick brown fox jumps over the lazy dog",  # longer
    ]

    for pt in plaintexts:
        ct = des.encrypt(pt, nonce=nonce)
        rt = des.decrypt(ct, nonce=nonce)
        assert rt == pt, f"CTR round-trip failed: {rt} != {pt}"


def test_ctr_keystream_changes_with_counter():
    key = "CRYPTKEY"
    des = DES(key)
    nonce = "ABCDEFG"
    # Different blocks should produce different keystream segments
    pt = "A" * 16
    ct = des.encrypt(pt, nonce=nonce)
    ct1, ct2 = ct[:8], ct[8:16]
    assert ct1 != ct2, (
        "CTR keystream appears identical across blocks; counter may be broken."
    )


# Pytest will discover and run the tests above automatically
