# 🧱 Build Your Own AES

Reconstructing AES‑128 + CTR Mode From the Specification

This folder is part of a hands‑on cryptography learning journey:
you rebuild a modern block cipher — AES‑128 — and wrap it into a real‑world mode of operation.

No shortcuts. No prebuilt primitives.  
Just the math, the spec, and code.

⸻

## 🔐 What’s Inside

| Component      | Description                                                    |
| -------------- | -------------------------------------------------------------- |
| `aes.py`       | AES‑128 implementation (S‑box, key schedule, rounds, CTR mode) |
| `test_aes.py`  | Unit tests for block encrypt/decrypt + CTR round‑trip          |
| GitHub Actions | CI — AES tests run together with DES tests                     |

The core class is:

- `AESCipher` in `aes/aes.py`
  - `encode_block` / `decode_block` — raw AES‑128 block encryption/decryption (ECB on a single block).
  - `encode` / `decode` — AES‑CTR mode on arbitrary‑length data (modern stream‑cipher style).

## ✨ Why this AES exists

AES is the workhorse behind modern cryptography:

- HTTPS
- VPNs
- Disk encryption
- Messaging apps

But, just like DES, it’s usually treated as a black box.  
Here, we **open the box** for AES‑128:

✔ Follow the FIPS‑197 layout and state mapping  
✔ Implement SubBytes, ShiftRows, MixColumns, AddRoundKey  
✔ Build the full AES‑128 key schedule (Rcon, RotWord, SubWord)  
✔ Verify against standard NIST test vectors  
✔ Wrap the block cipher in a modern **CTR mode** for real message encryption

By the end, AES becomes not just a cipher —  
but a story you understand.

## 🚀 Try It Yourself

🔧 Local Install

```bash
git clone https://github.com/DmytroHuzz/build_own_block_cipher.git
cd build_own_block_cipher
pip install -r requirements.txt  # if present
```

🧪 Run Tests

```bash
pytest
```

This runs both:

- `des/test_des.py`
- `aes/test_aes.py`

🔄 Example Usage (CTR mode)

```python
from aes.aes import AESCipher

aes = AESCipher()
key = b"Sixteen byte key"   # 16 bytes
nonce = b"12345678"         # 8-byte nonce (per message)

plaintext = b"Hello, AES CTR mode!"

ciphertext = aes.encode(plaintext, key, nonce)
recovered  = aes.decode(ciphertext, key, nonce)

print("Ciphertext (hex):", ciphertext.hex())
print("Recovered:", recovered)
```

Output:

```text
Ciphertext (hex): <depends on key/nonce>
Recovered: b'Hello, AES CTR mode!'
```

If you want to experiment with individual AES rounds, you can also call:

- `encode_block(block16, key16)`
- `decode_block(block16, key16)`

directly on 16‑byte blocks.

## 📚 Learning Resources

📌 Article: Building Your Own Block Cipher — Part 3 (AES)  
https://www.softwareinthegrid.com/p/building-own-block-cipher-part-3

📌 Series Index / Rest of Articles  
https://www.softwareinthegrid.com/p/rebuilding-cryptography-from-scratch

For the DES part of this project and earlier theory:

- Part 2 — Block Cipher Theory & Rebuilding DES  
  https://www.softwareinthegrid.com/p/building-your-own-block-cipher-part
- Part 1 — Lego Bricks of Modern Security  
  https://www.softwareinthegrid.com/p/building-cryptography-lego-bricks

## 🛡️ Disclaimer

This AES implementation is for education & research only.  
Do **not** use it as a drop‑in replacement for production‑grade cryptographic libraries.

## ⭐ If you enjoy this project…

…consider giving the repository a star 🌟  
and following [Software in the Grid](https://www.softwareinthegrid.com/) for future cryptography and software-foundations deep dives.
