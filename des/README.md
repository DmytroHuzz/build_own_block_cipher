# 🧱 Build Your Own Block Cipher

Reconstructing DES + CTR Mode From the Original Specification

This project is a hands-on cryptography learning journey:
you will build a block cipher from the ground up — starting with bits, substitutions, and permutations — and assemble them into a working encryption system.

No shortcuts. No prebuilt primitives.
Just the math, the spec, and code.

⸻

## 🔐 What’s Inside

| Component         | Description                                                   |
| ----------------- | ------------------------------------------------------------- |
| `des.py`          | Full DES implementation (rounds, S-boxes, Feistel network)    |
| `helpers.py`      | Bit utilities: permutations, XOR, splitting, padding          |
| `des_story.ipynb` | ⚡ Interactive notebook explaining every step of construction |
| `test_des.py`     | Unit tests validating correctness                             |
| GitHub Actions    | CI/CD pipeline — every change is validated automatically      |

## ✨ Why this project exists

Block ciphers are the core engines behind secure communication:

- HTTPS
- VPNs
- Disk encryption
- Banking systems
- Messaging apps

But they’re usually treated as a black box.  
Here, we **open the box**.

We rebuild DES by:

✔ Following the original NIST specification  
✔ Extracting every table: IP, FP, E-box, S-boxes  
✔ Implementing the Feistel network round-by-round  
✔ Generating all 16 round keys  
✔ Wrapping DES into a modern **CTR mode** for real message encryption

By the end, DES becomes not just a cipher —
but a story you understand.

## 🚀 Try It Yourself

💻 Run in Google Colab

Editable + runnable tutorial notebook:

🔗 https://colab.research.google.com/github/DmytroHuzz/build_own_block_cipher/blob/main/des/des_story.ipynb

🔧 Local Install

```
git clone https://github.com/DmytroHuzz/build_own_block_cipher.git
cd build_own_block_cipher
pip install -r requirements.txt
```

🧪 Run Tests

```
pytest
```

🔄 Example Usage

```
from des.des import DES

key = b"mysecret"
data = b"Hello, world!"
nonce = b"12345678"

cipher = DES(key)

encrypted = cipher.encrypt(data, nonce=nonce)
decrypted = cipher.decrypt(encrypted, nonce=nonce)

print("Encrypted:", encrypted)
print("Decrypted:", decrypted)

Output:

Encrypted: b'\x9f\xd1...\x88'
Decrypted: b'Hello, world!'
```

## 📚 Learning Resources

📌 Article Series: Building Cryptography LEGO Bricks
Part 1 — Building Your Own Block Cipher: Part 1 — Block Cipher Theory & Rebuilding DES
https://www.softwareinthegrid.com/p/building-your-own-block-cipher-part

📌 Previous Article: Building Own Block Cipher: Part 0 Lego Bricks of Modern Security
https://www.softwareinthegrid.com/p/building-cryptography-lego-bricks

## 🚧 Roadmap

If you’d like to discuss the AES follow-up, open an issue or continue with the article series on Software in the Grid.

## 🤝 Contributing

PRs, improvements, and feedback are welcome!
Just open an issue and let’s learn together.

## 🛡️ Disclaimer

DES is not secure for modern cryptographic use.
This implementation is for education & research only.

## ⭐ If you enjoy this project…

…consider giving the repository a star 🌟
and following [Software in the Grid](https://www.softwareinthegrid.com/) for future cryptography and software-foundations deep dives.

## 🔗 Connect

💬 LinkedIn: https://www.linkedin.com/in/dmitriyhuz/

Cryptography becomes much less magical
once you build it yourself.
