import helpers
from des import DES


data = "MESSAGE!MESSAGE!MESSAGE!"
key = "CRYPTKEY"
des = DES(key)
ciphertext = des.encrypt(data, nonce = "1234567")
print(f"Ciphertext (str): {ciphertext}")

decrypted_block = des.decrypt(ciphertext, nonce = "1234567")
print(f"Decrypted (str): {decrypted_block}")

assert decrypted_block == data
