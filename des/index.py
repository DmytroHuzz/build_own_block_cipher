import helpers
from des import DES


data = "MESSAGE!"
key = "CRYPTKEY"
expected_ciphertext_int = 5667652893345677775
des = DES(key)
ciphertext = des.encrypt_block(data)
assert ciphertext == expected_ciphertext_int
ciphertext_str = helpers.bits_to_string(ciphertext, length=8)
print(f"Ciphertext (str): {ciphertext_str}")

decrypted_block = des.decrypt_block(ciphertext_str)
decrypted_str = helpers.bits_to_string(decrypted_block, length=8)
print(f"Decrypted (str): {decrypted_str}")

assert decrypted_str == data
