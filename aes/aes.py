# Let's do exectaly that:
def plaintext_to_state(plaintext: str) -> list[list[int]]:
    """
    Convert a 16‑byte plaintext block into a 4x4 AES state matrix.

    The state is stored in the standard AES (FIPS‑197) layout:
    state[row][col] = plaintext[4 * col + row]
    """
    state = [[0 for _ in range(4)] for _ in range(4)]
    # if plaintext is bytes - skip encoding:
    if not isinstance(plaintext, bytes):
        bytes_text = plaintext.encode("utf-8")
    else:
        bytes_text = plaintext
    if len(bytes_text) != 16:
        raise ValueError(
            f"Plaintext must be 16 bytes long, {len(bytes_text)} len is given"
        )
    # Column-major mapping: 4 * col + row
    for col in range(4):
        for row in range(4):
            state[row][col] = bytes_text[4 * col + row]
    return state


def state_to_bytes(state: list[list[int]]) -> bytes:
    """
    Convert a 4x4 AES state matrix back into a 16‑byte block
    using the standard AES column‑major layout.
    """
    block = bytearray(16)
    for col in range(4):
        for row in range(4):
            block[4 * col + row] = state[row][col] & 0xFF
    return bytes(block)


# AES S-box (FIPS-197) in Python-friendly format:
# SBOX[x] gives the substituted byte for input byte x (0..255).

SBOX = [
    99,
    124,
    119,
    123,
    242,
    107,
    111,
    197,
    48,
    1,
    103,
    43,
    254,
    215,
    171,
    118,
    202,
    130,
    201,
    125,
    250,
    89,
    71,
    240,
    173,
    212,
    162,
    175,
    156,
    164,
    114,
    192,
    183,
    253,
    147,
    38,
    54,
    63,
    247,
    204,
    52,
    165,
    229,
    241,
    113,
    216,
    49,
    21,
    4,
    199,
    35,
    195,
    24,
    150,
    5,
    154,
    7,
    18,
    128,
    226,
    235,
    39,
    178,
    117,
    9,
    131,
    44,
    26,
    27,
    110,
    90,
    160,
    82,
    59,
    214,
    179,
    41,
    227,
    47,
    132,
    83,
    209,
    0,
    237,
    32,
    252,
    177,
    91,
    106,
    203,
    190,
    57,
    74,
    76,
    88,
    207,
    208,
    239,
    170,
    251,
    67,
    77,
    51,
    133,
    69,
    249,
    2,
    127,
    80,
    60,
    159,
    168,
    81,
    163,
    64,
    143,
    146,
    157,
    56,
    245,
    188,
    182,
    218,
    33,
    16,
    255,
    243,
    210,
    205,
    12,
    19,
    236,
    95,
    151,
    68,
    23,
    196,
    167,
    126,
    61,
    100,
    93,
    25,
    115,
    96,
    129,
    79,
    220,
    34,
    42,
    144,
    136,
    70,
    238,
    184,
    20,
    222,
    94,
    11,
    219,
    224,
    50,
    58,
    10,
    73,
    6,
    36,
    92,
    194,
    211,
    172,
    98,
    145,
    149,
    228,
    121,
    231,
    200,
    55,
    109,
    141,
    213,
    78,
    169,
    108,
    86,
    244,
    234,
    101,
    122,
    174,
    8,
    186,
    120,
    37,
    46,
    28,
    166,
    180,
    198,
    232,
    221,
    116,
    31,
    75,
    189,
    139,
    138,
    112,
    62,
    181,
    102,
    72,
    3,
    246,
    14,
    97,
    53,
    87,
    185,
    134,
    193,
    29,
    158,
    225,
    248,
    152,
    17,
    105,
    217,
    142,
    148,
    155,
    30,
    135,
    233,
    206,
    85,
    40,
    223,
    140,
    161,
    137,
    13,
    191,
    230,
    66,
    104,
    65,
    153,
    45,
    15,
    176,
    84,
    187,
    22,
]


def sub_word(w: list[int]) -> list[int]:
    """Apply AES S-box to a 4-byte word."""
    if len(w) != 4:
        raise ValueError("sub_word expects exactly 4 bytes")
    return [SBOX[b] for b in w]


def rcon_word(round_index: int) -> list[int]:
    RCON = [None, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54]

    return [RCON[round_index], 0, 0, 0]


# And a helper for XOR words:
def xor_words(w1: list[int], w2: list[int]) -> list[int]:
    return [w1[i] ^ w2[i] for i in range(4)]


def rotword(word: list[int]) -> list[int]:
    return word[1:] + word[:1]


def key_expansion(key: bytes) -> list[list[int]]:
    """
    Expand a 16-byte AES-128 key into 44 4-byte words.
    """
    if len(key) != 16:
        raise ValueError(f"Key must be 16 bytes long, {len(key)} len is given")

    Nk = 4  # number of 32-bit words comprising the cipher key
    Nb = 4  # number of columns (32-bit words) comprising the state
    Nr = 10  # number of rounds

    words: list[list[int]] = []

    # First Nk words come directly from the key bytes
    for i in range(Nk):
        words.append([key[4 * i + j] for j in range(4)])

    # Remaining words are derived per FIPS-197 key schedule
    for i in range(Nk, Nb * (Nr + 1)):
        temp = words[i - 1][:]
        if i % Nk == 0:
            temp = rotword(temp)
            temp = sub_word(temp)
            temp = xor_words(temp, rcon_word(i // Nk))
        words.append(xor_words(words[i - Nk], temp))

    return words


def getRoundKey(expanded_key: list[list[int]], round_index: int = 0) -> list[list[int]]:
    """
    Construct the 4x4 round key matrix for a given round (0..10)
    from the expanded key words.
    """
    start = round_index * 4
    round_words = expanded_key[start : start + 4]
    if len(round_words) != 4:
        raise ValueError("Invalid round index for expanded AES key")

    round_key = [[0 for _ in range(4)] for _ in range(4)]
    # Each word is a column in the round key; bytes are (row 0..3)
    for col in range(4):
        word = round_words[col]
        for row in range(4):
            round_key[row][col] = word[row]
    return round_key


def xor_state(state, key):
    for i in range(4):
        for j in range(4):
            state[i][j] ^= key[i][j]
    return state


# Let's zoom in the algorithm behind the round key scheduler:
def addRoundKey(state, round_key) -> list[list[int]]:
    """
    XOR the state with a 4x4 round key matrix.
    """
    state = xor_state(state, round_key)
    return state


def shift_rows(state):
    """
    AES ShiftRows step.
    state: 4x4 list of bytes (state[row][col])
    """
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]
    return state


def xtime(x: int) -> int:
    """
    Multiply a byte by 2 in AES finite field GF(2^8).

    - Shift left by 1 bit
    - If the highest bit was set, reduce modulo the AES polynomial (0x1B)
    """
    x &= 0xFF  # ensure x is a single byte (0..255)
    if x & 0x80:  # if MSB is 1, shifting would overflow
        return ((x << 1) ^ 0x1B) & 0xFF
    else:
        return (x << 1) & 0xFF


def mix_single_column(col: list[int]) -> list[int]:
    """
    Perform AES MixColumns on ONE column.

    Input:
        col = [a0, a1, a2, a3]
              top-to-bottom bytes of one AES state column

    Output:
        [b0, b1, b2, b3] = mixed column
    """
    if len(col) != 4:
        raise ValueError("mix_single_column expects exactly 4 bytes")

    # Extract column bytes (a0..a3)
    a0, a1, a2, a3 = (c & 0xFF for c in col)

    # Precompute multiplication by 2 for each byte
    # (this is the xtime operation in AES)
    a0_2 = xtime(a0)
    a1_2 = xtime(a1)
    a2_2 = xtime(a2)
    a3_2 = xtime(a3)

    # Multiplication by 3 is defined as: (2 * x) XOR x
    a0_3 = a0_2 ^ a0
    a1_3 = a1_2 ^ a1
    a2_3 = a2_2 ^ a2
    a3_3 = a3_2 ^ a3

    # Apply the AES MixColumns matrix:
    #
    # [ 2 3 1 1 ]   [ a0 ]
    # [ 1 2 3 1 ] x [ a1 ]
    # [ 1 1 2 3 ]   [ a2 ]
    # [ 3 1 1 2 ]   [ a3 ]
    #
    # All additions are XORs

    b0 = a0_2 ^ a1_3 ^ a2 ^ a3
    b1 = a0 ^ a1_2 ^ a2_3 ^ a3
    b2 = a0 ^ a1 ^ a2_2 ^ a3_3
    b3 = a0_3 ^ a1 ^ a2 ^ a3_2

    # Ensure outputs are bytes
    return [
        b0 & 0xFF,
        b1 & 0xFF,
        b2 & 0xFF,
        b3 & 0xFF,
    ]


def mix_columns(state: list[list[int]]) -> list[list[int]]:
    """
    Perform AES MixColumns on the FULL 4x4 AES state.

    State format:
        state[row][col]

    MixColumns is applied column-by-column.
    """
    if len(state) != 4 or any(len(row) != 4 for row in state):
        raise ValueError("state must be a 4x4 matrix")

    # Process each of the 4 columns independently
    for c in range(4):
        # Extract column c (top to bottom)
        column = [state[r][c] for r in range(4)]

        # Mix this column
        mixed_column = mix_single_column(column)

        # Write the mixed bytes back into the state
        for r in range(4):
            state[r][c] = mixed_column[r]

    return state


def sub_bytes(state: list[list[int]]) -> list[list[int]]:
    for i in range(4):
        for j in range(4):
            state[i][j] = SBOX[state[i][j]]
    return state


def aes(plaintext: str, key: bytes) -> bytes:
    ciphertext = None
    # 1. Convert the plaintext into the State;

    # 2. Generate a round key and add it to the sate;

    # 3. Iterate the state throughout K rounds to mixing it

    # 4. In every round mix rows and columns in the state
    # 5. Add a new round key

    # 6. The final mixing

    # 7. The final round key
    state = plaintext_to_state(plaintext)
    expanded_key = key_expansion(key)

    # Initial round (round 0) – XOR with original cipher key
    state = addRoundKey(state, getRoundKey(expanded_key, 0))

    # Rounds 1..9
    for round in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = addRoundKey(state, getRoundKey(expanded_key, round))

    # Final round (no MixColumns), round 10
    state = sub_bytes(state)
    state = shift_rows(state)
    state = addRoundKey(state, getRoundKey(expanded_key, 10))

    # Convert state back to bytes
    return state_to_bytes(state)


if __name__ == "__main__":
    # Example usage
    key = b"Thats my Kung Fu"
    plaintext = "Two One Nine Two"
    ciphertext = aes(plaintext, key)
    print("Ciphertext (hex):", ciphertext.hex())
    # Expected output: 29c3505f571420f6402299b31a02d73a
    assert ciphertext.hex() == "29c3505f571420f6402299b31a02d73a"
    print("AES encryption successful (example vector)!")

    # Additional AES-128 test vectors (NIST-style, hex)
    test_vectors: list[tuple[bytes, bytes, str]] = [
        # FIPS-197 C.1: key 000102...0f, plaintext 001122...ff
        (
            bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
            bytes.fromhex("00112233445566778899aabbccddeeff"),
            "69c4e0d86a7b0430d8cdb78070b4c55a",
        ),
        # Rijndael/AES example: key 2b7e15..., plaintext 3243f6...
        (
            bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"),
            bytes.fromhex("3243f6a8885a308d313198a2e0370734"),
            "3925841d02dc09fbdc118597196a0b32",
        ),
        # All-zero key, all-zero plaintext
        (
            bytes.fromhex("00000000000000000000000000000000"),
            bytes.fromhex("00000000000000000000000000000000"),
            "66e94bd4ef8a2c3b884cfa59ca342b2e",
        ),
        # NIST SP 800-38A AES-128-ECB, block 1
        (
            bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"),
            bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"),
            "3ad77bb40d7a3660a89ecaf32466ef97",
        ),
        # NIST SP 800-38A AES-128-ECB, block 2
        (
            bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"),
            bytes.fromhex("ae2d8a571e03ac9c9eb76fac45af8e51"),
            "f5d3d58503b9699de785895a96fdbaaf",
        ),
    ]

    for idx, (k, pt, expected_hex) in enumerate(test_vectors, start=1):
        ct = aes(pt, k)
        print(f"Test vector {idx} ciphertext (hex):", ct.hex())
        assert ct.hex() == expected_hex

    print("All AES test vectors passed!")
