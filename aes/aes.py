# Let's do exectaly that:
def plaintext_to_state(plaintext: str) -> list[list[int]]:
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
    for i in range(4):
        for j in range(4):
            state[i][j] = bytes_text[i * 4 + j]
    return state


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


def sub_word(w: bytes) -> bytes:
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


def getRoundKey(key_state, round=0) -> list[list[int]]:
    # 1. Assign the last workd of the key to the initial word

    # 2. Iterate 4 times to create 4 new workd
    # On the first iteration
    # Circular rotation
    # Sub word

    # XOR with Rcon[1]
    # Create a new word by previous word XOR words[i-4]
    # 3. Return 4 words (4*32-> 128 bits) as a round key.
    temp = key_state[-1]
    round_key = []
    for i in range(4):
        if not i and round:
            temp = rotword(temp)
            temp = sub_word(temp)
            temp = xor_words(temp, rcon_word(round))
        round_key.append(xor_words(key_state[i], temp))
        temp = round_key[-1]
    return round_key


def xor_state(state, key):
    for i in range(4):
        for j in range(4):
            state[i][j] ^= key[i][j]
    return state


# Let's zoom in the algorithm behind the round key scheduler:
def addRoundKey(state, key, round=0) -> list[list[int]]:
    # 1. Assign the last workd of the key to the initial word

    # 2. Iterate 4 times to create 4 new workd
    # On the first iteration
    # Circular rotation
    # Sub word

    # XOR with Rcon[1]
    # Create a new word by previous word XOR words[i-4]
    # 3. Return 4 words (4*32-> 128 bits) as a round key.
    round_key = getRoundKey(key, round)
    state = xor_state(state, round_key)
    return state, round_key


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
    key = plaintext_to_state(key)

    state, key = addRoundKey(state, key, round=0)
    for round in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state, key = addRoundKey(state, key, round)
    # Final round (no MixColumns)
    state = sub_bytes(state)
    state = shift_rows(state)
    state, key = addRoundKey(state, key, round=10)
    # Convert state back to bytes
    ciphertext_bytes = bytearray(16)
    for i in range(4):
        for j in range(4):
            ciphertext_bytes[i * 4 + j] = state[i][j]
    ciphertext = bytes(ciphertext_bytes)
    return ciphertext


if __name__ == "__main__":
    # Example usage
    key = b"Thats my Kung Fu"
    plaintext = "Two One Nine Two"
    ciphertext = aes(plaintext, key)
    print("Ciphertext (hex):", ciphertext.hex())
    # Expected output: 29c3505f571420f6402299b31a02d73a
    assert ciphertext.hex() == "29c3505f571420f6402299b31a02d73a"
    print("AES encryption successful!")
