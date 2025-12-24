class AESCipher:
    def block_to_state(self, block: bytes) -> list[list[int]]:
        """
        Convert a 16‑byte block into a 4x4 AES state matrix.

        The state is stored in the standard AES (FIPS‑197) layout:
        state[row][col] = block[4 * col + row]
        """
        if len(block) != 16:
            raise ValueError(f"Block must be 16 bytes long, {len(block)} len is given")
        state = [[0 for _ in range(4)] for _ in range(4)]
        for col in range(4):
            for row in range(4):
                state[row][col] = block[4 * col + row]
        return state

    def state_to_bytes(self, state: list[list[int]]) -> bytes:
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

    # Inverse S-box, computed from SBOX
    INV_SBOX = [0] * 256
    for i, v in enumerate(SBOX):
        INV_SBOX[v] = i

    def sub_word(self, w: list[int]) -> list[int]:
        """Apply AES S-box to a 4-byte word."""
        if len(w) != 4:
            raise ValueError("sub_word expects exactly 4 bytes")
        return [self.SBOX[b] for b in w]

    def rcon_word(self, round_index: int) -> list[int]:
        RCON = [None, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54]

        return [RCON[round_index], 0, 0, 0]

    # And a helper for XOR words:
    def xor_words(self, w1: list[int], w2: list[int]) -> list[int]:
        return [w1[i] ^ w2[i] for i in range(4)]

    def rotword(self, word: list[int]) -> list[int]:
        return word[1:] + word[:1]

    def key_schedule_generator(self, key: bytes):
        """
        Lazily generate round key states (AES-128).

        Each yield is a 4x4 matrix (state[row][col]) representing
        the round key for rounds 0..10. Only the current round key
        state is kept in memory; each next round key is derived
        from the previous one.
        """
        if len(key) != 16:
            raise ValueError(f"Key must be 16 bytes long, {len(key)} len is given")

        # Round 0 key as a state matrix
        key_state = self.block_to_state(key)
        yield key_state

        # Generate rounds 1..10 lazily, deriving each from the previous key state
        for round_index in range(1, 11):
            # Extract current words as columns from the state
            w0 = [key_state[row][0] for row in range(4)]
            w1 = [key_state[row][1] for row in range(4)]
            w2 = [key_state[row][2] for row in range(4)]
            w3 = [key_state[row][3] for row in range(4)]

            temp = self.rotword(w3)
            temp = self.sub_word(temp)
            temp = self.xor_words(temp, self.rcon_word(round_index))

            new_w0 = self.xor_words(w0, temp)
            new_w1 = self.xor_words(w1, new_w0)
            new_w2 = self.xor_words(w2, new_w1)
            new_w3 = self.xor_words(w3, new_w2)

            # Write new words back into the key_state columns
            for row in range(4):
                key_state[row][0] = new_w0[row]
                key_state[row][1] = new_w1[row]
                key_state[row][2] = new_w2[row]
                key_state[row][3] = new_w3[row]

            yield key_state

    def xor_state(self, state, key):
        for i in range(4):
            for j in range(4):
                state[i][j] ^= key[i][j]
        return state

    # Let's zoom in the algorithm behind the round key scheduler:
    def addRoundKey(self, state, round_key_state) -> list[list[int]]:
        """
        XOR the state with a 4x4 round key matrix.
        """
        state = self.xor_state(state, round_key_state)
        return state

    def shift_rows(self, state):
        """
        AES ShiftRows step.
        state: 4x4 list of bytes (state[row][col])
        """
        state[1] = state[1][1:] + state[1][:1]
        state[2] = state[2][2:] + state[2][:2]
        state[3] = state[3][3:] + state[3][:3]
        return state

    def inv_shift_rows(self, state):
        """
        Inverse of AES ShiftRows step.
        """
        state[1] = state[1][-1:] + state[1][:-1]
        state[2] = state[2][-2:] + state[2][:-2]
        state[3] = state[3][-3:] + state[3][:-3]
        return state

    def xtime(self, x: int) -> int:
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

    # Helpers for inverse MixColumns (multiplication by constants in GF(2^8)):
    def mul_by_9(self, x: int) -> int:
        x2 = self.xtime(x)
        x4 = self.xtime(x2)
        x8 = self.xtime(x4)
        return x8 ^ x

    def mul_by_11(self, x: int) -> int:
        x2 = self.xtime(x)
        x4 = self.xtime(x2)
        x8 = self.xtime(x4)
        return x8 ^ x2 ^ x

    def mul_by_13(self, x: int) -> int:
        x2 = self.xtime(x)
        x4 = self.xtime(x2)
        x8 = self.xtime(x4)
        return x8 ^ x4 ^ x

    def mul_by_14(self, x: int) -> int:
        x2 = self.xtime(x)
        x4 = self.xtime(x2)
        x8 = self.xtime(x4)
        return x8 ^ x4 ^ x2

    def mix_single_column(self, col: list[int]) -> list[int]:
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
        a0_2 = self.xtime(a0)
        a1_2 = self.xtime(a1)
        a2_2 = self.xtime(a2)
        a3_2 = self.xtime(a3)

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

    def inv_mix_single_column(self, col: list[int]) -> list[int]:
        """
        Inverse AES MixColumns on ONE column.
        """
        if len(col) != 4:
            raise ValueError("inv_mix_single_column expects exactly 4 bytes")

        a0, a1, a2, a3 = (c & 0xFF for c in col)

        b0 = (
            self.mul_by_14(a0)
            ^ self.mul_by_11(a1)
            ^ self.mul_by_13(a2)
            ^ self.mul_by_9(a3)
        )
        b1 = (
            self.mul_by_9(a0)
            ^ self.mul_by_14(a1)
            ^ self.mul_by_11(a2)
            ^ self.mul_by_13(a3)
        )
        b2 = (
            self.mul_by_13(a0)
            ^ self.mul_by_9(a1)
            ^ self.mul_by_14(a2)
            ^ self.mul_by_11(a3)
        )
        b3 = (
            self.mul_by_11(a0)
            ^ self.mul_by_13(a1)
            ^ self.mul_by_9(a2)
            ^ self.mul_by_14(a3)
        )

        return [
            b0 & 0xFF,
            b1 & 0xFF,
            b2 & 0xFF,
            b3 & 0xFF,
        ]

    def mix_columns(self, state: list[list[int]]) -> list[list[int]]:
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
            mixed_column = self.mix_single_column(column)

            # Write the mixed bytes back into the state
            for r in range(4):
                state[r][c] = mixed_column[r]

        return state

    def inv_mix_columns(self, state: list[list[int]]) -> list[list[int]]:
        """
        Inverse AES MixColumns on the FULL 4x4 AES state.
        """
        if len(state) != 4 or any(len(row) != 4 for row in state):
            raise ValueError("state must be a 4x4 matrix")

        for c in range(4):
            column = [state[r][c] for r in range(4)]
            mixed_column = self.inv_mix_single_column(column)
            for r in range(4):
                state[r][c] = mixed_column[r]

        return state

    def sub_bytes(self, state: list[list[int]]) -> list[list[int]]:
        for i in range(4):
            for j in range(4):
                state[i][j] = self.SBOX[state[i][j]]
        return state

    def inv_sub_bytes(self, state: list[list[int]]) -> list[list[int]]:
        for i in range(4):
            for j in range(4):
                state[i][j] = self.INV_SBOX[state[i][j]]
        return state

    def encode_block(self, block: bytes, key: bytes) -> bytes:
        # 1. Convert the plaintext into the State;

        # 2. Generate a round key and add it to the sate;

        # 3. Iterate the state throughout K rounds to mixing it

        # 4. In every round mix rows and columns in the state
        # 5. Add a new round key

        # 6. The final mixing

        # 7. The final round key
        state = self.block_to_state(block)

        # Lazily generate all round key states (0..10)
        round_key_states = self.key_schedule_generator(key)

        # Initial round (round 0) – XOR with original cipher key
        state = self.addRoundKey(state, next(round_key_states))

        # Rounds 1..9
        for _ in range(1, 10):
            state = self.sub_bytes(state)
            state = self.shift_rows(state)
            state = self.mix_columns(state)
            state = self.addRoundKey(state, next(round_key_states))

        # Final round (no MixColumns), round 10
        state = self.sub_bytes(state)
        state = self.shift_rows(state)
        state = self.addRoundKey(state, next(round_key_states))

        # Convert state back to bytes
        return self.state_to_bytes(state)

    def decode_block(self, block: bytes, key: bytes) -> bytes:
        """
        Decrypt a single 16-byte AES-128 block with the given key.
        """
        state = self.block_to_state(block)

        # Materialize all round key states (0..10) and copy them to avoid aliasing
        round_keys = [[row[:] for row in rk] for rk in self.key_schedule_generator(key)]

        # Initial AddRoundKey with last round key (round 10)
        state = self.addRoundKey(state, round_keys[10])

        # Rounds 9..1
        for round_index in range(9, 0, -1):
            state = self.inv_shift_rows(state)
            state = self.inv_sub_bytes(state)
            state = self.addRoundKey(state, round_keys[round_index])
            state = self.inv_mix_columns(state)

        # Final round (round 0): no MixColumns
        state = self.inv_shift_rows(state)
        state = self.inv_sub_bytes(state)
        state = self.addRoundKey(state, round_keys[0])

        return self.state_to_bytes(state)


if __name__ == "__main__":
    # Example usage
    aes = AESCipher()
    key = b"Thats my Kung Fu"
    plaintext = "Two One Nine Two"
    ciphertext = aes.encode_block(plaintext.encode(), key)
    print("Ciphertext (hex):", ciphertext.hex())
    # Expected output: 29c3505f571420f6402299b31a02d73a
    assert ciphertext.hex() == "29c3505f571420f6402299b31a02d73a"
    recovered = aes.decode_block(ciphertext, key)
    assert recovered == plaintext.encode()
    print("AES encryption/decryption successful (example vector)!")

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
        ct = aes.encode_block(pt, k)
        print(f"Test vector {idx} ciphertext (hex):", ct.hex())
        assert ct.hex() == expected_hex

    # Also verify decryption for those vectors
    for k, pt, _ in test_vectors:
        assert aes.decode_block(aes.encode_block(pt, k), k) == pt

    print("All AES encryption/decryption test vectors passed!")
