class AESCipher:
    def block_to_state(self, block: bytes) -> list[list[int]]:
        """
        Convert a 16‑byte block into a 4x4 AES state matrix.

        Description:
        - Interprets a 16-byte input as the AES state arranged in column-major order.

        Algorithm (pseudo-code):
        - Ensure len(block) == 16.
        - Allocate state[4][4] = 0.
        - For each column c in 0..3:
            - For each row r in 0..3:
                - state[r][c] = block[4 * c + r].

        Schematic layout (b0..b15 are block[0]..block[15]):

        - Input bytes in memory:
            block = [b0, b1, b2, b3, b4, b5, b6, b7,
                     b8, b9, b10, b11, b12, b13, b14, b15]

        - Resulting state matrix (state[row][col]):
            state[0] = [b0,  b4,  b8,  b12]
            state[1] = [b1,  b5,  b9,  b13]
            state[2] = [b2,  b6,  b10, b14]
            state[3] = [b3,  b7,  b11, b15]
        """
        if len(block) != 16:
            raise ValueError(f"Block must be 16 bytes long, {len(block)} len is given")
        state = [[0] * 4 for _ in range(4)]
        for col in range(4):
            for row in range(4):
                state[row][col] = block[4 * col + row]
        return state

    def state_to_bytes(self, state: list[list[int]]) -> bytes:
        """
        Convert a 4x4 AES state matrix back into a 16‑byte block.

        Description:
        - Inverse of block_to_state using the same AES column-major layout.

        Algorithm (pseudo-code):
        - Allocate block[16] = 0.
        - For each column c in 0..3:
            - For each row r in 0..3:
                - block[4 * c + r] = state[r][c] & 0xFF.
        - Return bytes(block).
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
        """
        Apply the AES S-box to each byte of a 4-byte word.

        Conceptually:
        - The AES S-box is a fixed nonlinear substitution table on bytes 0..255.
        - It is used to provide confusion in the cipher and in the key schedule.
        - sub_word corresponds to the g() transformation in the AES key schedule:
          it takes a 32-bit word and substitutes each byte using the S-box.

        Algorithm (pseudo-code):
        - Require len(w) == 4.
        - For each i in 0..3:
            - out[i] = SBOX[w[i]]  # table lookup on each byte.
        - Return out (a new 4-byte word).
        """
        if len(w) != 4:
            raise ValueError("sub_word expects exactly 4 bytes")
        return [self.SBOX[b] for b in w]

    def rcon_word(self, round_index: int) -> list[int]:
        """
        Compute the AES round constant (Rcon) word for a given round.

        Conceptually:
        - Rcon[i] is a one-byte constant equal to 2^(i-1) in GF(2^8) (with AES's
          reduction polynomial). For i = 1..10 in AES-128, this sequence is:
          0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36.
        - In the key schedule, Rcon is XORed only into the first word of each
          round key (after RotWord and SubWord) to break linearity between rounds.

        Representation here:
        - We return a 4-byte word [Rcon[i], 0, 0, 0] so it can be XORed with
          a 4-byte key word using xor_words().

        Algorithm (pseudo-code):
        - RCON = [None, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54].
        - Return [RCON[round_index], 0, 0, 0].
        """
        RCON = [None, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54]

        return [RCON[round_index], 0, 0, 0]

    def xor_words(self, w1: list[int], w2: list[int]) -> list[int]:
        """
        XOR two 4-byte words.

        Algorithm (pseudo-code):
        - For i in 0..3:
            - out[i] = w1[i] XOR w2[i].
        - Return out.
        """
        return [w1[i] ^ w2[i] for i in range(4)]

    def rotword(self, word: list[int]) -> list[int]:
        """
        Perform AES RotWord operation on a 4-byte word.

        Algorithm (pseudo-code):
        - Input word = [w0, w1, w2, w3].
        - Return [w1, w2, w3, w0].
        """
        return word[1:] + word[:1]

    def key_schedule_generator(self, key: bytes):
        """
        Lazily generate round key states (AES-128).

        Description:
        - Implements the AES-128 key schedule, yielding round keys for rounds 0..10.
        - Each yield is a 4x4 matrix (state[row][col]) representing one round key.

        Algorithm (high level):
        - Round 0:
          - Interpret the 16-byte key as a state via block_to_state and yield it.
        - For round_index from 1 to 10:
          - Extract columns w0..w3 from the current key_state.
          - temp = RotWord(w3); temp = SubWord(temp); temp = temp XOR Rcon[round_index].
          - new_w0 = w0 XOR temp.
          - new_w1 = w1 XOR new_w0.
          - new_w2 = w2 XOR new_w1.
          - new_w3 = w3 XOR new_w2.
          - Write new_w0..new_w3 back as the columns of key_state.
          - Yield key_state.
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
        """
        XOR two 4x4 state matrices element-wise.

        Algorithm (pseudo-code):
        - For each row i and column j:
            - state[i][j] ^= key[i][j].
        - Return the modified state.
        """
        for i in range(4):
            for j in range(4):
                state[i][j] ^= key[i][j]
        return state

    # Let's zoom in the algorithm behind the round key scheduler:
    def addRoundKey(self, state, round_key_state) -> list[list[int]]:
        """
        XOR the state with a 4x4 round key matrix (AddRoundKey).

        Description:
        - Wrapper around xor_state; conceptually state = state XOR round_key.
        """
        state = self.xor_state(state, round_key_state)
        return state

    def shift_rows(self, state):
        """
        AES ShiftRows step.

        Description:
        - Row 0 unchanged.
        - Row 1 rotated left by 1.
        - Row 2 rotated left by 2.
        - Row 3 rotated left by 3.
        """
        state[1] = state[1][1:] + state[1][:1]
        state[2] = state[2][2:] + state[2][:2]
        state[3] = state[3][3:] + state[3][:3]
        return state

    def inv_shift_rows(self, state):
        """
        Inverse of AES ShiftRows step.

        Description:
        - Reverses shift_rows:
          - Row 1 rotated right by 1.
          - Row 2 rotated right by 2.
          - Row 3 rotated right by 3.
        """
        state[1] = state[1][-1:] + state[1][:-1]
        state[2] = state[2][-2:] + state[2][:-2]
        state[3] = state[3][-3:] + state[3][:-3]
        return state

    def xtime(self, x: int) -> int:
        """
        Multiply a byte by 2 in AES finite field GF(2^8).

        Algorithm (pseudo-code):
        - x = x & 0xFF.
        - If (x & 0x80) != 0:
            - y = ((x << 1) ^ 0x1B) & 0xFF  # reduce modulo x^8 + x^4 + x^3 + x + 1.
          Else:
            - y = (x << 1) & 0xFF.
        - Return y.
        """
        x &= 0xFF  # ensure x is a single byte (0..255)
        if x & 0x80:  # if MSB is 1, shifting would overflow
            return ((x << 1) ^ 0x1B) & 0xFF
        else:
            return (x << 1) & 0xFF

    def mul_by_9(self, x: int) -> int:
        """
        Multiply a byte by 9 in GF(2^8) using xtime.

        Algorithm:
        - x2 = xtime(x)   # 2·x
        - x4 = xtime(x2)  # 4·x
        - x8 = xtime(x4)  # 8·x
        - return x8 XOR x  # 8·x + 1·x = 9·x
        """
        x2 = self.xtime(x)
        x4 = self.xtime(x2)
        x8 = self.xtime(x4)
        return x8 ^ x

    def mul_by_11(self, x: int) -> int:
        """
        Multiply a byte by 11 in GF(2^8) using xtime.

        Algorithm:
        - x2 = xtime(x)   # 2·x
        - x4 = xtime(x2)  # 4·x
        - x8 = xtime(x4)  # 8·x
        - return x8 XOR x2 XOR x  # 8+2+1 = 11
        """
        x2 = self.xtime(x)
        x4 = self.xtime(x2)
        x8 = self.xtime(x4)
        return x8 ^ x2 ^ x

    def mul_by_13(self, x: int) -> int:
        """
        Multiply a byte by 13 in GF(2^8) using xtime.

        Algorithm:
        - x2 = xtime(x)   # 2·x
        - x4 = xtime(x2)  # 4·x
        - x8 = xtime(x4)  # 8·x
        - return x8 XOR x4 XOR x  # 8+4+1 = 13
        """
        x2 = self.xtime(x)
        x4 = self.xtime(x2)
        x8 = self.xtime(x4)
        return x8 ^ x4 ^ x

    def mul_by_14(self, x: int) -> int:
        """
        Multiply a byte by 14 in GF(2^8) using xtime.

        Algorithm:
        - x2 = xtime(x)   # 2·x
        - x4 = xtime(x2)  # 4·x
        - x8 = xtime(x4)  # 8·x
        - return x8 XOR x4 XOR x2  # 8+4+2 = 14
        """
        x2 = self.xtime(x)
        x4 = self.xtime(x2)
        x8 = self.xtime(x4)
        return x8 ^ x4 ^ x2

    def mix_single_column(self, col: list[int]) -> list[int]:
        """
        Perform AES MixColumns on ONE column.

        Input:
            col = [a0, a1, a2, a3] (top-to-bottom bytes of one AES state column)

        Algorithm (mathematical view):
        - Treat col as a column vector and multiply by the fixed matrix:
              [2 3 1 1]
              [1 2 3 1]
              [1 1 2 3]
              [3 1 1 2]
          over GF(2^8), where:
            - 2·x = xtime(x)
            - 3·x = xtime(x) XOR x
        - Return the resulting [b0, b1, b2, b3].
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

        Algorithm (mathematical view):
        - Multiply the column by the inverse MixColumns matrix:
              [14 11 13  9]
              [ 9 14 11 13]
              [13  9 14 11]
              [11 13  9 14]
          using GF(2^8) multiplication by 9, 11, 13, 14 via mul_by_* helpers.
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

        Description:
        - Applies mix_single_column independently to each of the 4 columns.
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

        Description:
        - Applies inv_mix_single_column independently to each column,
          reversing mix_columns.
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
        """
        Apply the AES S-box to every byte in the state (SubBytes).

        Algorithm (pseudo-code):
        - For each (i, j):
            - state[i][j] = SBOX[state[i][j]].
        """
        for i in range(4):
            for j in range(4):
                state[i][j] = self.SBOX[state[i][j]]
        return state

    def inv_sub_bytes(self, state: list[list[int]]) -> list[list[int]]:
        """
        Apply the inverse AES S-box to every byte in the state (InvSubBytes).

        Algorithm (pseudo-code):
        - For each (i, j):
            - state[i][j] = INV_SBOX[state[i][j]].
        """
        for i in range(4):
            for j in range(4):
                state[i][j] = self.INV_SBOX[state[i][j]]
        return state

    def encode_block(self, block: bytes, key: bytes) -> bytes:
        """
        Encrypt a single 16-byte AES-128 block with the given key.

        High-level algorithm:
        - state = block_to_state(block).
        - round_keys = key_schedule_generator(key).
        - Round 0:
            - state = state XOR round_key_0 (AddRoundKey).
        - Rounds 1..9:
            - state = SubBytes(state).
            - state = ShiftRows(state).
            - state = MixColumns(state).
            - state = AddRoundKey(state, round_key_r).
        - Round 10:
            - state = SubBytes(state).
            - state = ShiftRows(state).
            - state = AddRoundKey(state, round_key_10).
        - Return state_to_bytes(state).
        """
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

        High-level algorithm (inverse cipher):
        - state = block_to_state(cipher_block).
        - round_keys = list(key_schedule_generator(key))  # keys for rounds 0..10.
        - Round 10:
            - state = AddRoundKey(state, round_keys[10]).
        - Rounds 9..1:
            - state = InvShiftRows(state).
            - state = InvSubBytes(state).
            - state = AddRoundKey(state, round_keys[r]).
            - state = InvMixColumns(state).
        - Round 0:
            - state = InvShiftRows(state).
            - state = InvSubBytes(state).
            - state = AddRoundKey(state, round_keys[0]).
        - Return state_to_bytes(state).
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

    def encode(self, data: bytes, key: bytes, nonce: bytes) -> bytes:
        """
        Encrypt data using AES-128 in CTR (Counter) mode.

        Description:
        - Turns the block cipher encode_block() into a stream cipher.
        - Generates a keystream by encrypting successive counter blocks and XORs
          it with the plaintext bytes.
        - Encryption and decryption are the same operation in CTR mode.

        Parameters:
        - data: arbitrary-length plaintext or ciphertext.
        - key: 16-byte AES-128 key.
        - nonce: 8-byte nonce. The internal 16-byte counter block is:
            counter_block = nonce || counter64_be
          where counter64_be starts at 0 and increments by 1 for each block.

        High-level algorithm:
        - Ensure len(nonce) == 8 and len(key) == 16.
        - For block index i = 0,1,2,...:
            - counter_block = nonce || i.to_bytes(8, "big").
            - keystream_block = encode_block(counter_block, key).
            - XOR keystream_block with data[i*16 : i*16+16] (truncate last block).
        - Concatenate all XORed chunks and return as bytes.
        """
        if len(key) != 16:
            raise ValueError(f"Key must be 16 bytes long, {len(key)} len is given")
        if len(nonce) != 8:
            raise ValueError(f"Nonce must be 8 bytes long, {len(nonce)} len is given")

        if not data:
            return b""

        ciphertext = bytearray(len(data))
        block_size = 16
        num_blocks = (len(data) + block_size - 1) // block_size

        for i in range(num_blocks):
            counter_block = nonce + i.to_bytes(8, "big")
            keystream = self.encode_block(counter_block, key)

            start = i * block_size
            end = min(start + block_size, len(data))
            chunk = data[start:end]

            for j, b in enumerate(chunk):
                ciphertext[start + j] = b ^ keystream[j]

        return bytes(ciphertext)

    def decode(self, data: bytes, key: bytes, nonce: bytes) -> bytes:
        """
        Decrypt data using AES-128 in CTR mode.

        Intuition / why this calls encode():
        - In CTR mode we never apply the block cipher directly to the plaintext.
          Instead we:
            keystream_block = AES_encrypt(counter_block, key)
            ciphertext_block = plaintext_block XOR keystream_block
        - Decryption reverses this by XORing with the *same* keystream:
            plaintext_block = ciphertext_block XOR keystream_block
        - Since XOR is its own inverse (x XOR k XOR k == x), using the same
          keystream generator for both directions is sufficient.

        Visual identity per byte:
            C = P ⊕ K
            P = C ⊕ K
        So the operation "⊕ K" is both the encrypt and decrypt step.

        This method:
        - Reuses encode() to generate the identical keystream and XOR it with
          `data`, regardless of whether `data` is plaintext or ciphertext.
        """
        return self.encode(data, key, nonce)


if __name__ == "__main__":
    # Minimal example usage (manual run only)
    aes = AESCipher()
    key = b"Thats my Kung Fu"
    plaintext = b"Two One Nine Two"
    ciphertext = aes.encode_block(plaintext, key)
    print("Ciphertext (hex):", ciphertext.hex())
