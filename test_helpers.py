import unittest

import helpers_draft


def reference_permute(value: int, table, width: int) -> int:
    """Simple bit-string based permutation for verification."""
    if width <= 0:
        raise ValueError("width must be positive")

    bits = f"{value:0{width}b}"
    return int("".join(bits[position - 1] for position in table), 2)


def reference_key_schedule(key: int) -> list[int]:
    """Reference implementation that mirrors the DES key schedule."""

    permuted = reference_permute(key, helpers_draft.PC_1, 64)
    bits = f"{permuted:056b}"
    c_bits = bits[:28]
    d_bits = bits[28:]

    subkeys: list[int] = []
    for shift in helpers_draft.SHIFTS_TABLE:
        rotation = shift % 28
        c_bits = c_bits[rotation:] + c_bits[:rotation]
        d_bits = d_bits[rotation:] + d_bits[:rotation]
        combined_bits = c_bits + d_bits
        subkey_bits = "".join(combined_bits[pos - 1] for pos in helpers_draft.PC_2)
        subkeys.append(int(subkey_bits, 2))
    return subkeys


class PermuteTests(unittest.TestCase):
    def test_identity_permutation(self):
        value = 0b10110010
        table = list(range(1, 9))
        self.assertEqual(
            helpers_draft.permute(value, table, input_width=8),
            value,
        )

    def test_arbitrary_permutation_matches_reference(self):
        value = 0b10110010
        table = [3, 1, 7, 5]
        expected = reference_permute(value, table, 8)
        self.assertEqual(
            helpers_draft.permute(value, table, input_width=8),
            expected,
        )

    def test_default_input_width_uses_table_size(self):
        value = 0b1011
        table = [4, 3, 2, 1]
        self.assertEqual(helpers_draft.permute(value, table), 0b1101)

    def test_detects_invalid_indices(self):
        with self.assertRaises(ValueError):
            helpers_draft.permute(0b1, [0], input_width=1)

        with self.assertRaises(ValueError):
            helpers_draft.permute(0b1, [2], input_width=1)

    def test_empty_table_requires_width(self):
        with self.assertRaises(ValueError):
            helpers_draft.permute(0b1, [])

    def test_pc1_result_matches_reference(self):
        key = 0x133457799BBCDFF1
        expected = reference_permute(key, helpers_draft.PC_1, 64)
        self.assertEqual(
            helpers_draft.permute(key, helpers_draft.PC_1, input_width=64),
            expected,
        )


class BinarySplitTests(unittest.TestCase):
    def test_splits_even_length_integer(self):
        left, right = helpers_draft.binary_split(0b10110100, 8)
        self.assertEqual(left, 0b1011)
        self.assertEqual(right, 0b0100)

    def test_masks_bits_outside_requested_size(self):
        left, right = helpers_draft.binary_split(0b111100001111, 8)
        self.assertEqual(left, 0)
        self.assertEqual(right, 0b1111)

    def test_rejects_invalid_sizes(self):
        with self.assertRaises(ValueError):
            helpers_draft.binary_split(0b0, 0)

        with self.assertRaises(ValueError):
            helpers_draft.binary_split(0b0, 7)


class JoinHalvesTests(unittest.TestCase):
    def test_join_reverses_split(self):
        value = 0b10110100
        left, right = helpers_draft.binary_split(value, 8)
        reconstructed = helpers_draft.join_halves(left, right, 4)
        self.assertEqual(reconstructed, value & 0xFF)

    def test_join_truncates_right_half(self):
        result = helpers_draft.join_halves(0b1010, 0b1111, 2)
        self.assertEqual(result, 0b101011)

    def test_negative_right_size_rejected(self):
        with self.assertRaises(ValueError):
            helpers_draft.join_halves(0, 0, -1)


class KeySchedulerTests(unittest.TestCase):
    def test_key_schedule_matches_reference(self):
        key = 0x133457799BBCDFF1
        expected = reference_key_schedule(key)
        actual = list(helpers_draft.key_scheduler(key))
        self.assertEqual(len(actual), 16)
        self.assertEqual(actual, expected)

    def test_rejects_odd_pc1_length(self):
        with self.assertRaises(ValueError):
            list(
                helpers_draft.key_scheduler(
                    0b0,
                    pc1=[1],
                    pc2=[1],
                    shifts=[1],
                )
            )

    def test_rejects_negative_shift(self):
        with self.assertRaises(ValueError):
            list(
                helpers_draft.key_scheduler(
                    0b0,
                    pc1=[1, 2],
                    pc2=[1],
                    shifts=[-1],
                )
            )


if __name__ == "__main__":
    unittest.main()
