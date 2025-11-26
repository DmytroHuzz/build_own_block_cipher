from typing import Sequence


def string_to_int(s: str) -> int:
    """Convert a string to its int representation."""
    result = 0
    for char in s:
        result = (result << 8) | ord(char)
    return result


def permute(
    data: int,
    permutation_table: Sequence[int],
    input_width=None,
) -> int:
    """Reorder bits of ``data`` as described by a DES-style permutation table.

    The table must contain 1-based bit positions counted from the most significant
    bit. This matches the notation used in the DES specification and allows
    published tables such as PC-1 or PC-2 to be used directly.

    Args:
        data: Integer that stores the bits to permute. Only the least significant
            ``input_width`` bits are considered.
        permutation_table: Sequence where each entry specifies the 1-based index of
            the bit that should be copied into the next output position.
        input_width: Number of significant bits to read from ``data``. Defaults to
            ``max(permutation_table)`` which is appropriate for DES tables.

    Returns:
        Integer whose bits follow the target order.
    """

    if input_width is None:
        if not permutation_table:
            raise ValueError("input_width must be provided when the table is empty.")
        input_width = max(permutation_table)
    if input_width <= 0:
        raise ValueError("input_width must be a positive integer.")

    mask = (1 << input_width) - 1
    data &= mask

    result = 0
    for position in permutation_table:
        if position <= 0 or position > input_width:
            raise ValueError(
                "Permutation indices must be in the range [1, input_width]."
            )
        shifted = input_width - position
        bit = (data >> shifted) & 1
        result = (result << 1) | bit
    return result


def binary_split(data: int, size: int) -> tuple[int, int]:
    """Split ``data`` into two halves of ``size // 2`` bits each.

    Args:
        data: Integer that contains the bits to split.
        size: Total number of least-significant bits from ``data`` that should
            be split into halves. The value must be even.

    Returns:
        A ``(left, right)`` tuple representing the most significant half and
        the least significant half respectively.
    """

    if size <= 0 or size % 2:
        raise ValueError("Size must be a positive even number.")
    half_size = size // 2
    mask = (1 << half_size) - 1
    left = (data >> half_size) & mask
    right = data & mask
    return left, right


# Key schedule:
def rotate_left(value: int, shift: int, width: int) -> int:
    if width <= 0:
        raise ValueError("width must be positive.")
    mask = (1 << width) - 1
    shift %= width
    return ((value << shift) & mask) | (value >> (width - shift))


def binary_join(left: int, right: int, right_size: int) -> int:
    mask = (1 << right_size) - 1 if right_size else 0
    return (left << right_size) | (right & mask)


def bits_to_string(bits: int, length: int) -> str:
    """Convert a bit representation back to a string."""
    chars = []
    for i in range(length):
        byte = (bits >> (8 * (length - i - 1))) & 0xFF
        chars.append(chr(byte))
    return "".join(chars)
