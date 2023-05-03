# coding: utf-8


def rol(x, n, max_bits) -> int:
    """
    Perform a bitwise rotate left
    :param x: The input number
    :param n: Number of bits to rotate
    :param max_bits: The size in bits of the input number
    :return: The result of the left rotation
    """
    return (x << n % max_bits) & (2**max_bits - 1) | (
        (x & (2**max_bits - 1)) >> (max_bits - (n % max_bits))
    )


def ror(x, n, max_bits) -> int:
    """
    Perform a bitwise rotate right
    :param x: The input number
    :param n: Number of bits to rotate
    :param max_bits: The size in bits of the input number
    :return: The result of the right rotation
    """
    return ((x & (2**max_bits - 1)) >> n % max_bits) | (
        x << (max_bits - (n % max_bits)) & (2**max_bits - 1)
    )


def rol32(x, n):
    """
    Perform a bitwise 32bits rotate left
    :param x: The 32bits input number
    :param n: Number of bits to rotate
    :return: The result of the 32bits left rotation
    """
    return rol(x, n, 32)


def ror32(x, n):
    """
    Perform a bitwise 32bits rotate right
    :param x: The 32bits input number
    :param n: Number of bits to rotate
    :return: The result of the 32bits right rotation
    """
    return ror(x, n, 32)
