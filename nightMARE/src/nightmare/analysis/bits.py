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


def rol8(x, n):
    """
    Perform a bitwise 8bits rotate left
    :param x: The 8bits input number
    :param n: Number of bits to rotate
    :return: The result of the 8bits left rotation
    """
    return rol(x, n, 8)


def rol16(x, n):
    """
    Perform a bitwise 16bits rotate left
    :param x: The 16bits input number
    :param n: Number of bits to rotate
    :return: The result of the 16bits left rotation
    """
    return rol(x, n, 16)


def rol32(x, n):
    """
    Perform a bitwise 32bits rotate left
    :param x: The 32bits input number
    :param n: Number of bits to rotate
    :return: The result of the 32bits left rotation
    """
    return rol(x, n, 32)


def rol64(x, n):
    """
    Perform a bitwise 64bits rotate left
    :param x: The 64bits input number
    :param n: Number of bits to rotate
    :return: The result of the 64bits left rotation
    """
    return rol(x, n, 64)


def ror8(x, n):
    """
    Perform a bitwise 8bits rotate right
    :param x: The 8bits input number
    :param n: Number of bits to rotate
    :return: The result of the 8bits right rotation
    """
    return ror(x, n, 8)


def ror16(x, n):
    """
    Perform a bitwise 16bits rotate right
    :param x: The 16bits input number
    :param n: Number of bits to rotate
    :return: The result of the 16bits right rotation
    """
    return ror(x, n, 16)


def ror32(x, n):
    """
    Perform a bitwise 32bits rotate right
    :param x: The 32bits input number
    :param n: Number of bits to rotate
    :return: The result of the 32bits right rotation
    """
    return ror(x, n, 32)


def ror64(x, n):
    """
    Perform a bitwise 64bits rotate right
    :param x: The 64bits input number
    :param n: Number of bits to rotate
    :return: The result of the 64bits right rotation
    """
    return ror(x, n, 64)


def swap32(x):
    """
    Perform a swap 32bits
    :param x: The 32bits input number
    :return: The result of the 32bits swap
    """
    return (rol32(x, 8) & 0x00FF00FF) | (rol32(x, 24) & 0xFF00FF00)


def xor(data: bytes, key: bytes) -> bytes:
    data = bytearray(data)
    for i in range(len(data)):
        data[i] ^= key[i % len(key)]
    return bytes(data)
