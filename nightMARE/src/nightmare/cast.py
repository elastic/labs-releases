# coding: utf-8

import functools
import base64


u64 = lambda x: int.from_bytes(x[0:8], "little")
u32 = lambda x: int.from_bytes(x[0:4], "little")
u16 = lambda x: int.from_bytes(x[0:2], "little")
u8 = lambda x: int.from_bytes(x[0:1], "little")

p64 = lambda x: x.to_bytes(8, "little")
p32 = lambda x: x.to_bytes(4, "little")
p16 = lambda x: x.to_bytes(2, "little")
p8 = lambda x: x.to_bytes(1, "little")


bool_to_byte = lambda x: p8(int(x))
byte_to_bool = lambda x: bool(u8(x))

utf8_to_str = functools.partial(bytes.decode, encoding="utf-8")
str_to_utf8 = lambda x: x.encode("utf-8")

utf16_to_str = functools.partial(bytes.decode, encoding="utf-16")
str_to_utf16 = lambda x: x.encode("utf-16-le")

ascii_bytes_to_int = lambda x: int(utf8_to_str(x))
int_to_ascii_bytes = lambda x: str_to_utf8(str(x))

ascii_bytes_to_bool = lambda x: bool(ascii_bytes_to_int(x))
bool_to_ascii_bytes = lambda x: int_to_ascii_bytes(int(x))

bytes_to_b64_str = lambda x: base64.b64encode(x).decode("utf-8")
