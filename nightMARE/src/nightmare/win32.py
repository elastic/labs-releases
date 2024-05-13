# coding: utf-8

import ctypes
import typing

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000

PAGE_READONLY = 2
PAGE_READWRITE = 4
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40

IMAGE_REL_BASED_HIGHLOW = 3
IMAGE_REL_BASED_DIR64 = 10

COMPRESSION_FORMAT_LZNT1 = 2

STATUS_SUCCESS = 0
STATUS_BAD_COMPRESSION_BUFFER = 0xC0000242


class IMAGE_BASE_RELOCATION(ctypes.Structure):
    _fields_ = [("VirtualAddress", ctypes.c_uint32), ("SizeOfBlock", ctypes.c_uint32)]


class IMAGE_THUNK_DATA32(ctypes.Union):
    _fields_ = [
        ("ForwarderString", ctypes.c_uint32),
        ("Function", ctypes.c_uint32),
        ("Ordinal", ctypes.c_uint32),
        ("AddressOfData", ctypes.c_uint32),
    ]


class IMAGE_THUNK_DATA64(ctypes.Union):
    _fields_ = [
        ("ForwarderString", ctypes.c_uint64),
        ("Function", ctypes.c_uint64),
        ("Ordinal", ctypes.c_uint64),
        ("AddressOfData", ctypes.c_uint64),
    ]


class IMAGE_IMPORT_DESCRIPTOR(ctypes.Structure):
    _fields_ = [
        ("OriginalFirstThunk", ctypes.c_uint32),
        ("TimeDateStamp", ctypes.c_uint32),
        ("ForwarderChain", ctypes.c_uint32),
        ("Name", ctypes.c_uint32),
        ("FirstThunk", ctypes.c_uint32),
    ]


def get_GetLastError() -> typing.Callable:
    GetLastError = ctypes.windll.Kernel32.GetLastError
    GetLastError.restype = ctypes.c_uint32
    GetLastError.argtypes = []
    return GetLastError


def get_GetProcAddress() -> typing.Callable:
    GetProcAddress = ctypes.windll.Kernel32.GetProcAddress
    GetProcAddress.restype = ctypes.c_void_p
    GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    return GetProcAddress


def get_LoadLibraryA() -> typing.Callable:
    LoadLibraryA = ctypes.windll.Kernel32.LoadLibraryA
    LoadLibraryA.restype = ctypes.c_void_p
    LoadLibraryA.argtypes = [ctypes.c_char_p]
    return LoadLibraryA


def get_VirtualAlloc() -> typing.Callable:
    VirtualAlloc = ctypes.windll.Kernel32.VirtualAlloc
    VirtualAlloc.restype = ctypes.c_void_p
    VirtualAlloc.argtypes = [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_uint32,
        ctypes.c_uint32,
    ]
    return VirtualAlloc


def get_RtlDecompressBuffer() -> typing.Callable:
    RtlDecompressBuffer = ctypes.windll.Ntdll.RtlDecompressBuffer
    RtlDecompressBuffer.restype = ctypes.c_long
    RtlDecompressBuffer.argtypes = [
        ctypes.c_ushort,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_void_p,
    ]
    return RtlDecompressBuffer
