# coding: utf-8

import argparse
import pathlib
import ctypes
import json

from nightmare.malware.icedid import custom_pe
from nightmare.malware.icedid import core as icedid_core
from nightmare import win32


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("core_path", type=pathlib.Path, help="Core custom PE")
    parser.add_argument(
        "ctx_path", type=pathlib.Path, help="Path to json file defining core's context"
    )
    parser.add_argument(
        "-o", "--offset", type=int, help="Offset to real data, skip possible garbage"
    )
    return parser.parse_args()


def print_info(base_address: int, entrypoint: int) -> None:
    print("=" * 80)
    print("Core Loader")
    print("=" * 80)
    print("Base address: 0x{:08x}".format(base_address))
    print("Entrypoint: 0x{:08x}".format(entrypoint))
    print()


def build_context(ctx_path: pathlib.Path) -> icedid_core.Ctx64:
    with ctx_path.open("r") as f:
        j = json.load(f)

    ctx = icedid_core.Ctx64()
    ctx.field_0 = j["field_0"]
    ctx.is_dll = j["is_dll"]
    ctx.stage_2_fullpath = bytes(j["stage_2_fullpath"], "utf-8")
    ctx.core_fullpath = bytes(j["core_fullpath"], "utf-8")
    ctx.core_subpath = bytes(j["core_subpath"], "utf-8")
    ctx.stage_2_export = bytes(j["stage_2_export"], "utf-8")

    with open(j["encrypted_config_path"], "rb") as f:
        encrypted_config = f.read()

    ctx.encrypted_config = win32.VirtualAlloc(
        0,
        len(encrypted_config),
        win32.MEM_COMMIT | win32.MEM_RESERVE,
        win32.PAGE_READWRITE,
    )

    if not ctx.encrypted_config:
        raise RuntimeError("Failed to allocate memory. GLE={}", win32.GetLastError())

    ctypes.memmove(ctx.encrypted_config, encrypted_config, len(encrypted_config))
    ctx.encrypted_config_size = len(encrypted_config)

    return ctx


def main() -> None:
    args = parse_arguments()

    with args.core_path.open("rb") as f:
        core = custom_pe.CustomPE(f.read()[args.offset if args.offset else 0 :])

    loader = custom_pe.Loader(core)
    print_info(loader.base_address, loader.entrypoint)

    input("Press a key to call entrypoint...\n")
    loader.EntryPoint(ctypes.byref(build_context(args.ctx_path)))


if __name__ == "__main__":
    main()
