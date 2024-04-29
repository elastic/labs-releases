# coding: utf-8

import yara
import capstone
import argparse
import pathlib
import lief
import os

from nightmare.malware.icedid import crypto
from nightmare import utils


RULES = yara.compile(os.path.join(os.path.dirname(__file__), "core_payloads.yar"))
SIZE = 0x100


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=str, help="Input file")
    parser.add_argument("output", type=pathlib.Path, help="Output directory")
    return parser.parse_args()


def find_browser_hook_payloads(pe: lief.Binary, address) -> list[tuple[int, int]]:
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    cs.detail = True

    code = bytes(pe.get_content_from_virtual_address(address, SIZE))
    instructions = list(cs.disasm(code, address, SIZE))

    result = list()
    for i, instruction in enumerate(instructions):
        if 2 == len(result):
            break
        if "lea" == instruction.mnemonic:
            payload_address = (
                instruction.operands[1].mem.disp
                + instruction.address
                + instruction.size
            )
            size = instructions[i + 1].operands[1].imm
            result.append((payload_address, size))

    return result


def get_browser_hook_payloads(pe: lief.Binary, address: int) -> list[bytes]:
    result = list()

    payloads_info = find_browser_hook_payloads(pe, address)
    if not payloads_info:
        raise RuntimeError("Failed to find browser hook payloads' location")
    elif 1 == len(payloads_info):
        print("Only 1/2 browser hook payloads' location has been found")

    for i, (payload_address, payload_size) in enumerate(payloads_info):
        if not (
            payload := crypto.decrypt_0(
                bytes(
                    pe.get_content_from_virtual_address(payload_address, payload_size)
                )
            )
        ):
            print(f"Failed to decrypt payload #{i}.")
            continue

        result.append(payload)

    return result


def get_payloads(path: str) -> dict[str, bytes]:
    result = dict()

    if not (match := RULES.match(path)):
        raise RuntimeError("Failed to find core's functions")

    core = lief.parse(path)

    for string in match[0].strings:
        match string.identifier:
            case "$browser_hook_payloads_decryption":
                for i, payload in enumerate(
                    get_browser_hook_payloads(
                        core,
                        core.offset_to_virtual_address(string.instances[0].offset)
                        + core.imagebase,
                    )
                ):
                    result[f"browser_hook_payload_{i}.cpe"] = payload
            case _:
                continue

    return result


def main() -> None:
    args = parse_arguments()

    args.output.mkdir(exist_ok=True)
    utils.write_files(args.output, get_payloads(args.input))


if __name__ == "__main__":
    main()
