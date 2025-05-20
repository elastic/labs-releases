import idautils
import idc

from ida_gdl import BasicBlock
from typing import Optional


def get_operand_value(ea: int, op_num: int) -> Optional[int]:
    """
    Returns the immediate operand value if present.

    param ea: The address of the instruction.
    param op_num: The operand number.
    :return: The immediate value or None if not present.
    """
    if idc.get_operand_type(ea, op_num) == idc.o_imm:
        value = idc.get_operand_value(ea, op_num)
        if idc.get_item_size(ea) == 8:
            return value & 0xFFFFFFFFFFFFFFFF
        else:
            return value & 0xFFFFFFFF

    return None


def patch_instructions(start_ea: int, encoding: list[int]) -> None:
    """
    Patches the instructions at the given address with the Keystone encoding.

    param start_ea: The starting address of the instruction to patch.
    param encoding: The byte array to patch the instruction with.
    """
    for i, byte in enumerate(encoding):
        idc.patch_byte(start_ea + i, byte)


def nop_bytes(start_ea: int, end_ea: int) -> None:
    """
    NOPs out the bytes from start_ea to end_ea, inclusive of the final instruction.

    :param start_ea: The starting address.
    :param end_ea: The ending address.
    """
    ea = start_ea
    while ea < end_ea:
        idc.patch_byte(ea, 0x90)
        ea += 1
    print(f"[+] NOPed instructions from {hex(start_ea)} to {hex(end_ea)}")


def get_masked_operand_value(ea: int, op_num: int) -> int:
    """
    Returns the masked operand value for the given instruction address and operand number.

    :param ea: The address of the instruction.
    :param op_num: The operand number.
    :return: The masked operand value.
    """
    value = idc.get_operand_value(ea, op_num)
    if value > 0xFFFFFFFF:
        return value & 0xFFFFFFFFFFFFFFFF
    else:
        return value & 0xFFFFFFFF


def match_mnemonic_pattern(
    block: BasicBlock, pattern: list[str]
) -> list[tuple[int, int]]:
    """
    Matches a mnemonic pattern in the instructions of a basic block.

    :param block: The basic block to analyze.
    :param pattern: The list of mnemonics to match.
    :return: A list of tuples containing the start and end addresses of matched patterns.
    """
    instructions = [
        (addr, idc.print_insn_mnem(addr))
        for addr in idautils.Heads(block.start_ea, block.end_ea)
    ]
    matches = []
    pattern_len = len(pattern)

    for i in range(len(instructions) - pattern_len + 1):
        if all(instructions[i + j][1] == pattern[j] for j in range(pattern_len)):
            matches.append((instructions[i][0], instructions[i + pattern_len - 1][0]))

    return matches
