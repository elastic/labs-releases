import idaapi
import idc
import idautils
from ida_gdl import BasicBlock

from typing import Optional

from utils.common import get_operand_value
from utils.common import patch_instructions
from utils.common import nop_bytes
from utils.common import match_mnemonic_pattern
from utils.common import get_masked_operand_value
from utils.patterns import IMMEDIATE_MOV_PATTERN, LEA_PATTERN, MUTATION_PATTERN

from keystone import Ks, KS_ARCH_X86, KS_MODE_32, KS_MODE_64, KsError


LEA_OFFSET = 7
LEA_PATTERN_LENGTH = 18
MUTATE_OFFSET = 9


def assemble_and_patch(
    start_ea: int, end_ea: int, instruction: str, mode: int, processed_addrs: set[int]
) -> None:
    """
    Assemble the given instruction, patch it into the binary, and mark addresses as processed.

    :param start_ea: Start address of the patch.
    :param end_ea: End address of the patch.
    :param instruction: Assembly instruction to patch.
    :param mode: Keystone mode (KS_MODE_32 or KS_MODE_64).
    :param processed_addrs: Set of processed addresses to avoid collisions.
    """
    ks = Ks(KS_ARCH_X86, mode)
    try:
        encoding, _ = ks.asm(instruction)
        print(f"\nPatched instructions from {hex(start_ea)} to {hex(end_ea)}")
        patch_instructions(start_ea, encoding)
        nop_bytes(start_ea + len(encoding), end_ea)

        # Mark addresses as processed
        for ea in range(start_ea, end_ea):
            processed_addrs.add(ea)
    except KsError as e:
        print(f"Keystone assembly error: {e}")
    except Exception as e:
        print(f"Failed to patch instructions for {hex(start_ea)}: {e}")


def parse_hex_string(value: str | int) -> int:
    """
    Converts a string with optional hex formatting into an integer.
    Handles strings like '1234h', '0x1234', '1234', etc.

    :param value: The string to convert.
    :return: The converted integer value.
    """
    if not isinstance(value, str):
        return value  # Already an int, return as-is

    value = value.strip().lower().replace("0x", "")
    if value.endswith("h"):
        value = value[:-1]

    return int(value, 16)


def get_mutated_registers(
    start_ea: int, end_ea: int, register: str, value: int
) -> list[str]:
    """
    Finds the two registers involved in the mutation obfuscation technique

    :param start_ea: Start address at the pattern
    :param end_ea: End address at the pattern
    :param register: Register to be mutated
    :param value: Value used in the mutation
    :return: Dictionary containing the mutated register values
    """
    registers = {}

    value = parse_hex_string(value)

    if value > 0xFFFFFFFF:
        registers = {register: value & 0xFFFFFFFFFFFFFFFF}  # 64-bit value
    else:
        registers = {register: value & 0xFFFFFFFF}  # 32-bit value

    stack = []
    sub_registers = []

    ea = start_ea
    while ea < end_ea:
        mnemonic = idc.print_insn_mnem(ea)
        op1 = idc.print_operand(ea, 0)
        op2 = idc.print_operand(ea, 1)
        imm_value = get_operand_value(ea, 1)

        for op in [op1, op2]:
            if op and op not in registers:
                registers[op] = 0

        if mnemonic == "not" and op1 in registers:
            if registers[op1] > 0xFFFFFFFF:
                registers[op1] = ~registers[op1] & 0xFFFFFFFFFFFFFFFF
            else:
                registers[op1] = ~registers[op1] & 0xFFFFFFFF

        elif mnemonic == "sub" and op1 in registers:
            if imm_value is not None:
                if registers[op1] > 0xFFFFFFFF or imm_value > 0xFFFFFFFF:
                    registers[op1] = (registers[op1] - imm_value) & 0xFFFFFFFFFFFFFFFF
                else:
                    registers[op1] = (registers[op1] - imm_value) & 0xFFFFFFFF
            else:
                sub_registers = [op1, op2]
                if registers[op1] > 0xFFFFFFFF or registers[op2] > 0xFFFFFFFF:
                    registers[op1] = (
                        registers[op1] - registers[op2]
                    ) & 0xFFFFFFFFFFFFFFFF
                else:
                    registers[op1] = (registers[op1] - registers[op2]) & 0xFFFFFFFF
        elif mnemonic == "push" and op1 in registers:
            stack.append(registers[op1])
        elif mnemonic == "pop" and op1 in registers:
            if stack:
                registers[op1] = stack.pop()

        ea = idc.next_head(ea)

    return sub_registers


def get_subtracted_lea_value(
    start_ea: int, end_ea: int, register: str, value: int
) -> Optional[int]:
    """
    Emulate the instructions to get the subtracted value from the LEA instruction.

    :param start_ea: The start address of the LEA pattern.
    :param end_ea: The end address of the LEA pattern.
    :param register: The register used in the LEA instruction.
    :param value: The value used in the LEA instruction.
    :return: The subtracted value from the LEA instruction.
    """
    ea = start_ea
    while ea < end_ea:
        mnemonic = idc.print_insn_mnem(ea)
        opnd_val = get_operand_value(ea, 1)

        if mnemonic == "sub":
            return value - opnd_val

        ea = idc.next_head(ea)

    return None


def find_end_address_imm_mov(addr: int) -> int:
    """
    Find the address (last popf) in the pattern.

    :param addr: The initial address.
    :return: The end address of the pattern.
    """
    current_register = None
    while True:
        addr = idc.next_head(addr)
        mnemonic = idc.print_insn_mnem(addr)
        if mnemonic == "popf":
            next_ea = idc.next_head(addr)
            next_mnemonic = idc.print_insn_mnem(next_ea)
            if next_mnemonic != "pushf":
                return addr
        elif mnemonic in ["not", "add", "xor", "rol"]:
            op_register = idc.print_operand(addr, 0)
            if current_register is None:
                current_register = op_register
            elif current_register != op_register:
                print(
                    f"Register changed from {current_register} to {op_register} at {hex(addr)}"
                )
                return addr


def print_pattern_info(match_start: int, pattern_end: int, register: str) -> None:
    """
    Print information about the matched pattern.

    :param match_start: Start address of the matched pattern.
    :param pattern_end: End address of the matched pattern.
    :param register: Register involved in the pattern.
    """
    print(f"\nPattern start: {hex(match_start)}")
    print(f"Pattern end: {hex(pattern_end)}")
    print(f"Targeted register: {register}")


def fix_register_mutation(
    match_start: int,
    prev_ea: int,
    op_value: int,
    processed_addrs: set[int],
) -> None:
    """
    Repair the register mutation obfuscation technique by emulating the instructions in the pattern.

    :param match_start: Start address of the mutation pattern.
    :param prev_ea: Previous instruction address.
    :param op_value: Value used in the mutation.
    """
    register = idc.print_operand(prev_ea, 0)
    pattern_end = match_start + MUTATE_OFFSET
    registers = get_mutated_registers(match_start, pattern_end, register, op_value)

    print_pattern_info(match_start, pattern_end, register)
    print(f"Final register values: {registers}")

    if len(registers) == 2:
        reg1, reg2 = registers

        if reg1.startswith("r") or reg2.startswith("r"):
            instruction = f"add {reg1}, {reg2}"
            mode = KS_MODE_64
        else:
            instruction = f"add {reg1}, {reg2}"
            mode = KS_MODE_32

        assemble_and_patch(match_start, pattern_end, instruction, mode, processed_addrs)


def clear_lea_obf(
    match_start: int,
    processed_addrs: set[int],
) -> None:
    """
    Repair the LEA obfuscation technique by subtracting the involved instructions.

    :param match_start: Start address of the LEA pattern.
    """
    pattern_end = match_start + LEA_PATTERN_LENGTH
    targeted_reg = idc.print_operand(match_start, 0)
    lea_value = get_masked_operand_value(match_start, 1)

    print_pattern_info(match_start, pattern_end, targeted_reg)
    print(f"Targeted value: {hex(lea_value)}")

    subtracted_value = get_subtracted_lea_value(
        match_start, pattern_end, targeted_reg, lea_value
    )
    displacement_value = subtracted_value - (match_start + LEA_OFFSET)

    if displacement_value is not None:
        instruction = f"lea {targeted_reg}, [rip {displacement_value}]"
        print(f"Instruction: {instruction}")
        assemble_and_patch(
            match_start, pattern_end, instruction, KS_MODE_64, processed_addrs
        )
    else:
        print(f"Failed to emulate instructions for {hex(match_start)}")


def repair_immediate_movs(
    match_start: int,
    match_end: int,
    prev_ea: int,
    op_value: int,
    processed_addrs: set[int],
) -> None:
    """
    Repair the immediate MOV instruction by emulating the instructions in the pattern.

    :param match_start: Start address of the immediate MOV pattern.
    :param match_end: End address of the immediate MOV pattern.
    :param prev_ea: Previous instruction address.
    """
    prev_mnemonic = idc.print_insn_mnem(prev_ea)
    targeted_reg = idc.print_operand(prev_ea, 0)
    end_ea = find_end_address_imm_mov(match_start)
    pattern_end = idc.next_head(end_ea)

    print_pattern_info(match_start, pattern_end, targeted_reg)
    print(f"\nPrevious {hex(prev_ea)}: {prev_mnemonic} {targeted_reg}, {hex(op_value)}")

    registers = emulate_instr(match_start, pattern_end, targeted_reg, op_value)
    new_mov_val = registers.get(targeted_reg)

    if new_mov_val is not None:
        instruction = f"mov {targeted_reg}, {new_mov_val}"
        print(f"Repaired instruction: {instruction}")
        assemble_and_patch(
            prev_ea, pattern_end, instruction, KS_MODE_64, processed_addrs
        )
    else:
        print(f"Failed to emulate instructions for {hex(match_start)}")


def emulate_instr(
    start_ea: int, end_ea: int, register: str, value: int
) -> dict[str, int]:
    """
    Emulate the instructions in the given range and return the final register values

    :param start_ea: Start address of the instruction range
    :param end_ea: End address of the instruction range
    :param register: Register to track
    :param value: Initial value of the register
    :return: Dictionary containing the final register values
    """
    registers = {}
    value = parse_hex_string(value)

    if value > 0xFFFFFFFF:
        registers = {register: value & 0xFFFFFFFFFFFFFFFF}
    else:
        registers = {register: value & 0xFFFFFFFF}

    ea = start_ea
    while ea < end_ea:
        mnemonic = idc.print_insn_mnem(ea)
        op1 = idc.print_operand(ea, 0)
        op2 = idc.print_operand(ea, 1)
        imm_value = get_operand_value(ea, 1)

        if op1 not in registers:
            registers[op1] = 0

        if mnemonic == "mov" and imm_value is not None:
            registers[op1] = imm_value
        elif mnemonic == "not" and op1 in registers:
            if registers[op1] > 0xFFFFFFFF:
                registers[op1] = ~registers[op1] & 0xFFFFFFFFFFFFFFFF
            else:
                registers[op1] = ~registers[op1] & 0xFFFFFFFF
        elif mnemonic == "add" and op1 in registers and imm_value is not None:
            if registers[op1] > 0xFFFFFFFF or imm_value > 0xFFFFFFFF:
                registers[op1] = (registers[op1] + imm_value) & 0xFFFFFFFFFFFFFFFF
            else:
                registers[op1] = (registers[op1] + imm_value) & 0xFFFFFFFF
        elif mnemonic == "xor" and op1 in registers and imm_value is not None:
            if registers[op1] > 0xFFFFFFFF or imm_value > 0xFFFFFFFF:
                registers[op1] ^= imm_value & 0xFFFFFFFFFFFFFFFF
            else:
                registers[op1] ^= imm_value & 0xFFFFFFFF
        elif mnemonic == "rol" and op1 in registers and imm_value is not None:
            shift = imm_value % 64 if registers[op1] > 0xFFFFFFFF else imm_value % 32
            val = registers[op1]
            if registers[op1] > 0xFFFFFFFF:
                registers[op1] = (
                    (val << shift) | (val >> (64 - shift))
                ) & 0xFFFFFFFFFFFFFFFF
            else:
                registers[op1] = ((val << shift) | (val >> (32 - shift))) & 0xFFFFFFFF

        if op2:
            print(
                f"\t{hex(ea)}: {mnemonic} {op1}, {op2} -> {hex(registers.get(op1, 0))}"
            )
        else:
            print(f"\t{hex(ea)}: {mnemonic} {op1}-> {hex(registers.get(op1, 0))}")

        ea = idc.next_head(ea)

    return registers


def clean_instructions(start_addr: int, end_addr: int) -> None:
    """
    NOP out specific instructions (e.g., pushf, popf) in the given address range.

    :param start_addr: Start address of the range.
    :param end_addr: End address of the range.
    """
    for addr in idautils.Heads(start_addr, end_addr):
        disasm = idc.generate_disasm_line(addr, 0)
        if not disasm:
            continue

        if "pushf" in disasm or "popf" in disasm:
            print(f"[+] Removing pushf/popf instruction at {hex(addr)}: {disasm}")
            nop_bytes(addr, addr + idc.get_item_size(addr))


def process_mutation_matches(block: BasicBlock, processed_addrs: set[int]) -> None:
    """
    Processes register mutation matches in the given basic block.
    If a match is found, it repairs the mutation instruction and marks the address as processed.

    :param block: The basic block to process.
    :param processed_addrs: A set of addresses that have already been processed.
    """
    mutant_matches = match_mnemonic_pattern(block, MUTATION_PATTERN)
    for match_start, match_end in mutant_matches:
        if match_start not in processed_addrs:
            print(f"Found register mutant obfuscation at {hex(match_start)}")
            prev_ea = idc.prev_head(match_start)
            op_value = get_masked_operand_value(prev_ea, 1)
            fix_register_mutation(match_start, prev_ea, op_value, processed_addrs)
            processed_addrs.add(match_start)


def process_lea_matches(block: BasicBlock, processed_addrs: set[int]) -> None:
    """
    Processes LEA matches in the given basic block.
    If a match is found, it repairs the LEA instruction and marks the address as processed.

    :param block: The basic block to process.
    :param processed_addrs: A set of addresses that have already been processed.
    """
    lea_matches = match_mnemonic_pattern(block, LEA_PATTERN)
    for match_start, match_end in lea_matches:
        if match_start not in processed_addrs:
            print(f"Found lea obfuscation pattern at {hex(match_start)}")
            clear_lea_obf(match_start, processed_addrs)
            processed_addrs.add(match_start)


def process_imm_mov_matches(block: BasicBlock, processed_addrs: set[int]) -> None:
    """
    Processes immediate MOV matches in the given basic block.
    If a match is found, it repairs the MOV instruction and marks the address as processed.

    :param block: The basic block to process.
    :param processed_addrs: A set of addresses that have already been processed.
    """
    imm_mov_matches = match_mnemonic_pattern(block, IMMEDIATE_MOV_PATTERN)
    for match_start, match_end in imm_mov_matches:
        if match_start not in processed_addrs:
            prev_ea = idc.prev_head(match_start)
            op_value = get_masked_operand_value(prev_ea, 1)
            repair_immediate_movs(
                match_start, match_end, prev_ea, op_value, processed_addrs
            )
            processed_addrs.add(match_start)


def traverse_flowchart(func_addr: int) -> set[int]:
    """
    Traverses the control flow graph of a function using idaapi.FlowChart.

    :param func_addr: The starting address of the function to analyze.
    :return: A set of visited basic block start addresses.
    """
    processed_addrs = set()
    func = idaapi.get_func(func_addr)

    if not func:
        print(f"Function not found at address: {hex(func_addr)}")
        return set()

    flowchart = idaapi.FlowChart(func)
    visited = set()
    print(f"Starting traversal of function at {hex(func_addr)}")

    for block in flowchart:
        if block.start_ea in visited:
            continue

        visited.add(block.start_ea)

        process_imm_mov_matches(block, processed_addrs)
        process_lea_matches(block, processed_addrs)
        process_mutation_matches(block, processed_addrs)

    clean_instructions(func.start_ea, func.end_ea)

    return visited


idaapi.msg_clear()

# Target individual function for cleaning
# START_ADDR = 0x14002502E
# visited_blocks = traverse_flowchart(START_ADDR)

# Target all functions for cleaning
for func_ea in idautils.Functions():
    traverse_flowchart(func_ea)
    print(f"Visited function at {hex(func_ea)}")
