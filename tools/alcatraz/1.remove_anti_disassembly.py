import ida_bytes
import ida_ua

UNDEFINE_OFFSET = 2
REDEFINE_OFFSET = 1


def find_eb_ff() -> list[int]:
    """
    Identifies each 'EB FF' pattern in the current segment nearby cursor.

    :return: A list of addresses where 'EB FF' patterns are found.
    """
    ea = get_segm_start(here())
    end_ea = get_segm_end(ea)
    eb_ff_addresses = []

    while ea < end_ea - 1:
        if get_wide_byte(ea) == 0xEB and get_wide_byte(ea + 1) == 0xFF:
            print(f"Found 'EB FF' at address {hex(ea)}")
            eb_ff_addresses.append(ea)
        ea = next_head(ea, end_ea)

    return eb_ff_addresses


def patch_eb_ff(eb_ff_addresses: list[int]) -> None:
    """
    Patch only the EB byte to 90 (NOP) while keeping the FF byte unchanged.

    :param eb_ff_addresses: A list of addresses where 'EB FF' patterns are found.
    :return: None
    """
    patched_count = 0

    for ea in eb_ff_addresses:
        print(f"Patching EB at {hex(ea)} → 90 (keeping FF at {hex(ea+1)})")
        patch_byte(ea, 0x90)
        patched_count += 1

    if patched_count == 0:
        print("No 'EB FF' sequences found.")
    else:
        print(f"Patched {patched_count} occurrences of EB FF.")


def undefine_bytes(eb_ff_addresses: list[int]) -> None:
    """
    Undefine the bytes at the address of the 'EB FF' pattern.

    :param eb_ff_addresses: A list of addresses where 'EB FF' patterns are found.
    :return: None
    """
    for ea in eb_ff_addresses:
        print(f"Undefining bytes at {hex(ea + UNDEFINE_OFFSET)}")
        ida_bytes.del_items(ea + UNDEFINE_OFFSET, ida_bytes.DELIT_SIMPLE)


def redefine_bytes(eb_ff_addresses: list[int]) -> None:
    """
    Redefine the bytes at the address of the 'EB FF' pattern as code.

    :return: None
    """
    for ea in eb_ff_addresses:
        print(f"Defining bytes at {hex(ea + REDEFINE_OFFSET)}")
        ida_ua.create_insn(ea + REDEFINE_OFFSET)


eb_ff_addresses = find_eb_ff()
patch_eb_ff(eb_ff_addresses)
undefine_bytes(eb_ff_addresses)
redefine_bytes(eb_ff_addresses)
