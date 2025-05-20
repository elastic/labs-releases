import idaapi
import lief

SECTION_NAME = ".0Dev"


def ror4(value: int, count: int) -> int:
    """
    Rotate right operation for 32-bit values.

    :param value: The value to rotate.
    :param count: The number of bits to rotate.
    :return: The rotated value.
    """
    count %= 32
    return (value >> count | value << (32 - count)) & 0xFFFFFFFF


file_path = idaapi.get_input_file_path()
pe = lief.parse(file_path)
base_address = pe.optional_header.imagebase
entrypoint = pe.optional_header.addressof_entrypoint
virtual_entrypoint = base_address + entrypoint

print(f"Base Address: {hex(base_address)}")
print(f"Virtual Entrypoint: {hex(virtual_entrypoint)}")

section = None
for sec in pe.sections:
    if sec.name == SECTION_NAME:
        section = sec
        break

if section:
    section_base_address = base_address + section.virtual_address
    print(f"Section '{SECTION_NAME}' Base Address: {hex(section_base_address)}")

    # Grab 4 bytes at the .0dev section
    four_bytes = section.content[:4]
    zero_dev_value = int.from_bytes(four_bytes, byteorder="little")
    print(f"4 bytes at section base address: {hex(zero_dev_value)}")
else:
    print(f"Section '{SECTION_NAME}' not found")

# Perform custom Alcatraz calculations
result_zero_dev_stack_commit = zero_dev_value ^ pe.optional_header.sizeof_stack_commit
last_byte_time_date_stamp = pe.header.time_date_stamps & 0xFF
result = ror4(result_zero_dev_stack_commit, last_byte_time_date_stamp)
entrypoint = base_address + result
print(f"Actual Entrypoint: {hex(entrypoint)}")
