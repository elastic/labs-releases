import idaapi
import pathlib

XOR_KEY = 0xB8

def get_addresses_from_tinytracer(file: pathlib.Path) -> list | None:
    """
    Retrieves all addresses from TinyTracer log file
    
    :param file: The path to the TinyTracer log file
    :return: A list of addresses from TinyTracer log file
             None if extraction fails or encounters an exception.
    """

    addrs = list()
    with open(file, "r") as file:
        for line in file:
            try:
                match = re.search(r'([0-9a-fA-F]+)\+([0-9a-fA-F]+);', line)
                if match:
                    result_address = int(match.group(1), 16) + int(match.group(2), 16)
                    addrs.append(result_address)
                else:
                    print(f"Invalid line format: {line.strip()}")
            except ValueError as e:
                print(f"Error processing line: {line.strip()}. {e}")
    return addrs 

def main(file_path):
    for index, bp in enumerate(get_addresses_from_tinytracer(file_path)):
        next_addr = bp + (idaapi.get_byte(bp + 7) ^ XOR_KEY)
        jmp_offset = next_addr - bp - 2
        print(f"\nIndex: {index}, Exception Address: {hex(bp)}")
        print(f"Offset byte for XOR: {hex(idaapi.get_byte(bp + 7))}")
        print(f"Next address: {hex(next_addr)}")
        print(f"Short JMP offset: {hex(jmp_offset)}")
        idaapi.patch_bytes(bp, bytes([0xEB, jmp_offset]))

if __name__ == "__main__":
    file_path = idaapi.ask_file(0, "*.log", "Select TinyTracer log file")    
    if file_path:
        main(pathlib.Path(file_path))
    else:
        print("No file selected. Exiting script.")
