import idautils
import idc
import idaapi
import yara

from Crypto.Cipher import ARC4
from nightmare import cast


warmcookie_yara = """
rule warmcookie_string_decryption {
    strings:
        $seq_str_decrypt = 
        { 
            48 89 5C 24 ??
			48 89 6C 24 ??
			48 89 74 24 ??
			57
			48 81 EC ?? ?? ?? ??
		}
    condition:
        1 of them
}
"""

RULES = yara.compile(source=warmcookie_yara)


def decrypt_string(encrypted_str: bytearray, key: bytes) -> bytearray:
    return ARC4.new(key).decrypt(encrypted_str)


def get_xrefs(ea: int) -> list[int]:
    return [ref.frm for ref in idautils.XrefsTo(ea)]


def set_decompiler_comment(address: int, decrypted_string: str) -> None:
    try:
        seg = idaapi.getseg(address)

        # Check if the segment is the .pdata section
        if seg and seg.name == ".pdata":
            print(f"Skipping comment in .pdata section at: {hex(address)}")
            return

        cfunc = idaapi.decompile(address)

        if cfunc is None:
            print(f"Failed to decompile function at: {hex(address)}")
            return

        eamap = cfunc.get_eamap()
        decomp_addr = eamap[address][0].ea
        tl = idaapi.treeloc_t()
        tl.ea = decomp_addr
        commentFlag = False
        for itp in range(idaapi.ITP_SEMI, idaapi.ITP_COLON):
            tl.itp = itp
            cfunc.set_user_cmt(tl, decrypted_string)
            cfunc.save_user_cmts()
            cfunc.__str__()
            if not cfunc.has_orphan_cmts():
                commentFlag = True
                cfunc.save_user_cmts()
                break
            cfunc.del_orphan_cmts()

        if not commentFlag:
            print(f"Failed to put in decompiler comment at: {hex(address)}")
    except Exception as e:
        print(f"Failed to put in decompiler comment at: {hex(address)}")


def get_string_decrypt_funcs(imagebase: int) -> list[int]:
    result = list()

    text_seg = ida_segment.get_segm_by_name(".text")
    if text_seg:
        text_start = text_seg.start_ea

    for ea in idautils.Segments():
        matches = RULES.match(data=idaapi.get_bytes(ea, get_segm_end(ea) - ea))
        for match in matches:
            print(f"Matched rule: {match.rule}")
            for offset in match.strings:
                result.append(text_start + offset[0])

    return result


def get_string_decrypt_funcs(imagebase: int) -> list[int]:
    result = list()

    text_seg = ida_segment.get_segm_by_name(".text")
    if text_seg:
        text_start = text_seg.start_ea

    for ea in idautils.Segments():
        for match in RULES.match(data=idaapi.get_bytes(ea, get_segm_end(ea) - ea)):
            print(f"Matched rule: {match.rule}")
            for offset in match.strings:
                result.append(text_start + offset[0])

    return result


def get_encrypted_string(xrefs: list) -> list[bytes]:
    encrypted_strings = []
    for xref in xrefs:
        if idc.is_loaded(xref):
            lea_ea = xref
            for _ in range(10):
                lea_ea = idc.prev_head(lea_ea)
                if (
                    idc.print_insn_mnem(lea_ea) == "lea"
                    and idc.print_operand(lea_ea, 0) == "rcx"
                ):
                    break

            arg_ea = idc.get_operand_value(lea_ea, 1)

            if idc.is_loaded(arg_ea):
                byte_list = []
                i = 0

                size_bytes = idc.get_bytes(arg_ea + i, 4)
                size = cast.u32(size_bytes)
                i += 4

                key_bytes = idc.get_bytes(arg_ea + i, 4)

                i += 4

                while i < size + 8:
                    byte = idc.get_wide_byte(arg_ea + i)
                    byte_list.append(byte)
                    i += 1

                encrypted_strings.append((xref, bytearray(byte_list), key_bytes))

    return encrypted_strings


imagebase = ida_nalt.get_imagebase()
decrypt_funcs = get_string_decrypt_funcs(imagebase)

for func in decrypt_funcs:
    for addr, encrypted_str, key in get_encrypted_string(get_xrefs(func)):
        decrypted_str = decrypt_string(encrypted_str, key)
        null_byte_count = decrypted_str.count(b"\x00")

        for encoding in ["utf-16", "utf-8"] if null_byte_count > 1 else ["utf-8"]:
            try:
                new_decrypted_str = decrypted_str.decode(encoding)
                print(hex(addr), new_decrypted_str)
                break
            except UnicodeDecodeError:
                continue
        else:
            print(f"Unable to decode as {', '.join(encoding)}")

        set_decompiler_comment(addr, new_decrypted_str)
