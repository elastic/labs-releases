import idautils
import idc
import idaapi
import os
import yara

from nightmare import cast
from nightmare.malware.latrodectus import crypto

latro_yara = """
rule latrodectus_string_decryption {
    strings:
        $seq_str_decrypt = { 48 89 54 24 ??
        48 89 4C 24 ??
        48 83 EC ??
        33 C9
        E8 ?? ?? ?? ??
        48 8B 44 24 ??
        8B 00
    }
    condition:
        1 of them
}
"""

RULES = yara.compile(source=latro_yara)


def get_xrefs(ea: int) -> list[int]:
    return [ref.frm for ref in idautils.XrefsTo(ea)]


def set_decompiler_comment(address: int, decrypted_string: str) -> None:
    try:
        seg = idaapi.getseg(address)

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
            print(
                f"Failed to put in decompiler comment at: {hex(int.from_bytes(address, 'big'))}"
            )
    except Exception as e:
        print(
            f"Failed to put in decompiler comment at: {hex(int.from_bytes(address, 'big'))}"
        )


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


def get_encrypted_string(xrefs: list) -> list[bytes]:
    encrypted_strings = []
    for xref in xrefs:
        push_ea = idc.prev_head(xref)
        arg_ea = idc.get_operand_value(push_ea, 1)

        if idc.is_loaded(arg_ea):
            byte_list = []
            i = 0

            while True:
                byte1 = idc.get_wide_byte(arg_ea + i)
                byte2 = idc.get_wide_byte(arg_ea + i + 1)

                if byte1 == 0 and byte2 == 0:
                    break

                byte_list.append(byte1)
                byte_list.append(byte2)
                i += 2

        encrypted_strings.append((xref, bytes(byte_list)))

    return encrypted_strings


imagebase = ida_nalt.get_imagebase()
xrefs = get_xrefs(get_string_decrypt_funcs(imagebase)[0])
addrs_encrypted_strings = get_encrypted_string(xrefs)

for addr, encrypted_str in addrs_encrypted_strings:
    decrypted_str = crypto.decrypt_string(encrypted_str)
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
