import idaapi
import ida_hexrays
import ida_lines


MCODE = sorted([(getattr(ida_hexrays, x), x) for x in filter(lambda y: y.startswith('m_'), dir(ida_hexrays))])

def get_mcode_name(mcode):
    """
    Return the name of the given mcode_t.
    """
    for value, name in MCODE:
        if mcode == value:
            return name
    return None


def parse_mop_t(mop):
    if mop.t != ida_hexrays.mop_z:
        return ida_lines.tag_remove(mop._print())
    return ''


def parse_minsn_t(minsn):
    opcode = get_mcode_name(minsn.opcode)
    ea = minsn.ea
    
    text = hex(ea) + " " + opcode
    for mop in [minsn.l, minsn.r, minsn.d]:
        text += ' ' + parse_mop_t(mop)
    print(text)
    
    
def parse_mblock_t(mblock):
    minsn = mblock.head
    while minsn and minsn != mblock.tail:
        parse_minsn_t(minsn)
        minsn = minsn.next
    

def parse_mba_t(mba):
    for i in range(0, mba.qty):
        mblock_n = mba.get_mblock(i)
        parse_mblock_t(mblock_n)


def main():
    func = idaapi.get_func(here()) # Gets the function at the current cursor
    maturity = ida_hexrays.MMAT_GENERATED
    mbr = ida_hexrays.mba_ranges_t(func)
    hf = ida_hexrays.hexrays_failure_t()
    ida_hexrays.mark_cfunc_dirty(func.start_ea)
    mba = ida_hexrays.gen_microcode(mbr, hf, None, ida_hexrays.DECOMP_NO_WAIT, maturity)
    parse_mba_t(mba)


if __name__ == '__main__':
    main()