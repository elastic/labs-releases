import idaapi
import ida_hexrays

OP_TYPE = sorted([(getattr(ida_hexrays, x), x) for x in filter(lambda y: y.startswith('cit_') or y.startswith('cot_'), dir(ida_hexrays))])


def get_op_name(op):
    """
    Return the name of the given mcode_t.
    """
    for value, name in OP_TYPE:
        if op == value:
            return name
    return None


def explore_ctree(item):
        print(f"item address: {hex(item.ea)}, item opname: {item.opname}, item op: {get_op_name(item.op)}")
        if item.is_expr():
            if item.op == ida_hexrays.cot_asg:
                explore_ctree(item.x) # left node
                explore_ctree(item.y) # right node

            elif item.op == ida_hexrays.cot_call:
                explore_ctree(item.x)
                for a_item in item.a: # call parameters
                    explore_ctree(a_item)

            elif item.op == ida_hexrays.cot_memptr:
                explore_ctree(item.x)
        else:
            if item.op == ida_hexrays.cit_block:
                for i_item in item.cblock: # list of statement nodes
                    explore_ctree(i_item)

            elif item.op == ida_hexrays.cit_expr:
                explore_ctree(item.cexpr)
                
            elif item.op == ida_hexrays.cit_return:
                explore_ctree(item.creturn.expr)
            

def main():
    cfunc = ida_hexrays.decompile(here())
    ctree = cfunc.body
    explore_ctree(ctree)


if __name__ == '__main__':
    main()