import idaapi
import ida_hexrays
import idc
import ida_lines
import random
import string

HASH_ENUM_INDEX = 2


def generate_random_string(length):
    letters = string.ascii_letters
    return "".join(random.choice(letters) for _ in range(length))


class ctree_visitor(ida_hexrays.ctree_visitor_t):
    def __init__(self, cfunc):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
        self.cfunc = cfunc
        self.func_name = "sub_7FF8CC3B0926"# API resolution function name

    def visit_expr(self, expr):
        if expr.op == idaapi.cot_call:
            if idc.get_name(expr.x.obj_ea) == self.func_name:
                carg_1 = expr.a[HASH_ENUM_INDEX]
                api_name = ida_lines.tag_remove(
                    carg_1.cexpr.print1(None)
                )  # Get API name
                expr_parent = self.cfunc.body.find_parent_of(expr)  # Get node parent

                # find asg node
                while expr_parent.op != idaapi.cot_asg:
                    expr_parent = self.cfunc.body.find_parent_of(expr_parent)

                if expr_parent.cexpr.x.op == idaapi.cot_var:
                    lvariable_old_name = (
                        expr_parent.cexpr.x.v.getv().name
                    )  # get name of variable
                    ida_hexrays.rename_lvar(
                        self.cfunc.entry_ea, lvariable_old_name, api_name
                    ) # rename variable
        return 0


def main():
    cfunc = idaapi.decompile(idc.here())
    v = ctree_visitor(cfunc)
    v.apply_to(cfunc.body, None)


if __name__ == "__main__":
    main()