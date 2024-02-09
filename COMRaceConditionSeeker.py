import idautils
import idc

current_function_start = idc.get_func_attr(idc.here(), idc.FUNCATTR_START)

for instr in idautils.FuncItems(current_function_start):
    for ref in idautils.CodeRefsFrom(instr, False):
        seg_name = idc.get_segm_name(ref)
        func_name = ida_name.get_name(ref)
        if func_name and seg_name == '.idata':
            print("Internal Func call(내부): {}".format(func_name))
        elif func_name and idc.get_func_attr(ref, idc.FUNCATTR_START) != current_function_start:
            print("Out(Ex) Func call(외부): {}".format(func_name))
