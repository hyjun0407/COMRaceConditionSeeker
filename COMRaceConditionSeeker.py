import idautils
import idc

current_function_start = idc.get_func_attr(idc.here(), idc.FUNCATTR_START)

for instr in idautils.FuncItems(current_function_start):
    for ref in idautils.CodeRefsFrom(instr, False):
        func_name = idc.get_func_name(ref)
        
        if func_name and idc.get_func_attr(ref, idc.FUNCATTR_START) != current_function_start:
            print("참조된 함수: {}".format(func_name))
