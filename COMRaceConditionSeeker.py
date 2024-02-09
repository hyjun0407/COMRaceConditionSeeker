import idautils
import idc
import ida_segment

current_function_start = idc.get_func_attr(idc.here(), idc.FUNCATTR_START)

for instr in idautils.FuncItems(current_function_start):
    for ref in idautils.CodeRefsFrom(instr, False):
        seg = ida_segment.getseg(ref)
        if seg and seg.type == ida_segment.SEG_DATA:
            func_addr = idc.get_qword(ref)
            if func_addr:
                func_name = idc.get_func_name(func_addr)
                if func_name:
                    print("간접 호출된 함수: {}".format(func_name))
