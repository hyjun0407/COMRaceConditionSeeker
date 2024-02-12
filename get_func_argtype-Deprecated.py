import idautils
import idc
import ida_name
import ida_hexrays
func_ea = idc.get_name_ea_simple("?put_AuthData@SignInContext@Internal@System@Windows@@UEAAJPEAUHSTRING__@@@Z")
cfunc = ida_hexrays.decompile(func_ea)
if cfunc:
    for arg in cfunc.arguments:
        print(arg.name,arg.type())
