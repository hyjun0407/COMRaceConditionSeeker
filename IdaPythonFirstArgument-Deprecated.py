import ida_hexrays
import idautils
import idaapi
import ida_name

# 특정 함수 호출의 인자를 디컴파일된 형태로 찾는 visitor 클래스
class FuncCallVisitor(ida_hexrays.ctree_visitor_t):
    def __init__(self, target_func_name):
        super(FuncCallVisitor, self).__init__(ida_hexrays.CV_FAST)
        self.target_func_name = target_func_name

    def visit_expr(self, e):
        if e.op == ida_hexrays.cot_call and e.x.obj_ea != idaapi.BADADDR:
            called_func_ea = e.x.obj_ea
            called_func_name = ida_funcs.get_func_name(called_func_ea)
            if called_func_name == self.target_func_name:
                print(f"Found call to {self.target_func_name} at {hex(called_func_ea)} with arguments:")
                for arg in e.a:
                    # 변환된 인자 표현식을 문자열로 출력
                    arg_str = ida_hexrays.citem_t.print1(arg)
                    arg_str = ida_lines.tag_remove(arg_str)
                    print(f"  Argument: {arg_str}")
                return 0
        return 0

def analyze_function_for_call(func_name, target_func_name):
    # 함수 이름으로부터 함수 주소 얻기
    func_ea = ida_name.get_name_ea(idaapi.BADADDR, func_name)
    if func_ea == idaapi.BADADDR:
        print(f"Failed to find function address for {func_name}.")
        return

    # 특정 함수 디컴파일
    cfunc = idaapi.decompile(func_ea)
    if cfunc is None:
        print("Failed to decompile function.")
        return
    
    # visitor 생성 및 적용
    visitor = FuncCallVisitor(target_func_name)
    visitor.apply_to(cfunc.body, None)
# 분석할 함수의 이름 예시: 'example_function'
analyze_function_for_call("?put_AuthData@SignInContext@Internal@System@Windows@@UEAAJPEAUHSTRING__@@@Z", "?Set@HString@Wrappers@WRL@Microsoft@@QEAAJAEBQEAUHSTRING__@@@Z")
