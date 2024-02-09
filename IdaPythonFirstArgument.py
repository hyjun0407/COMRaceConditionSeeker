import idaapi
import idc

class FirstArgumentExtractor(idaapi.ctree_visitor_t):
    def __init__(self):
        super(FirstArgumentExtractor, self).__init__(idaapi.CV_FAST)

    def _expr_to_string(self, expr):
        # cexpr_t 객체를 문자열로 변환합니다.
        return idaapi.tag_remove(idaapi.generate_disasm_line(expr.ea, 0))

    def visit_expr(self, e):
        # 함수 호출 표현식을 찾습니다.
        if e.op == idaapi.cot_call:
            # 호출에 인자가 하나 이상 있는지 확인합니다.
            if len(e.a) > 0:
                # 첫 번째 인자를 가져옵니다.
                first_arg = e.a[0]
                # 첫 번째 인자를 문자열로 변환합니다.
                arg_str = self._expr_to_string(first_arg)
                print("Found a call with first argument:", arg_str)
        # 순회를 계속하기 위해 0을 반환합니다.
        return 0

# 현재 위치의 함수를 디컴파일합니다.
cfunc = idaapi.decompile(idc.here())
if cfunc is None:
    print("Decompilation failed.")
else:
    # Extractor 인스턴스를 생성하고 CTREE에 적용합니다.
    extractor = FirstArgumentExtractor()
    extractor.apply_to(cfunc.body, None)
