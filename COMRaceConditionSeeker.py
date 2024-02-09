import idautils
import idc
import ida_name

# 모듈 내의 모든 함수를 순회합니다.
for func in idautils.Functions():
    # 함수의 시작 주소를 얻습니다.
    current_function_start = idc.get_func_attr(func, idc.FUNCATTR_START)
    # 함수의 이름을 얻습니다.
    current_function_name = ida_name.get_name(current_function_start)

    # 현재 함수의 모든 주소를 순회하며 함수 호출을 찾습니다.
    for instr in idautils.FuncItems(current_function_start):
        # 현재 주소에서 참조하는 모든 코드 참조를 순회합니다.
        for ref in idautils.CodeRefsFrom(instr, False):
            # 참조된 주소의 세그먼트 이름을 얻습니다.
            seg_name = idc.get_segm_name(ref)
            # 참조된 주소의 함수 이름을 얻습니다.
            ref_func_name = ida_name.get_name(ref)
            # 참조된 주소가 현재 분석 중인 함수의 범위 외부에 있고, `.idata` 세그먼트에 있으면 외부 함수로 간주합니다.
            if ref_func_name and seg_name == '.idata':
                if ref_func_name == '__imp_ReleaseSRWLockExclusive':
                print("{} 함수에서 외부 함수 참조: {}".format(current_function_name, ref_func_name))
            # 참조된 주소가 현재 분석 중인 함수의 범위 외부에 있지만, `.idata` 세그먼트에는 없는 경우, 내부 함수로 간주합니다.
            elif ref_func_name and idc.get_func_attr(ref, idc.FUNCATTR_START) != current_function_start:
                print("{} 함수에서 내부 함수 참조: {}".format(current_function_name, ref_func_name))
