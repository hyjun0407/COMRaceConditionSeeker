import idautils
import idc
import ida_name
import ida_hexrays
import ida_funcs
import re

func_resolve_dict = []
banlist = ['__imp__Mtx_unlock',' __imp__Mtx_lock','__imp_AcquireSRWLockExclusive', '__imp_ReleaseSRWLockShared', '__imp_InitializeSRWLock','__imp_TryAcquireSRWLockShared','__imp_ReleaseSRWLockExclusive','__imp_AcquireSRWLockExclusive','__imp_TryAcquireSRWLockExclusive','__imp_AcquireSRWLockShared','__imp_TryAcquireSRWLockShared','__imp_EnterCriticalSection','__imp_LeaveCriticalSection']
# 모듈 내의 모든 함수를 순회합니다.


def get_function_pseudocode(ea):
    # Hex-Rays Decompiler가 사용 가능한지 확인
    if not ida_hexrays.init_hexrays_plugin():
        print("Hex-Rays Decompiler is not available.")
        return None

    # 주어진 주소에서 함수를 찾음
    f = ida_funcs.get_func(ea)
    if not f:
        print("Function not found at the given address.")
        return None

    # 함수를 디컴파일
    cfunc = ida_hexrays.decompile(f.start_ea)
    if not cfunc:
        print("Failed to decompile function.")
        return None

    # 디컴파일된 함수의 pseudocode를 문자열로 변환
    pseudocode = str(cfunc)
    return pseudocode

def get_this_pseudo(code_snippet):
    pattern_corrected = r"this \+ (0x[0-9a-fA-F]+|\d+)"
    matches_corrected = re.findall(pattern_corrected, code_snippet)
    return matches_corrected

def get_this_xref(function_name):
    function_start = idc.get_name_ea_simple(function_name)
    function_end = idc.find_func_end(function_start)
    # 함수 내에서 'rcx' 레지스터를 사용하는 모든 명령어를 찾습니다.
    for head in idautils.Heads(function_start, function_end):
        a = idc.generate_disasm_line(head, 0)
        start_index = a.find("[rcx")
        end_index = a.find("]", start_index) + 1 # ']'의 위치를 찾음
        # '['와 ']' 사이의 문자열 추출
        substring = a[start_index:end_index]
        if(start_index != -1):
            print(substring)
    
def get_all_func_resolve():
    func_dict = []
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
                    func_dict.append(['out',current_function_name,ref_func_name,instr])
                # 참조된 주소가 현재 분석 중인 함수의 범위 외부에 있지만, `.idata` 세그먼트에는 없는 경우, 내부 함수로 간주합니다.
                elif ref_func_name and idc.get_func_attr(ref, idc.FUNCATTR_START) != current_function_start:
                    func_dict.append(['in',current_function_name,ref_func_name,instr])
    return func_dict

def get_specific_func_resolve(funcDo):
    func_dict = []
    for func in funcDo:
        # 함수의 시작 주소를 얻습니다.
        current_function_start = func[1]
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
                    func_dict.append(['out',current_function_name,ref_func_name,instr])
                        #print("{} 함수에서 외부 함수 참조: {}".format(current_function_name, ref_func_name))
                # 참조된 주소가 현재 분석 중인 함수의 범위 외부에 있지만, `.idata` 세그먼트에는 없는 경우, 내부 함수로 간주합니다.
                elif ref_func_name and idc.get_func_attr(ref, idc.FUNCATTR_START) != current_function_start:
                    func_dict.append(['in',current_function_name,ref_func_name,instr])
    return func_dict

def get_all_func():
    func_dict = []
    for func in idautils.Functions():
        # 함수의 시작 주소를 얻습니다.
        current_function_start = idc.get_func_attr(func, idc.FUNCATTR_START)
        # 함수의 이름을 얻습니다.
        current_function_name = ida_name.get_name(current_function_start)
        func_dict.append([current_function_name,current_function_start])
    return func_dict


def get_func_calls(func_name):
    func_dict = []  # 함수 호출 정보를 저장할 리스트
    # 입력된 함수 이름으로부터 함수 시작 주소를 가져옵니다.
    func_ea = idc.get_name_ea_simple(func_name)
    if func_ea != idc.BADADDR:
        # 함수가 발견되었을 때만 처리합니다.
        # 함수의 내부 호출 및 외부 호출 정보를 수집합니다.
        for instr in idautils.FuncItems(func_ea):
            # 현재 주소에서 참조하는 모든 코드 참조를 순회합니다.
            for ref in idautils.CodeRefsFrom(instr, False):
                # 참조된 주소의 세그먼트 이름을 가져옵니다.
                seg_name = idc.get_segm_name(ref)
                # 참조된 주소의 함수 이름을 가져옵니다.
                ref_func_name = ida_name.get_name(ref)
                # 참조된 주소가 내부 함수인지 외부 함수인지 확인합니다.
                if ref_func_name and seg_name == '.idata':
                    # 외부 함수로 간주됩니다.
                    func_dict.append(['out', func_name, ref_func_name, instr])
                elif ref_func_name and idc.get_func_attr(ref, idc.FUNCATTR_START) == func_ea:
                    # 내부 함수로 간주됩니다.
                    func_dict.append(['in', func_name, ref_func_name, instr])
    return func_dict

filtered_func = []

my_list = get_all_func()
for check in my_list:
    func_ea = idc.get_name_ea_simple(check[0])
    cfunc = ida_hexrays.decompile(func_ea)
    if cfunc:
        for arg in cfunc.arguments:
            if(arg.name == "this"):
                filtered_func.append(check)

func_resolve_dict = get_specific_func_resolve(filtered_func)
my_list = [sub_list for sub_list in func_resolve_dict if any(item in banlist for item in sub_list)]
only_all_func = get_all_func()
filtered_func_name_addr = []
for get in only_all_func:
    for checklist in my_list:
        if(checklist[1] == get[0]):
            filtered_func_name_addr.append(get)
            break
for filt in filtered_func_name_addr:
    dec = get_function_pseudocode(filt[1])
    pseduo = get_this_pseudo(dec)
    filt.append(pseduo)
    func_ea = idc.get_name_ea_simple(filt[0])
    cfunc = ida_hexrays.decompile(func_ea)
    if cfunc:
        arg = cfunc.arguments[0]
        filt.append(arg.type().dstr())

categorized_list = {}
for item in filtered_func_name_addr:
    category = item[-1]
    if category not in categorized_list:
        categorized_list[category] = []
    categorized_list[category].append(item)


for category, items in categorized_list.items():
    print(f"Category: {category}")
    for item in items:
        print(f"  - {item}")
    print()
