from slither import Slither
import sys
from slither.utils.function import get_function_id




def extract_info(isMul,file_name,contract_name,lib_func_list):
    slither = Slither(file_name)
    # all_contracts_name = []
    lib_con_func = []
    lib_func_list = []


    if len(slither.contracts) > 1:
        isMul= True

    # for compilation_unit in slither.compilation_units:
        for contract in slither.contracts:
        # for contract in slither.contracts:
            # print(contract.name)
            all_functions_name = []
            # all_contracts_name.append(c.name)
            for function in contract.functions:
                # all_functions_name.append(function.solidity_signature)
                all_functions_name.append(hex(get_function_id(function.solidity_signature)))

            lib_con_func.append([contract.name,all_functions_name])

    print(lib_con_func)

    # for item in lib_con_func:


    lib_con_func1 = lib_con_func

    for item in lib_con_func1:
        if item[0] == contract_name:
            # lib_con_func.remove(item)
            continue
        else:
            for f in item[1]:
                lib_func_list.append(f)
        
        
    # print(lib_con_func)



    return isMul,lib_con_func,lib_func_list

def extract_info1(isMul,file_name,contract_name,lib_func_list):
    slither = Slither(file_name)
    # all_contracts_name = []
    lib_con_func = []
    lib_func_list = []


    if len(slither.contracts) > 1:
        isMul= True

    # for compilation_unit in slither.compilation_units:
        for contract in slither.contracts:
        # for contract in slither.contracts:
            # print(contract.name)
            all_functions_name = []
            # all_contracts_name.append(c.name)
            for function in contract.functions:
                # all_functions_name.append(function.solidity_signature)
                all_functions_name.append(hex(get_function_id(function.solidity_signature)))

            lib_con_func.append([contract.name,all_functions_name])

    print("lib_con_func",lib_con_func)

    # for item in lib_con_func:


    lib_con_func1 = lib_con_func

    for item in lib_con_func1:
        if item[0] == contract_name:
            # lib_con_func.remove(item)
            continue
        else:
            for f in item[1]:
                lib_func_list.append(f)
        
        
    print(isMul,lib_con_func,lib_func_list)



    return isMul,lib_con_func,lib_func_list













if __name__ == "__main__":

    if len(sys.argv) != 3:
        print("python tool.py 合约文件.sol")
        sys.exit(-1)
    isMul= False
    file_name = sys.argv[1]
    contract_name = sys.argv[2]
    lib_con_func = []
    lib_func_list = []



    isMul,lib_con_func,lib_func_list = extract_info(isMul,file_name,contract_name,lib_func_list)

    print(isMul,lib_con_func,lib_func_list)
    # print(lib_con_func[0][1])





