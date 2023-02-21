# from asyncio.windows_events import NULL
import time
import sys
import os
import csv
from slither import Slither
# from slither.slither import Slither
from slither.utils.function import get_function_id
import json
import func_timeout
from print_pragma_version import get_solc
from manti_reen1 import d_execute
from run_manticore import task_detect


def detect_tasks(filename,contractname,functionname,task2_payable,task3_modifier):
    slither = Slither(filename)
    contracts = slither.get_contract_from_name(contractname)
    # print(type(contracts))
    # assert len(contracts) == 1
    # contract = contracts[0]
    if contracts:
        for function in contracts.functions:
        # for function in contracts[0].functions:
            if function.name == functionname:
                # 判定函数是否有payable修饰
                if function.payable:
                    task2_payable = True
                # 判定函数是否有自定义修饰器
                if function.modifiers:
                    task3_modifier = True

    return task2_payable,task3_modifier


def staticDetect(filename,task1_msgsender,task2_payable,task3_modifier):
    # 判定函数是否有msg.sender的权限界定
    # needDetect代表slither检测出存在漏洞
    f_name1 = ""
    f_name2 = ""
    global needDetect 
    global Contract_name
    global Function_name
    print(filename)
    Result_Name = filename +'.json'
    os.system("rm -f %s" %(Result_Name))
    os.system("slither %s --detect reentrancy-eth,unrestricted-write-state --solc-disable-warnings --json %s" %(filename,Result_Name))
    with open(Result_Name) as f:
        results = json.load(f)

            # Function_name1 = results['results']['detectors'][0]['elements'][0]['name']
        if results['success']:
            # print(results['results'] )
            if results['results'] != {}:

                detcet_list = []
                # 寻找未限制写入漏洞项
                for item in results['results']['detectors']:
                    # print("slither成功")
                    if item['check'] == "reentrancy-eth":
                        Function_name1 = item['elements'][0]['name']
                        f_name1 = item['elements'][0]['type_specific_fields']['signature']
                        c_name1 = item['elements'][0]['type_specific_fields']['parent']['name']
                        # task1_msgsender = True
                        # print(f_name1)
                    if item['check'] == "unrestricted-write-state":
                        f_name2 = item['elements'][0]['type_specific_fields']['signature']
                        detcet_list.append(f_name2)
                        # task1_msgsender = True
                        # print(detcet_list)
                if f_name1 in detcet_list:
                    # print(detcet_list)
                    needDetect = True
                    task1_msgsender = True
                    Function_name = f_name1
                    print(Function_name)
                    Contract_name = c_name1
                    task2_payable,task3_modifier = detect_tasks(filename,Contract_name,Function_name1,task2_payable,task3_modifier)
                else :
                    needDetect = False
                    Function_name = "NO_1"
                    Contract_name = None 
            else:
                needDetect = False
                Function_name = "NO_static"
                Contract_name = None          
        else:
            needDetect = False
            Function_name = "compile error!"
            Contract_name = None
                
    # print(task1_msgsender,task2_payable,task3_modifier)
    os.system("rm -f %s" %(Result_Name))
    return needDetect,Contract_name,Function_name,task1_msgsender,task2_payable,task3_modifier

def staticDetect_suicidal(filename,task1_msgsender,task2_payable,task3_modifier):
    # 判定函数是否有msg.sender的权限界定
    # needDetect代表slither检测出存在漏洞
    f_name1 = ""
    f_name2 = ""
    global needDetect 
    global Contract_name
    global Function_name
    fun_id = 0
    print(filename)
    Result_Name = filename +'.json'
    os.system("rm -f %s" %(Result_Name))
    os.system("slither %s --detect suicidal,unrestricted-write-state --solc-disable-warnings --json %s" %(filename,Result_Name))
    with open(Result_Name) as f:
        results = json.load(f)
        if results['success']:
            # print(results['results'] )
            if results['results'] != {}:

                detcet_list = []
                # 寻找未限制写入漏洞项
                for item in results['results']['detectors']:
                    # print("slither成功")
                    if item['check'] == "suicidal":
                        Function_name1 = item['elements'][0]['name']
                        f_name1 = item['elements'][0]['type_specific_fields']['signature']
                        c_name1 = item['elements'][0]['type_specific_fields']['parent']['name']
                    if item['check'] == "unrestricted-write-state" and item['impact'] == "owner":
                        f_name2 = item['elements'][0]['type_specific_fields']['signature']
                        detcet_list.append(f_name2)                    
                        # task1_msgsender = True
                        # fun_id = get_function_id(f_name1)
                        # needDetect = True
                        # Function_name = f_name1
                        # Contract_name = c_name1
                        # task2_payable,task3_modifier = detect_tasks(filename,Contract_name,Function_name1,task2_payable,task3_modifier)
                        # print(f_name1)
       
                if (f_name1 != "" and f_name2 != ""):
                    # print(detcet_list)
                    fun_id = get_function_id(f_name1)
                    needDetect = True
                    Function_name = f_name1
                    Contract_name = c_name1
                    task2_payable,task3_modifier = detect_tasks(filename,Contract_name,Function_name1,task2_payable,task3_modifier)
                else :
                    needDetect = False
                    Function_name = "NO_1"
                    Contract_name = None 

            else:
                needDetect = False
                Function_name = "NO_static"
                Contract_name = None   
                # fun_id = None       
        else:
            needDetect = False
            Function_name = "compile error!"
            Contract_name = None
            # fun_id = 0
                
    # print(task1_msgsender,task2_payable,task3_modifier)
    os.system("rm -f %s" %(Result_Name))
    return needDetect,Contract_name,Function_name,hex(fun_id),task1_msgsender,task2_payable,task3_modifier

def staticDetect_timestamp(filename,task1_msgsender,task2_payable,task3_modifier):
    # 判定函数是否有msg.sender的权限界定
    # needDetect代表slither检测出存在漏洞
    f_name1 = ""
    f_name2 = ""
    global needDetect 
    global Contract_name
    global Function_name
    fun_id = 0
    print(filename)
    Result_Name = filename +'.json'
    os.system("rm -f %s" %(Result_Name))
    os.system("slither %s --detect timestamp,unrestricted-write-state --solc-disable-warnings --json %s" %(filename,Result_Name))
    with open(Result_Name) as f:
        results = json.load(f)
        if results['success']:
            # print(results['results'] )
            if results['results'] != {}:

                detcet_list = []
                # 寻找未限制写入漏洞项
                for item in results['results']['detectors']:
                    # print("slither成功")
                    if item['check'] == "timestamp":
                        Function_name1 = item['elements'][0]['name']
                        f_name1 = item['elements'][0]['type_specific_fields']['signature']
                        c_name1 = item['elements'][0]['type_specific_fields']['parent']['name']
                        # task1_msgsender = True
                        fun_id = get_function_id(f_name1)
                        needDetect = True
                        Function_name = f_name1
                        Contract_name = c_name1
                        task2_payable,task3_modifier = detect_tasks(filename,Contract_name,Function_name1,task2_payable,task3_modifier)
                        # print(f_name1)
       
                        # print(detcet_list)

            else:
                needDetect = False
                Function_name = "NO_static"
                Contract_name = None   
                # fun_id = 0       
        else:
            needDetect = False
            Function_name = "compile error!"
            Contract_name = None
            # fun_id = 0 
                
    # print(task1_msgsender,task2_payable,task3_modifier)
    os.system("rm -f %s" %(Result_Name))
    return needDetect,Contract_name,Function_name,hex(fun_id),task1_msgsender,task2_payable,task3_modifier


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("python tool.py filename")
        sys.exit(-1)

    filename = sys.argv[1]
    # contract_Name = sys.argv[2]
    fname = ''

    result_csv = 'result_tool_suiciadl.csv'
    start = time.time()


    dir = ''
    state_id = 0
    testcase_id = 0
    g_coverage = 0
    fundings = []
    is_bug = False
    needDetect = False
    Contract_name=""
    Function_name=""
# ////////////////////////////////////////////////////////
# SC
    needDetect_sc = False
    Contract_name_sc=""
    Function_name_sc=""
    fun_id_sc = 0
    task1_msgsender_sc = False
    task2_payable_sc = False
    task3_modifier_sc = False
# ////////////////////////////////////////////////////////
# TS
    needDetect_ts = False
    Contract_name_ts=""
    Function_name_ts=""
    fun_id_ts = 0
    task1_msgsender_ts = False
    task2_payable_ts = False
    task3_modifier_ts = False
    
    timeout = 100
    

    cond1 ="- Potential reentrancy vulnerability -\n"
    cond2 ="- Reentrancy multi-million ether bug -\n"
    cond3 ="- Reachable ether leak to sender -\n"
    cond4 ="- Reachable ether leak1 to sender -\n"


    # task1_msgsender :既包含重入的基本条件也包括未限制的写入漏洞
    # task2_payable  ：是否有payable修饰
    # task3_modifier ：是否有自定义修饰器



    solc_v = get_solc(filename)
    print(solc_v)
    os.system("timeout 20s solc-select use %s" %(solc_v))

    # SC
    needDetect_sc,Contract_name_sc,Function_name_sc,fun_id_sc,task1_msgsender_sc,task2_payable_sc,task3_modifier_sc = staticDetect_suicidal(filename,task1_msgsender_sc,task2_payable_sc,task3_modifier_sc)
    print(needDetect_sc,Contract_name_sc,Function_name_sc,fun_id_sc,task1_msgsender_sc,task2_payable_sc,task3_modifier_sc)
    # TS
    needDetect_ts,Contract_name_ts,Function_name_ts,fun_id_ts,task1_msgsender_ts,task2_payable_ts,task3_modifier_ts = staticDetect_timestamp(filename,task1_msgsender_ts,task2_payable_ts,task3_modifier_ts)
    print(needDetect_ts,Contract_name_ts,Function_name_ts,fun_id_ts,task1_msgsender_ts,task2_payable_ts,task3_modifier_ts)
    # needDetect_sc = True
    # needDetect_ts = False
    if needDetect_sc:
        start_d = time.time()
        try:
            task_detect(timeout, filename, Contract_name_sc, "B2",Function_name_sc)
        except func_timeout.exceptions.FunctionTimedOut:
            print("timeout")
        finally:  
            os.system("rm -rf mcore*")
            end_d = time.time()
            d_ttime = end_d-start_d
            end = time.time()
            ttime = end-start
            file = open(result_csv,'a+', encoding='utf-8')
            csv_writer = csv.writer(file)
            row = [filename,'suicidal','NULL',ttime,task1_msgsender_sc,task2_payable_sc,task3_modifier_sc,Function_name_sc,d_ttime]
            csv_writer.writerow(row)
    elif needDetect_ts:
        start_d = time.time()
        try:
            task_detect(timeout, filename, Contract_name_ts, "B3",Function_name_ts)
        except func_timeout.exceptions.FunctionTimedOut:
            print("timeout")
        finally:     
            os.system("rm -rf mcore*")
            end_d = time.time()
            d_ttime = end_d-start_d
            end = time.time()
            ttime = end-start
            file = open(result_csv,'a+', encoding='utf-8')
            csv_writer = csv.writer(file)
            row = [filename,'timestamp','NULL',ttime,task1_msgsender_ts,task2_payable_ts,task3_modifier_ts,Function_name_ts,d_ttime]
            csv_writer.writerow(row)
    else:
        is_bug = False
        end = time.time()
        ttime = end-start
        # print(dir,is_bug,state_id,testcase_id,g_coverage,ttime)
        file = open(result_csv,'a+', encoding='utf-8')
        csv_writer = csv.writer(file)
        row = [filename,is_bug,0,ttime,'NULL','NULL','NULL',Function_name]
        csv_writer.writerow(row)





