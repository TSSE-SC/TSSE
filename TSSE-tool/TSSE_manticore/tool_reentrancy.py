import time
import sys
import os
import csv
from slither import Slither
import func_timeout
import json
from print_pragma_version import get_solc
from manti_reen import d_execute



def detect_tasks(filename,contractname,functionname,task2_payable,task3_modifier):
    slither = Slither(filename)
    contracts = slither.get_contract_from_name(contractname)
    if contracts:
        for function in contracts.functions:
        # for function in contracts[0].functions:
            if function.name == functionname:
                if function.payable:
                    task2_payable = True
                if function.modifiers:
                    task3_modifier = True

    return task2_payable,task3_modifier


def staticDetect(filename,task1_msgsender,task2_payable,task3_modifier):
    f_name1 = ""
    f_name2 = ""
    global needDetect 
    global Contract_name
    global Function_name
    print(filename)
    Result_Name = filename +'.json'
    os.system("rm -f %s" %(Result_Name))
    os.system("slither %s --detect reentrancy-eth,unrestricted-write-state,arbitrary-send,reentrancy-benign --solc-disable-warnings --json %s" %(filename,Result_Name))
    with open(Result_Name) as f:
        results = json.load(f)

        if results['success']:
            # print(results['results'] )
            if results['results'] != {}:

                detcet_list = []
                for item in results['results']['detectors']:
                    if item['check'] == "reentrancy-eth" or item['check'] == "arbitrary-send" or item['check'] == "reentrancy-benign":
                        Function_name1 = item['elements'][0]['name']
                        f_name1 = item['elements'][0]['type_specific_fields']['signature']
                        c_name1 = item['elements'][0]['type_specific_fields']['parent']['name']
                    if item['check'] == "unrestricted-write-state":
                        f_name2 = item['elements'][0]['type_specific_fields']['signature']
                        detcet_list.append(f_name2)
                    
                if f_name1 != "":
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
                
    os.system("rm -f %s" %(Result_Name))
    return needDetect,Contract_name,Function_name,task1_msgsender,task2_payable,task3_modifier





if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("python tool.py filename")
        sys.exit(-1)

    filename = sys.argv[1]
    fname = ''

    result_csv = 'result_tool_reentrancy.csv'
    start = time.time()


    dir = ''
    state_id = 0
    testcase_id = 0
    g_coverage = 0
    fundings = []
    needDetect = False
    is_bug = False
    Contract_name=""
    Function_name=""

    cond1 ="- Potential reentrancy vulnerability -\n"
    cond2 ="- Reentrancy multi-million ether bug -\n"
    cond3 ="- Reachable ether leak to sender -\n"
    cond4 ="- Reachable ether leak1 to sender -\n"

    task1_msgsender = False
    task2_payable = False
    task3_modifier = False

    solc_v = get_solc(filename)
    os.system("solc-select use %s" %(solc_v))

    needDetect,Contract_name,Function_name,task1_msgsender,task2_payable,task3_modifier = staticDetect(filename,task1_msgsender,task2_payable,task3_modifier)
    print(needDetect,Contract_name,Function_name,task1_msgsender,task2_payable,task3_modifier)

    if needDetect :

        if (task1_msgsender == True and task3_modifier == False or task1_msgsender == True):
            start_d = time.time()
            dir,is_bug,state_id = d_execute(filename,Contract_name,Function_name)

            end_d = time.time()
            d_ttime = end_d-start_d
            end = time.time()
            ttime = end-start
            file = open(result_csv,'a+', encoding='utf-8')
            csv_writer = csv.writer(file)
            row = [filename,is_bug,state_id,ttime,task1_msgsender,task2_payable,task3_modifier,Function_name,dir,d_ttime]
            csv_writer.writerow(row)
        else:
            is_bug = False
            end = time.time()
            ttime = end-start
            file = open(result_csv,'a+', encoding='utf-8')
            csv_writer = csv.writer(file)
            row = [filename,is_bug,0,ttime,task1_msgsender,task2_payable,task3_modifier,Function_name]
            csv_writer.writerow(row)
    else:
        is_bug = False
        end = time.time()
        ttime = end-start
        file = open(result_csv,'a+', encoding='utf-8')
        csv_writer = csv.writer(file)
        row = [filename,is_bug,0,ttime,task1_msgsender,task2_payable,task3_modifier,Function_name]
        csv_writer.writerow(row)
    os.system("rm -rf mcore*")




