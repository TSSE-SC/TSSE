import time
import sys
import os
import csv




def collect_manti(filename,contract_Name):
    # os.system(" manticore --exclude delegatecall,overflow,env-instr,suicidal,invalid,unused-return,uninitialized-memory,uninitialized-storage %s --contract %s " %(filename,contract_Name))
    global is_bug 
    global state_id 
    global testcase_id 
    global g_coverage
    
    # print(path)
    for file in os.listdir(path):
        if file.startswith("mcore"):
            # print(file)
            fname = filename +'_'+ contract_Name
            newName=file.replace(file,fname)
            os.rename(os.path.join(path,file),os.path.join(path,newName))
            dir = path +'/'+ newName
            for file in os.listdir(dir):
                file_name = dir +'/'+ 'global.findings'
                with open(file_name,'r') as f3:
                    lines=f3.readlines()
                    # print(lines[0])
                    # print(lines[1])
                    if len(lines) != 0:
                        if cond1 in lines or cond2 in lines :
                             is_bug = True
                        else :
                             is_bug = False

                        file_name = dir +'/'+ '.state_id'
                        with open(file_name,'r') as f1:
                            lines=f1.readlines()
                            state_id = lines[0]
                            # print(state_id)

                        file_name = dir +'/'+ '.testcase_id'
                        with open(file_name,'r') as f2:
                            lines=f2.readlines()
                            testcase_id = lines[0]

                        # global.findings
                        file_name = dir +'/'+ 'global.findings'
                        with open(file_name,'r') as f3:
                            lines=f3.readlines()
                            pass

                        # Global runtime coverage
                        file_name = dir +'/'+ 'global.summary'
                        with open(file_name,'r') as f4:
                            lines=f4.readlines()
                            g_coverage = lines[1][-7:-1]
                        
                        return dir,is_bug,state_id,testcase_id,g_coverage
                    else:
                        return dir,is_bug,state_id,testcase_id,g_coverage


if __name__ == "__main__":

    if len(sys.argv) != 3:
        print("python tool.py filename contract_name")
        sys.exit(-1)

    filename = sys.argv[1]
    contract_Name = sys.argv[2]
    fname = ''
    
    result_csv = 'result_manticore_reentrancy.csv'
    start = time.time()

    os.system(" manticore %s --contract %s " %(filename,contract_Name))

    path = '/root/manticore-0.3.0/examples/evm'
    dir = ''
    state_id = 0
    testcase_id = 0
    g_coverage = 0
    fundings = []
    is_bug = False

    cond1 = "- Potential reentrancy vulnerability -"+'\n'
    cond2 ="- Reentrancy multi-million ether bug -"+'\n'

    dir,is_bug,state_id,testcase_id,g_coverage = collect_manti(filename,contract_Name)

    end = time.time()
    ttime = end-start

    print(dir,is_bug,state_id,testcase_id,g_coverage,ttime)

    file = open(result_csv,'a+', encoding='utf-8')
    csv_writer = csv.writer(file)


    row = [dir,is_bug,state_id,testcase_id,g_coverage,ttime]
    csv_writer.writerow(row)


