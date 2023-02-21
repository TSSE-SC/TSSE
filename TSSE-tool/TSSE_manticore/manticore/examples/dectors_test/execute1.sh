# !/bin/bash

# for line in $(<index.txt)
# do 
#     python tool.py $line
# done

# nohup bash execut.sh  > log_re_data.out 2>&1 &

for line in $(<TD_index.txt)



do
    # cat ${line}  | while read LINE
    # do
    # if [[ ${LINE:0:15} == "pragma solidity" ]]; then
    # # 注释
    # solc-select use ${LINE: 17: 6}
    # fi
    # done
    timeout 300s python tool_suicidal.py $line
done