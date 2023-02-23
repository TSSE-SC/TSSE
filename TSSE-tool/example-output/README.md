# Output
This is an example vulnerability detection document. The detection contract file name is 0x01f8c4e3fa3edeb29e514cba738d87ce8c091d3f.sol, and the detection result is in 0x01f8c4e3fa3edeb29e514cba738d87ce8c091d3f.sol_PERSONAL_BANK folder, the result_tool_reentrancy.csv is the result summary.


## Detection result

* .tx file is a sequence of function transactions;
* .findings file is the result of the vulnerability and contains mainly vulnerability items;
* .constrains file is the path constraint record;
* .tx.json file is a sequence of function transactions in json format;

## result_tool_reentrancy.csv

* filename: file name;
* is-bug: whether to include vulnerabilities;
* total-access-states: number of state visits for the vulnerability detection process;
* time: time consumption;
* msgsender: dependent on msg.sender;
* value: whether to transfer the Ether;
* unrestricted-write-state: write status is not restricted;
* function-name: vulnerable function name;
* trace-file: traces of the transaction; 
* symbolic-execution-time: dynamic symbolic execution runtime;