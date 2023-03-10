from manticore.ethereum import ManticoreEVM
from manticore.platforms.evm import *
from manticore.core.smtlib import *
from manticore.core.smtlib.visitors import *
from manticore.utils import log
from manticore.platforms import evm
from manticore.ethereum import ManticoreEVM
from pyevmasm import instruction_tables, disassemble_hex, disassemble_all, assemble_hex
################ Script #######################

m = ManticoreEVM()
# And now make the contract account to analyze
source_code = """
contract C {
    uint n;
    function C(uint x) {
        n = x;
    }
    function f(uint x) payable returns (bool) {
        if (x == n) {
            return true;
        }
        else{
            return false;
        }
    }
}
"""

user_account = m.create_account(balance=1000)
print("[+] Creating a user account", user_account)

contract_account = m.solidity_create_contract(source_code=source_code,owner=user_account, args=[42])
print("[+] Creating a contract account", contract_account)
print("[+] Source code:")
# print(source_code)

print("[+] Now the symbolic values")
symbolic_data = m.make_symbolic_buffer(320)
symbolic_value = m.make_symbolic_value(name="value")
m.transaction(caller=user_account, address=contract_account, value=symbolic_value, data=symbolic_data)

# print(f"STORAGE = {translate_to_smtlib(world.get_storage(0x111111111111111111111111111111111111111),use_bindings=False)}")

print("[+] Resulting balances are:")
for state in m.all_states:
    # print(f"STORAGE = {state.platform.get_storage_items(0x111111111111111111111111111111111111111)[0][0]}")
    print(f"STORAGE = {translate_to_smtlib(state.platform.get_storage_items(contract_account)[0][0])}")
    # balance = state.platform.get_balance(int(user_account))
    # print(state.solve_one(balance))

m.finalize()
print(f"[+] Look for results in {m.workspace}")