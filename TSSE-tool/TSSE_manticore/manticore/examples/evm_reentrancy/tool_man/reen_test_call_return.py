from manticore.core.plugin import Plugin
from manticore.core.smtlib.visitors import simplify
import hashlib
import logging
from manticore.core.workspace import *
from contextlib import contextmanager
from manticore.core.smtlib.operators import OR, NOT, AND
from manticore.core.smtlib import ConstraintSet, operators, Constant, simplify
from manticore.core.smtlib.expression import issymbolic, taint_with, get_taints
# from manticore.utils.helpers import istainted, issymbolic, taint_with, get_taints
from manticore.core.plugin import Plugin
from manticore.ethereum import (ManticoreEVM,Detector,ABI)
from manticore.core.smtlib import Operators, to_constant
import pyevmasm as EVMAsm
import sys
import time
from binascii import unhexlify, hexlify
# from manticore.ethereum import (
#     # DetectExternalCallAndLeak,
#     # DetectReentrancyAdvanced,
# )
from manticore.ethereum.plugins import (
    FilterFunctions,
    # KeepOnlyIfStorageChanges,
    # SkipRevertBasicBlocks,
)
from contract_count import extract_info
from pyevmasm import instruction_tables, disassemble_hex, disassemble_all, assemble_hex
import binascii

################ Script #######################


class DetectReentrancyAdvanced(Detector):
    """
    Detector for reentrancy bugs.
    Given an optional concrete list of attacker addresses, warn on the following conditions.
    1) A _successful_ call to an attacker address (address in attacker list), or any human account address
    (if no list is given). With enough gas (>2300).
    2) A SSTORE after the execution of the CALL.
    3) The storage slot of the SSTORE must be used in some path to control flow
    """

    # ARGUMENT = "reentrancy-adv"
    # HELP = "Reentrancy bug (different method)"
    # IMPACT = DetectorClassification.HIGH
    # CONFIDENCE = DetectorClassification.HIGH

    def __init__(self, addresses=None, **kwargs):
        super().__init__(**kwargs)
        # TODO Check addresses are normal accounts. Heuristics implemented here
        # assume target addresses wont execute code. i.e. won't detect a Reentrancy
        # attack in progess but only a potential attack
        self._addresses = addresses

    @property
    def _read_storage_name(self):
        return "{:s}.read_storage".format(self.name)

    def will_open_transaction_callback(self, state, tx):
        # Reset reading log on new human transactions
        if tx.is_human:
            state.context[self._read_storage_name] = set()
            state.context["{:s}.locations".format(self.name)] = dict()

    def did_close_transaction_callback(self, state, tx):
        world = state.platform
        # Check if it was an internal tx
        if not tx.is_human:
            # Check is the tx was successful
            if tx.result:
                # Check if gas was enough for a reentrancy attack
                if state.can_be_true(operators.UGE(tx.gas, 2300)):
                # if tx.gas > 2300:
                    # Check if target address is attaker controlled
                    if (
                        self._addresses is None
                        and not world.get_code(tx.address)
                        or self._addresses is not None
                        and tx.address in self._addresses
                    ):
                        # that's enough. Save current location and read list
                        self._save_location_and_reads(state)
    #     # 添加资金流分析
    # def will_evm_execute_instruction_callback(self, state, instruction, arguments):
    #     if instruction.semantics == "CALL":
    #         dest_address = arguments[1]
    #         sent_value = arguments[2]
    #         msg_sender = state.platform.current_vm.caller

    #         msg = "ether leak1" if state.can_be_true(sent_value != 0) else "external call1"

    #         if issymbolic(dest_address):
    #             # We assume dest_address is symbolic because it came from symbolic tx data (user input argument)
    #             if state.can_be_true(msg_sender == dest_address):
    #                 self.add_finding_here(
    #                     state,
    #                     f"Reachable {msg} to sender via argument",
    #                     constraint=msg_sender == dest_address,
    #                 )
    #             else:
    #                 self.add_finding_here(
    #                         state,
    #                         f"Reachable {msg} to user controlled address via argument",
    #                         constraint=msg_sender != dest_address,
    #                     )


    #                 # ok it can't go to the sender, but can it go to arbitrary addresses? (> 1 other address?)
    #                 # we report nothing if it can't go to > 1 other addresses since that means the code constrained
    #                 # to a specific address at some point, and that was probably intentional. attacker has basically
    #                 # no control.

    #                 possible_destinations = state.solve_n(dest_address, 2)
    #                 if len(possible_destinations) > 1:
    #                     # This might be a false positive if the dest_address can't actually be solved to anything
    #                     # useful/exploitable, even though it can be solved to more than 1 thing
    #                     self.add_finding_here(
    #                         state,
    #                         f"Reachable {msg} to user controlled address via argument",
    #                         constraint=msg_sender != dest_address,
    #                     )
    #         else:
    #             if msg_sender == dest_address:
    #                 self.add_finding_here(state, f"Reachable {msg} to sender")

    def _save_location_and_reads(self, state):
        name = "{:s}.locations".format(self.name)
        locations = state.context.get(name, dict)
        world = state.platform
        address = world.current_vm.address
        pc = world.current_vm.pc
        if isinstance(pc, Constant):
            pc = pc.value
        assert isinstance(pc, int)
        at_init = world.current_transaction.sort == "CREATE"
        location = (address, pc, "Reentrancy multi-million ether bug", at_init)
        locations[location] = set(state.context[self._read_storage_name])
        state.context[name] = locations

    def _get_location_and_reads(self, state):
        name = "{:s}.locations".format(self.name)
        locations = state.context.get(name, dict)
        return locations.items()

    def did_evm_read_storage_callback(self, state, address, offset, value):
        state.context[self._read_storage_name].add((address, offset))

    def did_evm_write_storage_callback(self, state, address, offset, value):
        # if in potential DAO check that write to storage values read before
        # the "send"
        for location, reads in self._get_location_and_reads(state):
            for address_i, offset_i in reads:
                if address_i == address:
                    if state.can_be_true(offset == offset_i):
                        self.add_finding(state, *location)

class KeepOnlyIfStorageChanges(Plugin):
    """This plugin discards all transactions that results in states where
    the underlying EVM storage did not change or in other words,
    there were no writes to it.
    This allows to speed-up EVM engine exploration as we don't
    explore states that have the same storage (contract data).
    However, keep in mind that if the (contract) code relies on
    account balance and the balance is not a symbolic value
    it might be that a certain state will not be covered by the
    execution when this plugin is used.
    """

    def did_open_transaction_callback(self, state, tx, *args):
        """We need a stack. Each tx (internal or not) starts with a "False" flag
        denoting that it did not write anything to the storage
        """
        state.context["written"].append(False)

    def did_close_transaction_callback(self, state, tx, *args):
        """When a tx (internal or not) is closed a value is popped out from the
        flag stack. Depending on the result if the storage is not rolled back the
        next flag in the stack is updated. Not that if the a tx is reverted the
        changes it may have done on the storage will not affect the final result.
        """
        flag = state.context["written"].pop()
        if tx.result in {"RETURN", "STOP"}:
            code_written = (tx.result == "RETURN") and (tx.sort == "CREATE")
            flag = flag or code_written
            # As the ether balance of any account can be manipulated beforehand
            # it does not matter if a state can affect the balances or not.
            # The same reachability should be obtained as the account original
            # balances must be symbolic and free-ish
            if not flag:
                ether_sent = state.can_be_true(tx.value != 0)
                flag = flag or ether_sent
            state.context["written"][-1] = state.context["written"][-1] or flag

    def did_evm_write_storage_callback(self, state, *args):
        """Turn on the corresponding flag is the storage has been modified.
        Note: subject to change if the current transaction is reverted"""
        state.context["written"][-1] = True

    def will_run_callback(self, *args):
        """Initialize the flag stack at each human tx/run()"""
        for st in self.manticore.ready_states:
            st.context["written"] = [False]

    def did_run_callback(self):
        """When  human tx/run just ended remove the states that have not changed
        the storage"""
        with self.manticore.locked_context("ethereum.saved_states", list) as saved_states:
            # Normally the ready states are consumed and forked, eth save the
            # states that finished ok in a special context list. This list will
            # compose the ready states for the next human transaction.
            # The actual "ready_states" list at this point contain the states
            # that have not finished the previous TX due to a timeout. Those will
            # be ignored.
            for state_id in list(saved_states):
                st = self.manticore._load(state_id)
                if not st.context["written"][-1]:
                    if st.id in self.manticore._ready_states:
                        self._publish(
                            "will_transition_state",
                            state_id,
                            StateLists.ready,
                            StateLists.terminated,
                        )
                        self.manticore._ready_states.remove(st.id)
                        self.manticore._terminated_states.append(st.id)
                        self._publish(
                            "did_transition_state",
                            state_id,
                            StateLists.ready,
                            StateLists.terminated,
                        )
                    saved_states.remove(st.id)

    def generate_testcase(self, state, testcase, message):
        with testcase.open_stream("summary") as stream:
            if not state.context.get("written", (False,))[-1]:
                stream.write(
                    "State was removed from ready list because the last tx did not write to the storage"
                )

class StopAtDepth(Detector):
    """This just aborts explorations that are too deep"""

    def will_run_callback(self, *args):
        with self.manticore.locked_context("seen_rep", dict) as reps:
            reps.clear()

    def will_decode_instruction_callback(self, state, pc):
        world = state.platform
        with self.manticore.locked_context("seen_rep", dict) as reps:
            item = (
                world.current_transaction.sort == "CREATE",
                world.current_transaction.address,
                pc,
            )
            if not item in reps:
                reps[item] = 0
            reps[item] += 1
            if reps[item] > 6:
                state.abandon()

class SkipRevertBasicBlocks(Detector):
    
    def __init__(self, Lib_Address=None, **kwargs):
        super().__init__(**kwargs)
        # TODO Check addresses are normal accounts. Heuristics implemented here
        # assume target addresses wont execute code. i.e. won't detect a Reentrancy
        # attack in progess but only a potential attack
        self._Lib_Address = Lib_Address
        # self._Dest_loc = Dest_loc

    def will_evm_execute_instruction_callback(self, state, instruction, arguments):
        world = state.platform
        if state.platform.current_transaction.sort != "CREATE":
            if instruction.semantics == "CALL":
                dest_address = arguments[1]
                sent_value = arguments[2]
                msg_sender = state.platform.current_vm.caller

                curr_tx = world.current_transaction
                d = curr_tx.data[:4]
                d = state.solve_one(d)
                s_value = state.solve_one(sent_value)

                if issymbolic(dest_address):
                    # We assume dest_address is symbolic because it came from symbolic tx data (user input argument)
                    arguments[1] = self._Lib_Address
                    print(arguments)
                    calldata = world.current_vm.read_buffer(arguments[3], arguments[4])
                    print(calldata)
                    world.start_transaction('CALL',arguments[1],data=calldata,caller=msg_sender,value=arguments[2],gas=30000)
            
            if instruction.semantics == "RETURN":
                m._migrate_tx_expressions(state, msg_sender, curr_tx.address, sent_value, calldata)
                        



class SkipLibCall(Detector):

    def __init__(self, Lib_function=None,Dest_loc=None, **kwargs):
        super().__init__(**kwargs)
        # TODO Check addresses are normal accounts. Heuristics implemented here
        # assume target addresses wont execute code. i.e. won't detect a Reentrancy
        # attack in progess but only a potential attack
        self._Lib_function = Lib_function
        self._Dest_loc = Dest_loc

    def _is_revert_bb(self, state, pc):
        world = state.platform

        def read_code(_pc=None):
            # is_REVERT = 0
            while True:
                # print(to_constant(world.current_vm.read_code(_pc)[0]))
                yield to_constant(world.current_vm.read_code(_pc)[0])
                _pc += 1

        for inst in EVMAsm.disassemble_all(read_code(pc), pc):
            print("inst.name",inst.name)
            # if inst.name == "REVERT":
            #     return hex(inst.pc)
            
            # else :
            #     return 0
                # return True
            if inst.is_terminator:
                print("基本块边界：",inst.pc,inst.name)
                return False
    
    def _is_revert_bb1(self, state, pc):
        world = state.platform

        def read_code(_pc=None):
            # is_REVERT = 0
            while True:
                yield to_constant(world.current_vm.read_code(_pc)[0])
                _pc += 1

        for inst in EVMAsm.disassemble_all(read_code(pc), pc):
            if inst.name == "PUSH2":
                l_dest = hex(inst.operand)
                print("push2对应的跳转地址：",l_dest)
                return l_dest


                # pc0 = self._is_revert_bb(state, inst.pc+4)
                # pc0 = self._is_revert_bb(state, inst.pc)
                # print("jumpide 位置：",pc0)
                # if pc0 != 0:
                #     return pc0
                # else :
                #     return 0
            # if inst.is_terminator:
            #     return False

    def will_evm_execute_instruction_callback(self, state, instruction, arguments):
        world = state.platform
        if state.platform.current_transaction.sort != "CREATE":

            if instruction.semantics == "CALL":
                dest_address = arguments[1]
                sent_value = arguments[2]
                msg_sender = state.platform.current_vm.caller

                print(arguments)
                curr_tx = world.current_transaction
                d = curr_tx.data[:4]
                d = state.solve_one(d)
                s_value = state.solve_one(sent_value)
                print(s_value,d)
                # msg = "ether leak" if state.can_be_true(sent_value != 0) else "external call"
                msg = "ether leak" if issymbolic(sent_value) else "external call"
                if issymbolic(dest_address):
                    # We assume dest_address is symbolic because it came from symbolic tx data (user input argument)
                    # arguments[1] = 0x30000
                    # print(arguments)
                    # calldata = world.current_vm.read_buffer(arguments[3], arguments[4])
                    # print(calldata)
                    # world.start_transaction('CALL',arguments[1],data=calldata,caller=msg_sender,value=arguments[2],gas=30000)
                    # if state.can_be_true(msg_sender == dest_address):
                    self.add_finding_here(
                        state,
                        f"Reachable {msg} to sender via argument",
                        constraint=msg_sender == dest_address,
                    )
                    # else:
                    #     # ok it can't go to the sender, but can it go to arbitrary addresses? (> 1 other address?)
                    #     # we report nothing if it can't go to > 1 other addresses since that means the code constrained
                    #     # to a specific address at some point, and that was probably intentional. attacker has basically
                    #     # no control.

                    #     possible_destinations = state.solve_n(dest_address, 2)
                    #     if len(possible_destinations) > 1:
                    #         # This might be a false positive if the dest_address can't actually be solved to anything
                    #         # useful/exploitable, even though it can be solved to more than 1 thing
                    #         self.add_finding_here(
                    #             state,
                    #             f"Reachable {msg} to user controlled address via argument",
                    #             constraint=msg_sender != dest_address,
                    #         )
                else:
                    if msg_sender == dest_address:
                        self.add_finding_here(state, f"Reachable {msg} to sender")



        # # if state.platform.current_transaction.sort == "CALL":
        #     # if instruction.semantics == "PUSH4" and arguments[0] == "0x4c2f04a4":
        #     if instruction.semantics == "PUSH" and instruction.operand_size == 4:

        #         if hex(arguments[0]) in self._Lib_function:
        #         # if hex(arguments[0]) == self._Lib_function:
        #             print("arguments[0]:",hex(arguments[0]))
        #             # print("jumpi位置2：",world.current_vm.pc + instruction.size)
        #             # if the bb after the jumpi ends ina JUMPI
        #             # pc1 = self._is_revert_bb1(state, world.current_vm.pc + instruction.size)
        #             # print("push2的地址：：",int(pc1,16))


        #             # if pc1 != 0:
        #                 # world.current_vm.pc = int(pc1,16)
        #             world.current_vm.pc = self._Dest_loc
        #             # world.current_vm.pc = 141   #0x8d
            
            
            if instruction.semantics == "CALLDATACOPY":
                print("进入库函数！！！")




def search_cut_loc(runtimecode):

    instruction_table = instruction_tables['istanbul']
    try:
        instrs = list(disassemble_all(binascii.unhexlify(runtimecode)))
    except: #binascii.Error: Odd-length string
        runtimecode = runtimecode+'0'
        instrs = list(disassemble_all(binascii.unhexlify(runtimecode)))
    lib_func_loc = []
    for l in instrs:
        if l.name  == 'STOP' and l_last.name  == 'JUMPDEST' :
            print(l_last.pc)
            lib_func_loc.append(l_last.pc)
            l_last = l
        else:
            l_last = l
    return lib_func_loc







def d_execute(filename,contractname,function_Name):


    with open(filename) as f:
        source_code = f.read()

    m = ManticoreEVM()
    m.verbosity(0)
    isMul= False
    lib_con_func = []
    lib_func_list = []
    lib_jump_loc = []
    isMul,_,lib_func_list = extract_info(isMul,filename,contractname,lib_func_list)
    compile_result  = m._compile(source_code,contractname)
    #  (name, source_code, bytecode, runtime, srcmap, srcmap_runtime, hashes, abi, warnings)
    initcode = compile_result[2]
    runtimecode = compile_result[3].hex()
    lib_jump_loc = search_cut_loc(runtimecode)
    
    source_code1 = """
    pragma solidity ^0.4.13;
    
    contract LogFile {
            
            string w ;

        function testTarget(string memory input) public returns(string memory) {
            w = input;
            return w;
        }
    }

    """



    # m.verbosity(0)
    p = DetectReentrancyAdvanced()
    # l = DetectExternalCallAndLeak()
    l = SkipLibCall()
    m.register_detector(p)
    # m.register_detector(l)
    m.register_plugin(StopAtDepth())
    # m.register_plugin(KeepOnlyIfStorageChanges())
    # m.register_plugin(SkipRevertBasicBlocks(Lib_Address=contract_account.address))
    # m.register_plugin(SkipRevertBasicBlocks())
    m.register_plugin(SkipLibCall(Lib_function=lib_func_list,Dest_loc=lib_jump_loc[0]))
    # Dest_loc： 8d d0 f0 107 134 154

    source_code1 = """
    pragma solidity ^0.4.13;
    
    contract LogFile {
            
            string w ;

        function testTarget(string memory input) public returns(string memory) {
            w = input;
            return w;
        }
    }

    """
    user_account = m.create_account(balance=10000000000000000000000)
    contract_account = m.solidity_create_contract(source_code1, owner=user_account)
    # m.register_detector(SkipRevertBasicBlocks(Lib_Address=contract_account.address))
    # print(initcode.hex())
    # print(hex(int(initcode).encode()))
    # yes
    # user_account = m.create_account(balance=10000000000000000000000)
    # # initcode = '60806040526004361061004c576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680634c2f04a414610051578063a21f0368146100e4575b600080fd5b34801561005d57600080fd5b506100e2600480360381019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190803590602001908201803590602001908080601f01602080910402602001604051908101604052809392919081815260200183838082843782019150505050505091929192905050506101cb565b005b3480156100f057600080fd5b5061010f60048036038101908080359060200190929190505050610316565b604051808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200180602001848152602001838152602001828103825285818151815260200191508051906020019080838360005b8381101561018d578082015181840152602081019050610172565b50505050905090810190601f1680156101ba5780820380516001836020036101000a031916815260200191505b509550505050505060405180910390f35b82600160000160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555042600160030181905550816001600201819055508060018001908051906020019061023b92919061040d565b5060006001908060018154018082558091505090600182039060005260206000209060040201600090919290919091506000820160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff168160000160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550600182018160010190805460018160011615610100020316600290046102f992919061048d565b506002820154816002015560038201548160030155505050505050565b60008181548110151561032557fe5b90600052602060002090600402016000915090508060000160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1690806001018054600181600116156101000203166002900480601f0160208091040260200160405190810160405280929190818152602001828054600181600116156101000203166002900480156103f75780601f106103cc576101008083540402835291602001916103f7565b820191906000526020600020905b8154815290600101906020018083116103da57829003601f168201915b5050505050908060020154908060030154905084565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f1061044e57805160ff191683800117855561047c565b8280016001018555821561047c579182015b8281111561047b578251825591602001919060010190610460565b5b5090506104899190610514565b5090565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f106104c65780548555610503565b8280016001018555821561050357600052602060002091601f016020900482015b828111156105025782548255916001019190600101906104e7565b5b5090506105109190610514565b5090565b61053691905b8082111561053257600081600090555060010161051a565b5090565b905600a165627a7a72305820d3563f40e8e70c1f08a935420a1c9c415d2b9de0c675f88028fbf64902452c5e0029'
    # # initcode = initcode.encode()
    # contract_account = m.solidity_create_contract(source_code1, owner=user_account)
    # contract_account = m.create_contract(owner=user_account, balance=0, init=initcode)

    print("user",contract_account.address)
    
    # m.register_plugin(SkipRevertBasicBlocks(Lib_Address=contract_account.address))
    symbolic_value = m.make_symbolic_value()
    m.multi_tx_analysis(filename, contract_name=contractname, args=symbolic_value,tx_limit=2,tx_preconstrain=True,tx_use_coverage=True,tx_send_ether=True,libraries=[("LogFile", contract_account.address)])
    # m.multi_tx_analysis(filename, contract_name=contractname, args=symbolic_value,tx_limit=2,tx_preconstrain=True,tx_use_coverage=True,tx_send_ether=True)
    # m.multi_tx_analysis1(initcode, contract_name=contractname, args=symbolic_value,tx_limit=2,tx_preconstrain=False,tx_use_coverage=True,tx_send_ether=True)
    # # state = next(m.ready_states)  

    # m.finalize()

    # actual_findings = set(((c, d) for a, b, c, d in m.global_findings))

    # print(actual_findings)

    for state in m.ready_states:
        f_value = []
        l_l = 0
        l_p = []
        is_exis = False
        findings = l.get_findings(state)
        findings1 = p.get_findings(state)
        print("lllll",findings)
        print("ppppp",findings1)

        # info_l = "Reachable ether leak to sender"
        # info_l1 = "Reachable ether leak1 to sender"
        # info_p = "Reentrancy multi-million ether bug"
        # for item in findings:
        #     v = item[2]
        #     if v == info_l:
        #         is_exis = True  

        # # for item in findings1:
        # #     v = item[2]
        # #     if v == info_p:
        # #         l_p.append(item[1])
        # # if l_l in l_p:
        # #     is_exis = True

        # for item in findings1:
        #     v = item[2]
        #     if v == info_l1:
        #         is_exis = True  

        info_l = "Reachable ether leak to sender"
        info_p = "Reentrancy multi-million ether bug"
        for item in findings:
            v = item[2]
            if v == info_l:
                l_l = item[1]

        for item in findings1:
            v = item[2]
            if v == info_p:
                l_p.append(item[1])
        if l_l in l_p:
            is_exis = True
    # 0x9173a3c8
    # 0000000000000000000000000000000000000000000000000000000000000020
    # 0000000000000000000000000000000000000000000000000000000000000001
    # 6100000000000000000000000000000000000000000000000000000000000000
    # ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
        # retval_array = state.platform.transactions[-1].return_data
        # retval = operators.CONCAT(256, *retval_array)
        # if m.generate_testcase(state, "return can be 0", only_if=retval == 0):
        #     expected_files = {"user_00000000." + ext for ext in ("summary", "constraints", "pkl", "tx.json", "tx", "trace", "logs")}
        #     expected_files.add("state_00000000.pkl")
        #     print("Bug found! see {}".format(m.workspace))
    
   # ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
        if is_exis:
            if len(state.platform.transactions) > 2:
                # print("READS", len(p.context["reen_s"]))
                # print("READS", p.context["reen_s"])

                reentry_string = ABI.function_selector(function_Name)
                caller = state.platform.transactions[-1].caller
                balance2 = state.platform.get_balance(caller)
                d = state.platform.transactions[-1].data
                d1 = state.platform.transactions[-2].data[:4]
                value = state.platform.transactions[-2].value

                # contract_account = state.platform.transactions[-1].contract_account
                funcid, dynargs = ABI.deserialize(type_spec=function_Name, data=d)
                funcd = state.solve_one(funcid)
                funcd1 = state.solve_one(d1)
                tvaule = state.solve_one(value)
                balance2 = state.solve_one(balance2)
            
                # new_coverage = m.global_coverage(contract_account)
                print(funcd,reentry_string,funcd1,tvaule,balance2,findings)
                if m.generate_testcase(state, "maybe reentrancy?", only_if=funcd == reentry_string):
                # if m.generate_testcase(state, "maybe reentrancy?", only_if=AND(funcd == reentry_string,operators.UGT(tvaule , 0))):
                # if m.generate_testcase(state, "maybe reentrancy?"):
                # AND(funcd == reentry_string,funcd != funcd1,operators.UGT(tvaule , 0)),AND(funcd == reentry_string,funcd != funcd1,balance2 != 1000)
                # if m.generate_testcase(state, "maybe reentrancy?", only_if=OR(AND(funcd == reentry_string,operators.UGT(tvaule, 0)),AND(funcd == reentry_string,balance2 != 1000))):
                    expected_files = {"user_00000000." + ext for ext in ("summary", "tx.json", "tx", "trace","findings")}
                    # expected_files = {"user_00000000." + ext for ext in ("summary", "constraints", "pkl", "tx.json", "tx", "trace", "logs","findings")}
                    # expected_files.add("state_00000000.pkl")
                    print(funcd,reentry_string,funcd1,tvaule,balance2,findings)
                    print("Bug found! see {}".format(m.workspace))
                    # print(.format(m.workspace))

                    # break
                    fname = filename +'_'+ contract_Name
                    newName="/data/home/wangzexu/manticore_pro/manticore-0.3.0/examples/evm/"+fname
                    os.rename(m.workspace,newName)

                    # newName = m.workspace

                    file_name = newName +'/'+ '.state_id'
                    with open(file_name,'r') as f1:
                        lines=f1.readlines()
                        state_id = lines[0]
                        # print(state_id)      
                    return newName,True,state_id
                        # break
            else:
                 continue                        
        else:
             continue
    
    return m.workspace,False,0
            





if __name__ == "__main__":

    if len(sys.argv) != 4:
        print("python tool.py filename contract_name")
        sys.exit(-1)

    filename = sys.argv[1]
    contract_Name = sys.argv[2]
    function_Name = sys.argv[3]
    # fname = ''
    # workspace = Workspace("mem:")

    lib_con_func = []
    lib_func_list = []

    result_csv = 'result_tool_reentrancy.csv'

    start = time.time()
    dir,isbug,state_count = d_execute(filename,contract_Name,function_Name)

    end = time.time()
    ttime = end-start

    print(dir,isbug,state_count,ttime)


