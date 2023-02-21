from manticore.core.plugin import Plugin
from manticore.core.smtlib.visitors import simplify
import hashlib
import logging
from manticore.core.workspace import *
from contextlib import contextmanager
from manticore.core.smtlib.operators import OR, NOT, AND
from manticore.core.smtlib import ConstraintSet, operators, Constant, simplify, istainted
from manticore.core.smtlib.expression import issymbolic, taint_with, get_taints
# from manticore.utils.helpers import istainted, issymbolic, taint_with, get_taints
from manticore.core.plugin import Plugin
from manticore.ethereum import (ManticoreEVM,Detector,ABI)
from manticore.core.smtlib import Operators, to_constant
import pyevmasm as EVMAsm
import sys
import time
from binascii import unhexlify, hexlify
from manticore.ethereum import (ManticoreEVM,DetectInvalid,DetectIntegerOverflow,DetectReentrancyAdvanced,)
from manticore.ethereum.plugins import (FilterFunctions,SkipRevertBasicBlocks,)
from contract_count import extract_info
from pyevmasm import instruction_tables, disassemble_hex, disassemble_all, assemble_hex
import binascii
from evm_cfg_builder.cfg import CFG
from explore_functions import searcher

################ Script #######################

class DetectSuicidal(Detector):
    # ARGUMENT = "suicidal"
    # HELP = "Reachable selfdestruct instructions"
    # IMPACT = DetectorClassification.MEDIUM
    # CONFIDENCE = DetectorClassification.HIGH

    def will_evm_execute_instruction_callback(self, state, instruction, arguments):
        if instruction.semantics == "SELFDESTRUCT":
            self.add_finding_here(state, "Reachable SELFDESTRUCT")

class DetectReentrancySimple(Detector):
    """
    Simple detector for reentrancy bugs.
    Alert if contract changes the state of storage (does a write) after a call with >2300 gas to a user controlled/symbolic
    external address or the msg.sender address.
    """
    @property
    def _context_key(self):
        return f"{self.name}.call_locations"

    def will_open_transaction_callback(self, state, tx):
        if tx.is_human:
            state.context[self._context_key] = []

    def will_evm_execute_instruction_callback(self, state, instruction, arguments):
        if instruction.semantics == "CALL":
            gas = arguments[0]
            dest_address = arguments[1]
            msg_sender = state.platform.current_vm.caller
            pc = state.platform.current_vm.pc

            is_enough_gas = Operators.UGT(gas, 2300)
            if not state.can_be_true(is_enough_gas):
                return

            # flag any external call that's going to a symbolic/user controlled address, or that's going
            # concretely to the sender's address
            if issymbolic(dest_address) or msg_sender == dest_address:
                state.context.get(self._context_key, []).append((pc, is_enough_gas))

    def did_evm_write_storage_callback(self, state, address, offset, value):
        locs = state.context.get(self._context_key, [])

        # if we're here and locs has stuff in it. by definition this state has
        # encountered a dangerous call and is now at a write.
        for callpc, gas_constraint in locs:
            addr = state.platform.current_vm.address
            at_init = state.platform.current_transaction.sort == "CREATE"
            self.add_finding(
                state,
                addr,
                callpc,
                "Potential reentrancy vulnerability",
                at_init,
                constraint=gas_constraint,
            )


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

class SensitiveStorageCFG(Detector):
    
    def __init__(self, Jump_map=None, **kwargs):
        super().__init__(**kwargs)
        # TODO Check addresses are normal accounts. Heuristics implemented here
        # assume target addresses wont execute code. i.e. won't detect a Reentrancy
        # attack in progess but only a potential attack
        self._Jump_loc = list(Jump_map.keys())
        self._JumpDest_loc = Jump_map


    @staticmethod
    def _signed_sub_overflow(state, a, b):
        sub = Operators.SEXTEND(a, 256, 512) - Operators.SEXTEND(b, 256, 512)
        cond = Operators.OR(sub < -(1 << 255), sub >= (1 << 255))
        return cond

    @staticmethod
    def _signed_add_overflow(state, a, b):
        add = Operators.SEXTEND(a, 256, 512) + Operators.SEXTEND(b, 256, 512)
        cond = Operators.OR(add < -(1 << 255), add >= (1 << 255))
        return cond

    @staticmethod
    def _unsigned_sub_overflow(state, a, b):
        cond = Operators.UGT(b, a)
        return cond

    @staticmethod
    def _unsigned_add_overflow(state, a, b):
        add = Operators.ZEXTEND(a, 512) + Operators.ZEXTEND(b, 512)
        cond = Operators.UGE(add, 1 << 256)
        return cond

    @staticmethod
    def _signed_mul_overflow(state, a, b):
        mul = Operators.SEXTEND(a, 256, 512) * Operators.SEXTEND(b, 256, 512)
        cond = Operators.OR(mul < -(1 << 255), mul >= (1 << 255))
        return cond

    @staticmethod
    def _unsigned_mul_overflow(state, a, b):
        mul = Operators.SEXTEND(a, 256, 512) * Operators.SEXTEND(b, 256, 512)
        cond = Operators.UGE(mul, 1 << 256)
        return cond

    def _check_finding(self, state, what):
        if istainted(what, "SIGNED"):
            for taint in get_taints(what, "IOS_.*"):
                address, pc, finding, at_init, condition = self._get_location(state, taint[4:])
                if state.can_be_true(condition):
                    self.add_finding(state, address, pc, finding, at_init, condition)
        else:
            for taint in get_taints(what, "IOU_.*"):
                address, pc, finding, at_init, condition = self._get_location(state, taint[4:])
                if state.can_be_true(condition):
                    self.add_finding(state, address, pc, finding, at_init, condition)


    def will_evm_execute_instruction_callback(self, state, instruction, arguments):
        world = state.platform
        vm = state.platform.current_vm
        mnemonic = instruction.semantics
        ios = False
        iou = False
        if state.platform.current_transaction.sort != "CREATE":

            if instruction.semantics == "JUMPI" :
                if instruction.pc in self._Jump_loc:
                    print("跳转到块",hex(self._JumpDest_loc[instruction.pc]))
                    world.current_vm.pc = self._JumpDest_loc[instruction.pc]
            if instruction.semantics == "SELFDESTRUCT":
                self.add_finding_here(state, "Reachable SELFDESTRUCT11111111")
            
            # if instruction.semantics == "ADD":
            #     self.add_finding_here(state, "Reachable overflow")
    def did_evm_execute_instruction_callback(self, state, instruction, arguments, result):
        vm = state.platform.current_vm
        mnemonic = instruction.semantics
        ios = False
        iou = False

        if mnemonic == "ADD":
            ios = self._signed_add_overflow(state, *arguments)
            iou = self._unsigned_add_overflow(state, *arguments)
        elif mnemonic == "MUL":
            ios = self._signed_mul_overflow(state, *arguments)
            iou = self._unsigned_mul_overflow(state, *arguments)
        elif mnemonic == "SUB":
            ios = self._signed_sub_overflow(state, *arguments)
            iou = self._unsigned_sub_overflow(state, *arguments)
        elif mnemonic == "SSTORE":
            # If an overflowded value is stored in the storage then it is a finding
            # Todo: save this in a stack and only do the check if this does not
            #  revert/rollback
            where, what = arguments
            self._check_finding(state, what)
        elif mnemonic == "RETURN":
            world = state.platform
            if world.current_transaction.is_human:
                # If an overflowded value is returned to a human
                offset, size = arguments
                data = world.current_vm.read_buffer(offset, size)
                self._check_finding(state, data)

        if mnemonic in ("SLT", "SGT", "SDIV", "SMOD"):
            result = taint_with(result, "SIGNED")
        if mnemonic in ("ADD", "SUB", "MUL"):
            id_val = self._save_current_location(
                state, "Signed integer overflow at %s instruction" % mnemonic, ios
            )
            result = taint_with(result, "IOS_{:s}".format(id_val))

            id_val = self._save_current_location(
                state, "Unsigned integer overflow at %s instruction" % mnemonic, iou
            )
            result = taint_with(result, "IOU_{:s}".format(id_val))

        if mnemonic in ("SLT", "SGT", "SDIV", "SMOD", "ADD", "SUB", "MUL"):
            vm.change_last_result(result)



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

    def will_evm_execute_instruction_callback(self, state, instruction, arguments):
        world = state.platform
        if state.platform.current_transaction.sort != "CREATE":
            jupm_l = 0
            if instruction.semantics == "CALL":
                dest_address = arguments[1]
                sent_value = arguments[2]
                msg_sender = state.platform.current_vm.caller

                            # world = state.platform
                curr_tx = world.current_transaction
                d = curr_tx.data[:4]
                d = state.solve_one(d)
                s_value = state.solve_one(sent_value)
                print(s_value,d)
                msg = "ether leak" if state.can_be_true(sent_value != 0) else "external call"

                if issymbolic(dest_address):
                    # We assume dest_address is symbolic because it came from symbolic tx data (user input argument)
                    if state.can_be_true(msg_sender == dest_address):
                        self.add_finding_here(
                            state,
                            f"Reachable {msg} to sender via argument",
                            constraint=msg_sender == dest_address,
                        )
                else:
                    if msg_sender == dest_address:
                        self.add_finding_here(state, f"Reachable {msg} to sender")

            if instruction.semantics == "PUSH" and instruction.operand_size == 4:

                if hex(arguments[0]) in self._Lib_function:
                # if hex(arguments[0]) == self._Lib_function:
                    print("arguments[0]:",hex(arguments[0]))
                    # print("jumpi位置2：",world.current_vm.pc + instruction.size)
                    # if the bb after the jumpi ends ina JUMPI
                    # pc1 = self._is_revert_bb1(state, world.current_vm.pc + instruction.size)
                    # print("push2的地址：：",int(pc1,16))
                    for tup in self._Dest_loc:
                        if instruction.pc == tup[0]:
                            jupm_l = tup[1]

                    # if pc1 != 0:
                        # world.current_vm.pc = int(pc1,16)
                    print(jupm_l)

                    # 根据字节码的特点，需要将栈内的元素推出
                    world.current_vm.pc = jupm_l+3
                    # world.current_vm.pc = 1072    #141   #0x8d
            
            # if instruction.semantics == "SELFDESTRUCT":
            #     self.add_finding_here(state, "Reachable SELFDESTRUCT000000")

class SkipLibCall1(Detector):

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


    def will_evm_execute_instruction_callback(self, state, instruction, arguments):
        world = state.platform
        m = ManticoreEVM()

        if state.platform.current_transaction.sort != "CREATE":

            if instruction.semantics == "CALL":
                print("执行call的分析")
                dest_address = arguments[1]
                sent_value = arguments[2]
                msg_sender = state.platform.current_vm.caller
                print("执行call的分析")
                print("call arguement",arguments)
                curr_tx = world.current_transaction
                d = curr_tx.data[:4]
                # d = state.solve_one(d)
                # s_value = state.solve_one(sent_value)
                # print(s_value,d)
                # msg = "ether leak" if state.can_be_true(sent_value != 0) else "external call"
                # msg = "ether leak"
                msg = "ether leak" if issymbolic(sent_value) else "external call"
                # if issymbolic(dest_address):
                    
                    
                    
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
                
                # calldata = world.current_vm.read_buffer(arguments[3], arguments[4])
                # print(calldata)
                # world.start_transaction('CALL',arguments[1],data=calldata,caller=msg_sender,value=arguments[2],gas=30000)
                # (caller_migrated,address_migrated,value_migrated,data_migrated,gas_migrated,price_migrated) = m._migrate_tx_expressions(state, msg_sender, dest_address, sent_value, calldata,23000,1)
                # world.start_transaction(sort='CALL',address=address_migrated,price=price_migrated,data=data_migrated,caller=caller_migrated,value=value_migrated,gas=gas_migrated)
                # world.current_vm.pc = self._Dest_loc
                # world.current_vm.pc = world.current_vm.pc + 1
                world.current_vm._pop()
                world.current_vm._pop()
                world.current_vm._pop()
                world.current_vm._pop()
                world.current_vm._pop()
                world.current_vm._pop()
                world.current_vm._pop()
                world.current_vm._push(1)
                world.current_vm.pc = world.current_vm.pc + 1
                
        
            if instruction.semantics == "CALLDATACOPY":
                print("进入库函数！！！")

            # if instruction.semantics == "SELFDESTRUCT":
            #     self.add_finding_here(state, "Reachable SELFDESTRUCT")
            
            # if instruction.semantics == "ADD":
            #     self.add_finding_here(state, "Reachable overflow")

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

def search_cut_loc_mid(runtimecode):

    instruction_table = instruction_tables['istanbul']
    try:
        instrs = list(disassemble_all(binascii.unhexlify(runtimecode)))
    except: #binascii.Error: Odd-length string
        initcode = initcode+'0'
        instrs = list(disassemble_all(binascii.unhexlify(runtimecode)))

    disassemble_txt = 'disassemble.txt'
    Note=open(disassemble_txt,mode='w')
    Note.write(str(instrs)+'\n') 
    for ins in instrs:
        Note.write(str(ins)+'\n') 

    lib_func_loc_mid = []
    is_start = False
    is_front = False
    func_loc = 0
    for l in instrs:
        if l.semantics == "PUSH" and l.operand_size == 4 and hex(l.operand) == "0x4c2f04a4" :
            is_start = True
            print("打开开关")
            func_loc = l.pc
        # Instruction(0x14, 'EQ', 0, 2, 1, 3, 'Equality comparision.', None, 0)
        if l.name  == 'ISZERO' and l_last.name  == 'CALL' and is_start :
            # print(hex(i-1))
            is_front = True
        
        if l.semantics == "PUSH" and l.operand_size == 2 and is_front :
            # print(instrs.index(l))
            # instrs.index(l)+3 表示在ISZERO后的第三个指令的PUSH指令，其对应的元素为跳转目标地址
            # print(hex(l_j.operand))
            # print(l.operand)
            tup = [func_loc,l.operand]
            print(tup)
            lib_func_loc_mid.append(tup)
            l_last = l
            is_start = False
            is_front = False
            print("关闭开关")
        else:
            l_last = l

    # print(lib_func_loc_mid)

    return lib_func_loc_mid


def search_cut_return_use(runtimecode,function_name,lib_con_func):
    
    lib_func_loc_mid = []
    is_start = False
    is_front = False
    func_loc = 0
    jump_dest = 0

    ##############################

    fun_return = False
    return_use = False
    
    instruction_table = instruction_tables['istanbul']
    cfg = CFG(runtimecode)

    for function in sorted(cfg.functions, key=lambda x: x.start_addr):
        print('Function {}'.format(function.name))
        # if function.name == function_name:
        if function.name == "0x703d59b0":
            for basic_block in sorted(function.basic_blocks, key=lambda x:x.start.pc):
                for l in basic_block.instructions:
                    print('\t\t- {}'.format(l.name))
                    if l.semantics == "PUSH" and l.operand_size == 4 and hex(l.operand) in lib_con_func[1][1] :
                        is_start = True
                        print("打开开关")
                        func_loc = l.pc
                    # Instruction(0x14, 'EQ', 0, 2, 1, 3, 'Equality comparision.', None, 0)
                    if l.name  == 'ISZERO' and l_last.name  == 'CALL' and is_start :
                        # print(hex(i-1))
                        is_front = True
                    
                    if l.semantics == "PUSH" and l.operand_size == 2 and is_front :
                        # print(instrs.index(l))
                        # instrs.index(l)+3 表示在ISZERO后的第三个指令的PUSH指令，其对应的元素为跳转目标地址
                        # print(hex(l_j.operand))
                        # print(l.operand)
                        tup = [func_loc,l.operand]
                        print(tup)
                        lib_func_loc_mid.append(tup)
                        jump_dest = hex(l.operand)
                        print("跳转目标：",jump_dest)
                        l_last = l
                        is_start = False
                        is_front = False
                        print("关闭开关")
                    else:
                        l_last = l
                        
                if jump_dest != 0:
                    for outgoing_bb in sorted(basic_block.outgoing_basic_blocks(function.key), key=lambda x:x.start.pc):
                        if(hex(outgoing_bb.start.pc) == jump_dest):
                            print("找到该块")
                            print("h后继块列表类型",len(outgoing_bb.outgoing_basic_blocks(function.key)))
                            if outgoing_bb.outgoing_basic_blocks(function.key) :
                                for second_outgoing_bb in sorted(outgoing_bb.outgoing_basic_blocks(function.key), key=lambda x:x.start.pc):
                                    for ins in second_outgoing_bb.instructions:
                                        if ins.name == "MLOAD":
                                            fun_return = True
                                        if ins.name == "SSTORE":
                                            return_use = True
                                
                                
    print("是否有返回值,返回值是否使用",fun_return,return_use )

    return fun_return,return_use








def d_execute(filename,contractname,function_Name):


    with open(filename) as f:
        source_code = f.read()

    m = ManticoreEVM()
    m.verbosity(0)
    isMul= False
    fun_return = True
    lib_con_func = []
    lib_func_list = []
    lib_jump_loc = []
    fun_return = False
    return_use = False
    jump_map = {}

    isMul,lib_con_func,lib_func_list = extract_info(isMul,filename,contractname,lib_func_list)
    compile_result  = m._compile(source_code,contractname)
    #  (name, source_code, bytecode, runtime, srcmap, srcmap_runtime, hashes, abi, warnings)
    initcode = compile_result[2]
    runtimecode = compile_result[3].hex()
    lib_jump_loc = search_cut_loc_mid(runtimecode)
    fun_return,_ = search_cut_return_use(runtimecode,function_Name,lib_con_func)
    jump_map = searcher(runtimecode)
    
    m.register_plugin(SensitiveStorageCFG(Jump_map=jump_map))
    print("jump_map",jump_map)
    
    if fun_return:
        l = SkipLibCall1()
        m.register_plugin(SkipLibCall1(Lib_function=lib_func_list,Dest_loc=lib_jump_loc))
        p= DetectReentrancyAdvanced()
        # m.register_detector(p)
    else :
        p = DetectReentrancyAdvanced()
        l = SkipLibCall()
        # m.register_detector(p)
        m.register_plugin(SkipLibCall(Lib_function=lib_func_list,Dest_loc=lib_jump_loc))
    
    l = DetectSuicidal()
    m.register_plugin(DetectSuicidal())
    Int = DetectIntegerOverflow()
    m.register_plugin(DetectIntegerOverflow())

        
    
    
    # p= DetectReentrancySimple()
    # p = DetectReentrancyAdvanced()
    # l = DetectExternalCallAndLeak()
    
    # m.register_detector(p)
    # m.register_detector(l)
    m.register_plugin(StopAtDepth())

    
    # m.verbosity(0)
    # m.register_plugin(KeepOnlyIfStorageChanges())
    # m.register_plugin(SkipRevertBasicBlocks(Lib_Address=contract_account.address))
    # m.register_plugin(SkipRevertBasicBlocks())
    # m.register_plugin(SkipLibCall(Lib_function=lib_func_list,Dest_loc=lib_jump_loc))
    # Dest_loc： 8d d0 f0 107 134 154
    
    symbolic_value = m.make_symbolic_value()
    # m.multi_tx_analysis(filename, contract_name=contractname, args=symbolic_value,tx_limit=2,tx_preconstrain=True,tx_use_coverage=True,tx_send_ether=True,libraries=[("LogFile", contract_account.address)])
    m.multi_tx_analysis1(initcode, contract_name=contractname, args=symbolic_value,tx_limit=2,tx_preconstrain=False,tx_use_coverage=True,tx_send_ether=True)



    # for state in m.all_states:
    for state in m.ready_states:
        f_value = []
        l_l = 0
        l_p = []
        is_exis = False
        findings = l.get_findings(state)
        # findings1 = p.get_findings(state)
        print("lllll",findings)
        # print("ppppp",findings1)

        info_l = "Reachable ether leak to sender"
        info_p = "Reentrancy multi-million ether bug"
        info_p1 = "Potential reentrancy vulnerability"
        info_suicidal = "Reachable SELFDESTRUCT"
        
        # for item in findings:
        #     v = item[2]
        #     if v == info_l:
        #         l_l = item[1]

        # for item in findings1:
        #     v = item[2]
        #     if v == info_p or v == info_p1:
        #         l_p.append(item[1])
        # if l_l in l_p:
        #     is_exis = True
            
        # for item in findings:
        #     v = item[2]
        #     if v == info_suicidal:
        #         is_exis = True
        if findings:
            is_exis = True
            
        # is_exis = True


    
   # ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
        if is_exis:
            if len(state.platform.transactions) > 1:
                reentry_string = ABI.function_selector(function_Name)
                d = state.platform.transactions[-1].data
                funcid, dynargs = ABI.deserialize(type_spec=function_Name, data=d)
                funcd = state.solve_one(funcid)
                print(funcd,reentry_string,findings)
                if m.generate_testcase(state, "maybe reentrancy?", only_if=funcd == reentry_string):
                    expected_files = {"user_00000000." + ext for ext in ("summary", "tx.json", "tx", "trace","findings")}
                    print(funcd,reentry_string,findings)
                    print("Bug found! see {}".format(m.workspace))
                    fname = filename +'_'+ contractname
                    newName="/home/wangzexu/manticore_pro/manticore-0.3.0/examples/dectors_test/"+fname
                    os.rename(m.workspace,newName)
                    file_name = newName +'/'+ '.state_id'
                    with open(file_name,'r') as f1:
                        lines=f1.readlines()
                        state_id = lines[0]
                        # print(state_id)      
                    return newName,True,state_id
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


# python mult_detectors.py ethereum/contracts/detectors/selfdestruct_mult.sol Test2 "bug_intou_inter(address,uint256)"
# python mult_detectors.py ethereum/contracts/detectors/selfdestruct_true_pos.sol DetectThis "kill()"