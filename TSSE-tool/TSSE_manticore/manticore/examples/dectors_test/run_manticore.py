import sys
import time
import json
from itertools import chain
from manticore.ethereum import (ManticoreEVM,Detector,ABI)
from manticore.ethereum import ManticoreEVM
from manticore.ethereum.detectors import (DetectEnvInstruction,DetectInvalid,DetectReentrancySimple,DetectReentrancyAdvanced,DetectIntegerOverflow,DetectUnusedRetVal)
from manticore.ethereum.plugins import (FilterFunctions,VerboseTrace)
from manticore.utils import config
from manticore.utils.log import RunningTime
from func_timeout import func_set_timeout
from manticore.core.smtlib.expression import issymbolic, taint_with, get_taints
from contract_count import extract_info,extract_info1
from pyevmasm import instruction_tables, disassemble_hex, disassemble_all, assemble_hex
import binascii
from evm_cfg_builder.cfg import CFG
from explore_functions import searcher



class DetectSuicidal(Detector):

    def will_evm_execute_instruction_callback(self, state, instruction, arguments):
        if instruction.semantics == "SELFDESTRUCT":
            self.add_finding_here(state, "Reachable SELFDESTRUCT")
class DetectTimeSTAMP(Detector):

    def will_evm_execute_instruction_callback(self, state, instruction, arguments):
        if instruction.semantics == "TIMESTAMP":
            self.add_finding_here(state, "USING TIMESTAMP")
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
                # msg = "ether leak" if issymbolic(sent_value) else "external call"
                # if issymbolic(dest_address):
                # self.add_finding_here(state,f"Reachable {msg} to sender via argument",constraint=msg_sender == dest_address,)
                
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


class SkipLibCall2(Detector):

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
            # print("inst.name",inst.name)
            if inst.is_terminator:
                # print("基本块边界：",inst.pc,inst.name)
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
            if instruction.semantics == "PUSH" and instruction.operand_size == 4:

                if hex(arguments[0]) in self._Lib_function:
                # if hex(arguments[0]) == self._Lib_function:
                    print("arguments[0]:",hex(arguments[0]))
                    world.current_vm.pc =self._Dest_loc


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

def search_cut_return_use(runtimecode,function_name,lib_con_func,lib_func_list):
    
    lib_func_loc_mid = []
    is_start = False
    is_front = False
    func_loc = 0
    jump_dest = 0
    suicidal_bb_loc = 0
                                 
    ##############################
    fun_return = False
    return_use = False
    instruction_table = instruction_tables['istanbul']
    cfg = CFG(runtimecode)
    for function in sorted(cfg.functions, key=lambda x: x.start_addr):
        print('Function {}'.format(function.name))
        # if function.name in lib_con_func:
            # print("function.name",function.name )
        # if function.name == "0x703d59b0":
        for basic_block in sorted(function.basic_blocks, key=lambda x:x.start.pc):
            for l in basic_block.instructions:
                # print('\t\t- {}'.format(l.name))
                # if l.semantics == "PUSH" and l.operand_size == 4 and hex(l.operand) in lib_func_list :
                if l.semantics == "PUSH" and l.operand_size == 4 :
                    is_start = True
                    print("打开开关")
                    print(hex(l.operand))
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
                    # print(tup)
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
                                    if ins.name == "SELFDESTRUCT":
                                        suicidal_bb_loc = second_outgoing_bb.start.pc
                                
                                
    print("sc_bb,是否有返回值,返回值是否使用",suicidal_bb_loc,fun_return,return_use )

    return suicidal_bb_loc,fun_return,return_use


def search_cut_sc_use(runtimecode,function_name,lib_con_func,lib_func_list):
    
    lib_func_loc_mid = []
    is_start = False
    is_front = False
    func_loc = 0
    jump_dest = 0
    suicidal_bb_loc = 0
                                 
    ##############################
    fun_return = False
    return_use = False
    instruction_table = instruction_tables['istanbul']
    cfg = CFG(runtimecode)
    for function in sorted(cfg.functions, key=lambda x: x.start_addr):
        print('Function {}'.format(function.name))
        for basic_block in sorted(function.basic_blocks, key=lambda x:x.start.pc):
            for l in basic_block.instructions:
                if l.name == "SELFDESTRUCT":
                    suicidal_bb_loc = basic_block.start.pc
                                
                                
    print("sc_bb",suicidal_bb_loc, )

    return suicidal_bb_loc


# TIMESTAMP
def search_cut_ts_use(runtimecode,function_name,lib_con_func,lib_func_list):
    
    lib_func_loc_mid = []
    is_start = False
    is_front = False
    func_loc = 0
    jump_dest = 0
    timestamp_bb_loc = 0
                                 
    ##############################
    fun_return = False
    return_use = False
    instruction_table = instruction_tables['istanbul']
    cfg = CFG(runtimecode)
    for function in sorted(cfg.functions, key=lambda x: x.start_addr):
        print('Function {}'.format(function.name))
        for basic_block in sorted(function.basic_blocks, key=lambda x:x.start.pc):
            for l in basic_block.instructions:
                if l.name == "TIMESTAMP":
                    timestamp_bb_loc = basic_block.start.pc
                                
                                
    print("timestamp_bb_loc",timestamp_bb_loc, )

    return timestamp_bb_loc

class SensitiveStorageCFG(Detector):
    
    def __init__(self, Jump_map=None, **kwargs):
        super().__init__(**kwargs)
        # TODO Check addresses are normal accounts. Heuristics implemented here
        # assume target addresses wont execute code. i.e. won't detect a Reentrancy
        # attack in progess but only a potential attack
        self._Jump_loc = list(Jump_map.keys())
        self._JumpDest_loc = Jump_map

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
        





MAXTX=3 # Configurable

def init_config():
    config.get_group("smt").timeout=120
    config.get_group("smt").memory=16384
    config.get_group("smt").optimize = False
    config.get_group("evm").oog = "ignore"

def create_EVM(src, name, benchmark,function_Name):
    RunningTime()
    with open(src) as f:
        source_code = f.read()
    print('Creating EVM object...')
    m = ManticoreEVM()
    
    isMul= False
    fun_return = True
    lib_con_func = []
    lib_func_list = []
    lib_jump_loc = []
    fun_return = False
    return_use = False
    jump_map = {}
    sc_bb_loc = 0
    ts_bb_loc = 0

    isMul,lib_con_func,lib_func_list = extract_info1(isMul,src,name,lib_func_list)
    compile_result  = m._compile(source_code,name)
    #  (name, source_code, bytecode, runtime, srcmap, srcmap_runtime, hashes, abi, warnings)
    initcode = compile_result[2]
    runtimecode = compile_result[3].hex()
    lib_jump_loc = search_cut_loc_mid(runtimecode)
    if lib_func_list:
        # sc_bb_loc,fun_return,_ = search_cut_return_use(runtimecode,function_Name,lib_con_func,lib_func_list)
        sc_bb_loc = search_cut_sc_use(runtimecode,function_Name,lib_con_func,lib_func_list)
        ts_bb_loc = search_cut_ts_use(runtimecode,function_Name,lib_con_func,lib_func_list)
    print("sc_bb_loc,fun_return",sc_bb_loc,fun_return)   
    jump_map = searcher(runtimecode)
    # if fun_return:
    #     l = SkipLibCall1()
    #     m.register_plugin(SkipLibCall1(Lib_function=lib_func_list,Dest_loc=lib_jump_loc))
    #     # p= DetectReentrancyAdvanced()
    #     # m.register_detector(p)
    #     # l = SkipLibCall()
    #     # # m.register_detector(p)
    #     # m.register_plugin(SkipLibCall(Lib_function=lib_func_list,Dest_loc=lib_jump_loc))
    #     # m.register_plugin(SensitiveStorageCFG(Jump_map=jump_map))
    # else :
    #     p = DetectReentrancyAdvanced()
    #     l = SkipLibCall()
    #     # m.register_detector(p)
    #     m.register_plugin(SkipLibCall(Lib_function=lib_func_list,Dest_loc=lib_jump_loc))
    
    # m.register_plugin(SensitiveStorageCFG(Jump_map=jump_map))
    if sc_bb_loc != 0:
        m.register_plugin(SkipLibCall2(Lib_function=lib_func_list,Dest_loc=sc_bb_loc))
    elif ts_bb_loc !=0:
        m.register_plugin(SkipLibCall2(Lib_function=lib_func_list,Dest_loc=ts_bb_loc))
    else:
        m.register_plugin(SkipLibCall1(Lib_function=lib_func_list,Dest_loc=lib_jump_loc))
    
    # l = SkipLibCall1()
    # m.register_plugin(SkipLibCall(Lib_function=lib_func_list,Dest_loc=lib_jump_loc))
    

    print('Registering detector modules...')
    detectors = {}
    if benchmark == "B1":
        # IB Detector
        ib = DetectIntegerOverflow()
        detectors['IntegerBug'] = ib
        m.register_detector(ib)
    elif benchmark == "B2":
        # SC Detector
        sc = DetectSuicidal()
        detectors['Suicidal'] = sc
        m.register_detector(sc)
    elif benchmark == "B3":
        # BD Detector
        bd = DetectTimeSTAMP()
        detectors['BlockstateDependency'] = bd
        m.register_detector(bd)
    elif benchmark == "B4":
        # RE Detector
        re = DetectReentrancySimple()
        detectors['Reentrancy'] = re
        m.register_detector(re)
    # elif benchmark == "B5":
    #     # RE Detector
    #     re = DetectReentrancySimple()
    #     detectors['Reentrancy'] = re
    #     m.register_detector(re)
    else:
        print('Unexpected benchmark: %s' % benchmark)
        exit(1)

    print('Adding filters...')
    # Avoid all human level tx that has no effect on the storage
    filter_nohuman_constants = FilterFunctions(regexp=r".*", depth="human", mutability="constant", include=False)
    m.register_plugin(filter_nohuman_constants)

    print('Creating accounts...')
    # user_account = m.create_account(balance=10**10)
    user_account = m.create_account(balance=10 ** 20, name="owner")
    # contract_account = m.solidity_create_contract(src, owner=user_account, contract_name=name)
    print("user_account",hex(user_account.address))
    contract_account = m.create_contract(init=initcode,owner=user_account,name=name)

    return m, detectors, user_account, contract_account,initcode

def save_tc(m, state):
    with state as temp_state:
        txlist = []
        world = temp_state.platform
        for sym_tx in world.human_transactions:
            try: # Caution: we should handle this exception and continue.
                conc_tx = sym_tx.concretize(temp_state)
            except Exception as e:
                print(e)
                print('Skip this test case')
                return
            txlist.append(conc_tx.to_dict(m))

        with open('./output/tc_%0.5f' % state._elapsed, 'w') as f:
            f.write(json.dumps(txlist))

def get_time_str(elapsed):
    s = int(elapsed)
    d = s // 86400
    s = s - (d * 86400)
    h = s // 3600
    s = s - (h * 3600)
    m = s // 60
    s = s - (m * 60)
    time_str = '%02d:%02d:%02d:%02d' % (d, h, m, s)
    return time_str

def dump_bug(state, detectors,src):
    for bug_type in detectors:
        detector = detectors[bug_type]
        for addr, pc, msg, at_init, cond in detector.get_findings(state):
            if state.can_be_true(cond):
                print('Bug Found')
                time_str = get_time_str(state._elapsed)
                bug_pc = pc - 1 if bug_type == "IntegerBug" else 0
                msg = '[%s] Found %s in %s\n' % (time_str, bug_type,src)
                print(msg)
                with open('./output/log.txt', 'a+') as f:
                    f.write(msg)

def main(timeout, src, name, benchmark,function_Name):
    print('Contract name: %s' % name)
    init_config()
    m, detectors, user_account, contract_account,initcode = create_EVM(src, name, benchmark,function_Name)

    if contract_account is None:
        print('Failed to create contract ccount')
        return

    handled_killed_states = set()
    print('Start running...')
    with m.kill_timeout(timeout=timeout):
        for _ in range(MAXTX):
            if m.is_killed():
                print('EVM object is killed, exit.')
                break
            symbolic_data = m.make_symbolic_buffer(320)
            symbolic_value = m.make_symbolic_value()
            print('Making transaction...')
            # m.transaction(caller=user_account, address=contract_account,value=symbolic_value, data=symbolic_data)
            m.multi_tx_analysis1(initcode, contract_name=name, args=symbolic_data,tx_limit=2,tx_preconstrain=False,tx_use_coverage=True,tx_send_ether=True)

            print('Start handling ready_states')
            total = m.count_ready_states()
            i = 0
            for state in m.ready_states:
                print('save_tc on state %d / %d' % (i, total))
                save_tc(m, state)
                print('dump_bug on state %d / %d' % (i, total))
                dump_bug(state, detectors,src)
                i += 1

            for state in chain(m.ready_states, m.killed_states):
                print('save_tc on state %d / %d' % (i, total))
                save_tc(m, state)
                i += 1

            print('Start handling killed_states')
            total = m.count_killed_states()
            i = 0
            for state in m.killed_states:
                if state.id not in handled_killed_states:
                    handled_killed_states.add(state.id)
                    print('save_tc on state %d / %d' % (i, total))
                    save_tc(m, state)
                    print('dump_bug on state %d / %d' % (i, total))
                    dump_bug(state, detectors,src)
                else:
                    print('Skip already handled killed state')
                i += 1


@func_set_timeout(300)
def task_detect(timeout, src, name, benchmark,function_Name):
    print('Contract name: %s' % name)
    init_config()
    m, detectors, user_account, contract_account,initcode = create_EVM(src, name, benchmark,function_Name)

    if contract_account is None:
        print('Failed to create contract ccount')
        return

    handled_killed_states = set()
    print('Start running...')
    with m.kill_timeout(timeout=timeout):
        for _ in range(MAXTX):
            if m.is_killed():
                print('EVM object is killed, exit.')
                break
            symbolic_data = m.make_symbolic_buffer(320)
            symbolic_value = m.make_symbolic_value()
            print('Making transaction...')
            # m.transaction(caller=user_account, address=contract_account,value=symbolic_value, data=symbolic_data)
            m.multi_tx_analysis1(initcode, contract_name=name, args=symbolic_data,tx_limit=2,tx_preconstrain=False,tx_use_coverage=True,tx_send_ether=True)

            print('Start handling ready_states')
            total = m.count_ready_states()
            i = 0
            for state in m.ready_states:
                print('save_tc on state %d / %d' % (i, total))
                save_tc(m, state)
                print('dump_bug on state %d / %d' % (i, total))
                dump_bug(state, detectors,src)
                i += 1

            for state in chain(m.ready_states, m.killed_states):
                print('save_tc on state %d / %d' % (i, total))
                save_tc(m, state)
                i += 1

            print('Start handling killed_states')
            total = m.count_killed_states()
            i = 0
            for state in m.killed_states:
                if state.id not in handled_killed_states:
                    handled_killed_states.add(state.id)
                    print('save_tc on state %d / %d' % (i, total))
                    save_tc(m, state)
                    print('dump_bug on state %d / %d' % (i, total))
                    dump_bug(state, detectors,src)
                else:
                    print('Skip already handled killed state')
                i += 1



if __name__ == '__main__':
    timeout = int(sys.argv[1])
    src = sys.argv[2]
    name = sys.argv[3]
    benchmark = sys.argv[4]
    function_Name = sys.argv[5]
    main(timeout, src, name, benchmark,function_Name)
