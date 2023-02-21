#!/usr/bin/env python

# EVM disassembler
from manticore.platforms.evm import *
from manticore.core.smtlib import *
from manticore.core.smtlib.visitors import *
from manticore.utils import log
from manticore.platforms import evm
from manticore.ethereum import ManticoreEVM
# log.set_verbosity(9)
config.out_of_gas = 1


def printi(instruction):
    print(f"Instruction: {instruction}")
    print(f"\tdescription: {instruction.description}")
    print(f"\tgroup: {instruction.group}")
    print(f"\taddress: {instruction.offset}")
    print(f"\tsize: {instruction.size}")
    print(f"\thas_operand: {instruction.has_operand}")
    print(f"\toperand_size: {instruction.operand_size}")
    print(f"\toperand: {instruction.operand}")
    print(f"\tsemantics: {instruction.semantics}")
    print(f"\tpops: {instruction.pops}")
    print(f"\tpushes:", instruction.pushes)
    print(f"\tbytes: 0x{instruction.bytes.hex()}")
    print(f"\twrites to stack: {instruction.writes_to_stack}")
    print(f"\treads from stack: {instruction.reads_from_stack}")
    print(f"\twrites to memory: {instruction.writes_to_memory}")
    print(f"\treads from memory: {instruction.reads_from_memory}")
    print(f"\twrites to storage: {instruction.writes_to_storage}")
    print(f"\treads from storage: {instruction.reads_from_storage}")
    print(f"\tis terminator {instruction.is_terminator}")


constraints = ConstraintSet()
m = ManticoreEVM()

source_code = """
    contract Storage_test {

        bool public istrue;
        uint8 public testAmount;

        function SetAmount(uint8 _val) public {
            testAmount = _val;
        }

    }
"""


code = EVMAsm.assemble(
    """
        PUSH1 0x60
        PUSH1 0x40
        MSTORE
        PUSH1 0x0
        DUP1
        PUSH1 0x14
        PUSH2 0x100
        EXP
        DUP2
        SLOAD
        DUP2
        PUSH1 0xff
        MUL
        NOT
        AND
        SWAP1
        DUP4
        ISZERO
        ISZERO
        MUL
        OR
        SWAP1
        SSTORE
        POP
        CALLVALUE
        ISZERO
        PUSH2 0x29
        JUMPI
"""
)


data = constraints.new_array(index_bits=256, name="array")
# data = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


class callbacks:
    initial_stack = []

    def will_execute_instruction(self, pc, instr):
        for i in range(len(evm.stack), instr.pops):
            e = constraints.new_bitvec(256, name=f"stack_{len(self.initial_stack)}")
            self.initial_stack.append(e)
            evm.stack.insert(0, e)


class DummyWorld:
    def __init__(self, constraints):
        self.balances = constraints.new_array(index_bits=256, value_bits=256, name="balances")
        self.storage = constraints.new_array(index_bits=256, value_bits=256, name="storage")
        self.origin = constraints.new_bitvec(256, name="origin")
        self.price = constraints.new_bitvec(256, name="price")
        self.timestamp = constraints.new_bitvec(256, name="timestamp")
        self.coinbase = constraints.new_bitvec(256, name="coinbase")
        self.gaslimit = constraints.new_bitvec(256, name="gaslimit")
        self.difficulty = constraints.new_bitvec(256, name="difficulty")
        self.number = constraints.new_bitvec(256, name="number")

    def get_balance(self, address):
        return self.balances[address]

    def tx_origin(self):
        return self.origin

    def tx_gasprice(self):
        return self.price

    def block_coinbase(self):
        return self.coinbase

    def block_timestamp(self):
        return self.timestamp

    def block_number(self):
        return self.number

    def block_difficulty(self):
        return self.difficulty

    def block_gaslimit(self):
        return self.gaslimit

    def get_storage_data(self, address, offset):
        # This works on a single account address
        return self.storage[offset]

    def set_storage_data(self, address, offset, value):
        self.storage[offset] = value

    def log(self, address, topics, memlog):
        pass

    def send_funds(self, address, recipient, value):
        orig = self.balances[address] - value
        dest = self.balances[recipient] + value
        self.balances[address] = orig
        self.balances[recipient] = dest



caller = constraints.new_bitvec(256, name="caller")
value = constraints.new_bitvec(256, name="value")

# world = DummyWorld(constraints)
# callbacks = callbacks()

# constraints = ConstraintSet()
# make the ethereum world state
world = evm.EVMWorld(constraints)
callbacks = callbacks()

# world.create_account(address=0xF572E5295C57F15886F9B263E2F6D2D6C7B5EC6,balance=100000000000000000000000,code=EVMAsm.assemble("PUSH1 0x5b\nPUSH1 0x1\nJUMP"),)

asm_acc1 = """  CALLER
                PUSH1 0x0
                SSTORE
                ADDRESS
                PUSH1 0x1
                SSTORE
                CALLVALUE
                PUSH1 0x2
                SSTORE
                STOP
            """
# delegatecall(gas, address, in_offset, in_size, out_offset, out_size)
asm_acc2 = """  PUSH1 0x0
                PUSH2 0X0
                PUSH1 0x0
                PUSH2 0X0
                PUSH32 0x111111111111111111111111111111111111111
                PUSH32 0x100000
                CALL
                STOP
    """
asm_acc3 = """  PUSH1 0x0
                PUSH2 0X0
                PUSH1 0x0
                PUSH2 0X0
                PUSH32 0x111111111111111111111111111111111111111
                PUSH32 0x100000
                DELEGATECALL
                STOP
    """


world.create_account(address=0x111111111111111111111111111111111111111, code=EVMAsm.assemble(asm_acc1))
world.create_account(address=0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,balance=100000000000000000000000,code=EVMAsm.assemble(asm_acc1),)
world.create_account(address=0x222222222222222222222222222222222222222, code=EVMAsm.assemble(asm_acc2))
world.create_account(address=0x333333333333333333333333333333333333333, code=EVMAsm.assemble(asm_acc3))

# evm = world.current_vm
# evm = EVM(constraints, 0x41424344454647484950, data, caller, value, code, world=world, gas=1000000)
# code = 0x608060405260043610610057576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680637f698c291461005c578063a78db2901461008d578063f46eab06146100bd575b600080fd5b34801561006857600080fd5b506100716100ec565b604051808260ff1660ff16815260200191505060405180910390f35b34801561009957600080fd5b506100bb600480360381019080803560ff1690602001909291905050506100ff565b005b3480156100c957600080fd5b506100d261011d565b604051808215151515815260200191505060405180910390f35b600060019054906101000a900460ff1681565b80600060016101000a81548160ff021916908360ff16021790555050565b6000809054906101000a900460ff16815600a165627a7a723058204ed60a79a185eeb78751b1e17151293109d9d2acd282f64be41255082282b1290029
evm = EVM(constraints,0x222222222222222222222222222222222222222, data, 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa, value, EVMAsm.assemble(asm_acc1), world=world, gas=1000000)
evm.subscribe("will_execute_instruction", callbacks.will_execute_instruction)

print("CODE:")
while not issymbolic(evm.pc):
    print(f"\t {evm.pc} {evm.instruction}")
    try:
        evm.execute()
    except EndTx as e:
        print(type(e))
        break

# print translate_to_smtlib(arithmetic_simplifier(evm.stack[0]))   get_storage(address)
print(f"STORAGE1 = {translate_to_smtlib(world.get_storage(0x111111111111111111111111111111111111111),use_bindings=False)}")
print(f"STORAGE2 = {translate_to_smtlib(world.get_storage(0x222222222222222222222222222222222222222),use_bindings=False)}")
print(f"STORAGE3 = {translate_to_smtlib(world.get_storage(0x333333333333333333333333333333333333333),use_bindings=False)}")
# print(f"STORAGE = {translate_to_smtlib(world.storage)}")
for sid,sval in world.get_storage_items(0x222222222222222222222222222222222222222):
     print(f"STORAGE_id = {translate_to_smtlib(sid)},STORAGE_value = {translate_to_smtlib(sval)} ")
print(f"MEM = {translate_to_smtlib(evm.memory)}")


for i in range(len(callbacks.initial_stack)):
    print(f"STACK[{i}] = {translate_to_smtlib(callbacks.initial_stack[i])}")
print("CONSTRAINTS:")
print(constraints)

# print(f"PC: {evm.pc} {solver.get_all_values(constraints, evm.pc, maxcnt=3, silent=True)}")
# print(f"PC: {translate_to_smtlib(evm.pc)} {solver.get_all_values(constraints, evm.pc, maxcnt=3, silent=True)}")