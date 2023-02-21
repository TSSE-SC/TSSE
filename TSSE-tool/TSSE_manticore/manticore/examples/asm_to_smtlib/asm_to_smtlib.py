#!/usr/bin/env python

# EVM disassembler
from manticore.platforms.evm import *
from manticore.core.smtlib import *
from manticore.core.smtlib.visitors import *
from manticore.utils import log
from manticore.platforms import evm
from manticore.ethereum import ManticoreEVM
from pyevmasm import instruction_tables, disassemble_hex, disassemble_all, assemble_hex
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


# code = EVMAsm.assemble(
#     """
#     MSTORE
# """
# )


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

print(code)


# con_code = '0x608060405234801561001057600080fd5b5061015b806100206000396000f300608060405260043610610057576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680637f698c291461005c578063a78db2901461008d578063f46eab06146100bd575b600080fd5b34801561006857600080fd5b506100716100ec565b604051808260ff1660ff16815260200191505060405180910390f35b34801561009957600080fd5b506100bb600480360381019080803560ff1690602001909291905050506100ff565b005b3480156100c957600080fd5b506100d261011d565b604051808215151515815260200191505060405180910390f35b600060019054906101000a900460ff1681565b80600060016101000a81548160ff021916908360ff16021790555050565b6000809054906101000a900460ff16815600a165627a7a723058204ed60a79a185eeb78751b1e17151293109d9d2acd282f64be41255082282b1290029'

# con_code = EVMAsm.assemble(disassemble_hex(con_code))


# asm_acc1 = EVMAsm.assemble(
#             """  CALLER
#                 PUSH1 0x0
#                 SSTORE
#                 ADDRESS
#                 PUSH1 0x1
#                 SSTORE
#                 CALLVALUE
#                 PUSH1 0x2
#                 SSTORE
#                 GASLIMIT
#                 PUSH1 0x3
#                 SSTORE
#                 PUSH1 0x2
#                 SLOAD
#                 PUSH1 0x1
#                 ADD
#                 PUSH1 0x2
#                 SSTORE
#                 PUSH1 0x2
#                 SLOAD
#                 GAS
#                 ADD
#                 PUSH1 0x2
#                 SSTORE
#                 STOP
#             """
# )


asm_acc1 =EVMAsm.assemble(
           """  CALLER
                PUSH1 0x0
                SSTORE
                ADDRESS
                PUSH1 0x1
                SSTORE
                CALLVALUE
                PUSH1 0x2
                SSTORE
                PUSH1 0x2
                SLOAD
                PUSH1 0x6
                ADD
                PUSH1 0x2
                SSTORE
                STOP
       """
)

data = constraints.new_array(index_bits=256, name="array")
# data = 0xf46eab06

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
gas = constraints.new_bitvec(256, name="gas")
world = evm.EVMWorld(constraints)
callbacks = callbacks()
# address = world.create_account(balance=balance, code=code )
address = world.create_account(address=0x111111111111111111111111111111111111111,balance=100000000000000000000000, code=asm_acc1)
caller = world.create_account(address=0x222222222222222222222222222222222222222, balance=100000000000000000000000)
# evm = world.current_vm
evm = EVM(constraints,0x111111111111111111111111111111111111111, data, caller, value, asm_acc1, world=world, gas=gas)
# evm.subscribe("will_execute_instruction", callbacks.will_execute_instruction)

print("CODE:")
while not issymbolic(evm.pc):
    print(f"\t {evm.pc} {evm.instruction}")
    # evm.execute()
    try:
        evm.execute()
    except EndTx as e:
        print(type(e))
        break
print(f"STORAGE1 = {translate_to_smtlib(world.get_storage(0x111111111111111111111111111111111111111))}")
# print(world.get_storage_items(0x111111111111111111111111111111111111111))
for sid,sval in world.get_storage_items(0x111111111111111111111111111111111111111):
     print(f"STORAGE_id = {translate_to_smtlib(sid)},STORAGE_value = {translate_to_smtlib(sval)} ")
# state.platform.get_storage_items(0x111111111111111111111111111111111111111)[0][0]
# print(f"STORAGE = {translate_to_smtlib(world.get_storage_items(0x111111111111111111111111111111111111111)[2][1])}")
print(f"MEM = {translate_to_smtlib(evm.memory)}")


for i in range(len(callbacks.initial_stack)):
    print(f"STACK[{i}] = {translate_to_smtlib(callbacks.initial_stack[i])}")
print("CONSTRAINTS:")
print(constraints)

# print(f"PC: {translate_to_smtlib(evm.pc)} {solver.get_all_values(constraints, evm.pc, maxcnt=3, silent=True)}")

