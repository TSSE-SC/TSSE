import sys
from evm_cfg_builder.cfg import CFG






def searcher(runtime_bytecode):
    jump_map = {}
    Halt_BLOCK_END = ["STOP","REVERT","INVALID",]
    cfg = CFG(runtime_bytecode)
    for function in sorted(cfg.functions, key=lambda x: x.start_addr):
        # print(f"Function {function.name}")
        
        # if function.name == "Collect(uint256)":
        # if function.name == "Deposit()":
        # print("\n\tBasic Blocks:")
        jump_map = {}
        dest_pc = 0
        for basic_block in sorted(function.basic_blocks, key=lambda x: x.start.pc):
            # Each basic block has a start and end instruction
            # instructions are pyevmasm.Instruction objects
            # print(f"\t- @{hex(basic_block.start.pc)}-{hex(basic_block.end.pc)}")
            list_outgoing = []
            list_outgoing1 = []
            # print("\t\tOutgoing basic_block:")
            for outgoing_bb in sorted(basic_block.outgoing_basic_blocks(function.key), key=lambda x: x.start.pc):
                out_bb_weight = 0
                halt_block = False
                # print(f"\t\t-后继块：{outgoing_bb}")
                if outgoing_bb.end.name in Halt_BLOCK_END:
                    halt_block = True
                out_bb_weight = count_w(outgoing_bb,out_bb_weight)

                if halt_block == False:
                    list_outgoing.append([outgoing_bb.start.pc,out_bb_weight,outgoing_bb])
                    
                # print("\t\t权重1:",out_bb_weight,halt_block)

                # print("\t\tall_outgoing:",outgoing_bb.all_outgoing_basic_blocks)
                for star_pc,weight,first_outgoing_bb in list_outgoing: 
                    if len(first_outgoing_bb.all_outgoing_basic_blocks) != 0:   
                        out_bb_weight2 = weight   
                        for second_outgoing_bb in sorted(first_outgoing_bb.outgoing_basic_blocks(function.key), key=lambda x: x.start.pc):   
                            out_bb_weight2 = count_w(second_outgoing_bb,out_bb_weight2)
                            list_outgoing1.append([star_pc,out_bb_weight2,first_outgoing_bb])
            #     print("\t\t权重2:",out_bb_weight2,halt_block)
            # print("\t\tlist_outgoing:",list_outgoing)
            # print("\t\tlist_outgoing1:",list_outgoing1)
            if len(list_outgoing) > 0:
                dest_pc = search_max(list_outgoing,list_outgoing1)
                # print("\t\t下一个最大跳转块:",dest_pc )
                jump_map[basic_block.end.pc] = dest_pc
    print("jump_map",jump_map)   
    return(jump_map)
            


def count_w(out_bb,out_bb_weight):
    # out_bb_weight = 0
    for ins in out_bb.instructions:
        if ins.name == "SLOAD":
            out_bb_weight = out_bb_weight + 5
        if ins.name == "SSTORE":
            out_bb_weight = out_bb_weight + 10
        # if ins.name == "JUMPI":
        #     out_bb_weight = out_bb_weight + 1
            
    return out_bb_weight
    
def search_max(list_outgoing,list_outgoing1):
    if len(list_outgoing) == 1:
        return list_outgoing[0][0]
    
    max_first = list_outgoing[0][1]
    max_bb = list_outgoing[0]
    min_first = list_outgoing[0][1]
    min_bb = list_outgoing[0]
    max_start_pc = list_outgoing[0][0]
    for pc,weight,bb in list_outgoing:
        if max_first < weight:
            max_first = weight
            max_bb = bb
            max_start_pc = pc
        if min_first > weight:
            min_first = weight
            min_bb = bb
    if max_first != min_first:
        return max_start_pc
    else:
        max_second = list_outgoing1[0][1]
        max_bb2 = list_outgoing1[0]
        min_second = list_outgoing1[0][1]
        min_bb2 = list_outgoing1[0]
        for pc,weight,bb in list_outgoing1:
            if max_second < weight:
                max_second = weight
                max_bb2 = bb
                max_start_pc = pc
            if min_second > weight:
                min_second = weight
                min_bb2 = bb
        return max_start_pc
                    

if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage python explore_functions.py contract.evm")
        sys.exit(-1)

    with open(sys.argv[1], encoding="utf-8") as f:
        runtime_bytecode = f.read()

    Halt_BLOCK_END = ["STOP","REVERT","INVALID",]
    jump_map = {}
    jump_map = searcher(runtime_bytecode)
    a = 445
    print(jump_map[a])
    print(jump_map)
    print(list(jump_map.keys()))