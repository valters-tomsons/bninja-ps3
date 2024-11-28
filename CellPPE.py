from binaryninja import ArchitectureHook, LowLevelILFunction, RegisterInfo

class CellPPE(ArchitectureHook):
    name = "cellbe-ppc64"
    address_size = 4
    default_int_size = 4
    instr_alignment = 4
    max_instr_length = 4
    stack_pointer = "r1"
    link_reg = "lr"
    flags = ["cr", "vscr", "fpscr", "xer"]
    regs = {
        "r0": RegisterInfo("r0", 8),
        "r1": RegisterInfo("r1", 8),
        "r2": RegisterInfo("r2", 8),
        "r3": RegisterInfo("r3", 8),
        "r4": RegisterInfo("r4", 8),
        "r5": RegisterInfo("r5", 8),
        "r6": RegisterInfo("r6", 8),
        "r7": RegisterInfo("r7", 8),
        "r8": RegisterInfo("r8", 8),
        "r9": RegisterInfo("r9", 8),
        "r10": RegisterInfo("r10", 8),
        "r11": RegisterInfo("r11", 8),
        "r12": RegisterInfo("r12", 8),
        "r13": RegisterInfo("r13", 8),
        "r14": RegisterInfo("r14", 8),
        "r15": RegisterInfo("r15", 8),
        "r16": RegisterInfo("r16", 8),
        "r17": RegisterInfo("r17", 8),
        "r18": RegisterInfo("r18", 8),
        "r19": RegisterInfo("r19", 8),
        "r20": RegisterInfo("r20", 8),
        "r21": RegisterInfo("r21", 8),
        "r22": RegisterInfo("r22", 8),
        "r23": RegisterInfo("r23", 8),
        "r24": RegisterInfo("r24", 8),
        "r25": RegisterInfo("r25", 8),
        "r26": RegisterInfo("r26", 8),
        "r27": RegisterInfo("r27", 8),
        "r28": RegisterInfo("r28", 8),
        "r29": RegisterInfo("r29", 8),
        "r30": RegisterInfo("r30", 8),
        "r31": RegisterInfo("r31", 8),

        "f0": RegisterInfo("f0", 8),
        "f1": RegisterInfo("f1", 8),
        "f2": RegisterInfo("f2", 8),
        "f3": RegisterInfo("f3", 8),
        "f4": RegisterInfo("f4", 8),
        "f5": RegisterInfo("f5", 8),
        "f6": RegisterInfo("f6", 8),
        "f7": RegisterInfo("f7", 8),
        "f8": RegisterInfo("f8", 8),
        "f9": RegisterInfo("f9", 8),
        "f10": RegisterInfo("f10", 8),
        "f11": RegisterInfo("f11", 8),
        "f12": RegisterInfo("f12", 8),
        "f13": RegisterInfo("f13", 8),
        "f14": RegisterInfo("f14", 8),
        "f15": RegisterInfo("f15", 8),
        "f16": RegisterInfo("f16", 8),
        "f17": RegisterInfo("f17", 8),
        "f18": RegisterInfo("f18", 8),
        "f19": RegisterInfo("f19", 8),
        "f20": RegisterInfo("f20", 8),
        "f21": RegisterInfo("f21", 8),
        "f22": RegisterInfo("f22", 8),
        "f23": RegisterInfo("f23", 8),
        "f24": RegisterInfo("f24", 8),
        "f25": RegisterInfo("f25", 8),
        "f26": RegisterInfo("f26", 8),
        "f27": RegisterInfo("f27", 8),
        "f28": RegisterInfo("f28", 8),
        "f29": RegisterInfo("f29", 8),
        "f30": RegisterInfo("f30", 8),
        "f31": RegisterInfo("f31", 8),

        "v0": RegisterInfo("v0", 16),
        "v1": RegisterInfo("v1", 16),
        "v2": RegisterInfo("v2", 16),
        "v3": RegisterInfo("v3", 16),
        "v4": RegisterInfo("v4", 16),
        "v5": RegisterInfo("v5", 16),
        "v6": RegisterInfo("v6", 16),
        "v7": RegisterInfo("v7", 16),
        "v8": RegisterInfo("v8", 16),
        "v9": RegisterInfo("v9", 16),
        "v10": RegisterInfo("v10", 16),
        "v11": RegisterInfo("v11", 16),
        "v12": RegisterInfo("v12", 16),
        "v13": RegisterInfo("v13", 16),
        "v14": RegisterInfo("v14", 16),
        "v15": RegisterInfo("v15", 16),
        "v16": RegisterInfo("v16", 16),
        "v17": RegisterInfo("v17", 16),
        "v18": RegisterInfo("v18", 16),
        "v19": RegisterInfo("v19", 16),
        "v20": RegisterInfo("v20", 16),
        "v21": RegisterInfo("v21", 16),
        "v22": RegisterInfo("v22", 16),
        "v23": RegisterInfo("v23", 16),
        "v24": RegisterInfo("v24", 16),
        "v25": RegisterInfo("v25", 16),
        "v26": RegisterInfo("v26", 16),
        "v27": RegisterInfo("v27", 16),
        "v28": RegisterInfo("v28", 16),
        "v29": RegisterInfo("v29", 16),
        "v30": RegisterInfo("v30", 16),
        "v31": RegisterInfo("v31", 16),

        "lr": RegisterInfo("lr", 8),
        "ctr": RegisterInfo("ctr", 8),
        "xer": RegisterInfo("xer", 4),
        "cr": RegisterInfo("cr", 4),
        "fpscr": RegisterInfo("fpscr", 4),
        "vrsave": RegisterInfo("vrsave", 4),
        "vscr": RegisterInfo("vscr", 4),
        "cia": RegisterInfo("cia", 8),
    }

    def get_instruction_low_level_il(self, data: bytes, addr: int, il: LowLevelILFunction) -> int | None:

        text, length = self.get_instruction_text(data, addr)
        if(length == 0 or len(text) == 0):
            return super(CellPPE, self).get_instruction_low_level_il(data, addr, il)

        # opcode = text[0].text
        # match opcode:
        #     case 'lfs':  # Load Floating-Point Single
        #     case 'stfs':  # Store Floating-Point Single
        #     case 'clrldi':  # Clear Left Double Word Immediate
        #     case 'cmpdi':  # Compare Double Word Immediate

        return super(CellPPE, self).get_instruction_low_level_il(data, addr, il)