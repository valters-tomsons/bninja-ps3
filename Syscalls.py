import os
from binaryninja import CallingConvention, Function, InstructionTextTokenType, LowLevelILOperation, Type, TypeBuilder, TypeLibrary, log, BackgroundTaskThread, BinaryView

class PS3SyscallCallingConvention(CallingConvention):
    name = "lv2-syscall"
    int_arg_regs = ["r11"]

class SyscallAnalysisTask(BackgroundTaskThread):
    def __init__(self, bv: BinaryView):
        BackgroundTaskThread.__init__(self, 'Waiting for analysis for finish...', False)
        self.bv = bv

    def load_syscall_mappings(self) -> dict:
        plugin_dir = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(plugin_dir, 'syscalls')

        syscalls = {}
    
        with open(path, 'r') as f:
            for line in f:
                num, name = line.strip().split(' ', 1)
                syscalls[int(num)] = name

        return syscalls

    def run(self):
        log.log_info("Loading syscall definitions...")
        syscalls = self.load_syscall_mappings()

        log.log_info("Looking for system calls...")
        usedSyscalls = {}
        for func in self.bv.functions:
            for il in func.basic_blocks:
                for line in il.disassembly_text:
                    for token in line.tokens:
                        if token.type == InstructionTextTokenType.InstructionToken and token.text.strip() == 'sc':
                            syscall = func.get_reg_value_at(line.address, "r11").value & 0xFFFFFFFF
                            backtracked = False

                            if syscall is None or syscall == 0:
                                backtracked = True
                                syscall = self.find_r11_value_by_backtrack(func, line.address)
                                if syscall is None or syscall == 0:
                                    log.log_error(f"failed to find syscall number for 0x{line.address:02x}")
                                    continue

                            syscall_name = syscalls.get(syscall)
                            if syscall_name is None:
                                log.log_warn(f"Unknown system call number: {syscall}")
                                syscall_name = f'_syscall_{syscall}'

                            log.log_debug(f"{"backtracked" if backtracked else "lifted"} 0x{line.address:02x} sc {syscall} ('{syscall_name}')")
                            
                            self.bv.set_comment_at(line.address, syscall_name)

                            if usedSyscalls.get(syscall) is None:
                                syscall_type = TypeBuilder.function(Type.void(), calling_convention=self.bv.platform.system_call_convention)
                                syscall_type.system_call_number = syscall
                                self.bv.define_type(syscall_name, syscall_name, syscall_type)
                                usedSyscalls[syscall] = True 

                            func.add_user_type_ref(line.address, syscall_name, self.bv.arch)


        log.log_info(f"{len(usedSyscalls)} unique syscall definitions added!")

    def get_syscall_name_by_num(self, syscalls: dict, number: int) -> str:
        if syscalls[number] is None:
            log.log_warn(f"unknown LV2 syscall number: {number}")
            return f"_syscall_{number}"
        return syscalls[number]

    # used in cases when bninja can't find value of r11    
    def find_r11_value_by_backtrack(self, func: Function, target_address):
        current_block = None

        for block in func.basic_blocks:
            if block.start <= target_address <= block.end:
                current_block = block
                break
        if not current_block:
            return None

        blocks_to_check = [current_block] + [
               block for block in func.basic_blocks 
               if block.end < current_block.start
           ]

        for block in blocks_to_check:
            for line in reversed(block.disassembly_text):
                if block == current_block and line.address >= target_address:
                    continue

                tokens = [token.text for token in line.tokens]
                tokens = [s for s in tokens if s.strip(",#(){}[]").strip()]
                if len(tokens) < 3:  # Need instruction, r11, and a value
                    continue

                if tokens[1].lower() != 'r11':
                    continue

                value = tokens[2]
                try:
                    parsed_value = int(value, 0) if value.startswith('0x') else int(value)
                    return parsed_value & 0xFFFFFFFF
                except ValueError:
                    continue
        
        return None