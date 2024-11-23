import os
from binaryninja import CallingConvention, Function, InstructionTextTokenType, LowLevelILOperation, Type, TypeBuilder, TypeLibrary, log, BackgroundTaskThread, BinaryView

class PS3SyscallCallingConvention(CallingConvention):
    name = "lv2-syscall"
    int_arg_regs = ["r11"]

def add_syscall_library(bv: BinaryView):
    lib = TypeLibrary.new(bv.arch, "LV2_SYSCALLS")
    lib.add_platform(bv.platform)

    syscall_convention = PS3SyscallCallingConvention(bv.arch, "lv2-syscall")
    bv.platform.system_call_convention = syscall_convention

    plugin_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(plugin_dir, 'syscalls')

    with open(path, 'r') as f:
        for line in f:
            num, name = line.strip().split(' ', 1)
            syscall = TypeBuilder.function(Type.void(), calling_convention=syscall_convention)
            syscall.system_call_number = int(num)
            lib.add_named_type(name, syscall)

    bv.add_type_library(lib)

class SyscallAnalysisTask(BackgroundTaskThread):
    def __init__(self, bv: BinaryView):
        BackgroundTaskThread.__init__(self, 'Waiting for analysis for finish...', False)
        self.bv = bv

    def run(self):
        lib = self.bv.get_type_library("LV2_SYSCALLS")
        log.log_info("Looking for syscalls...")

        for func in self.bv.functions:
            for il in func.basic_blocks:
                for line in il.disassembly_text:
                    for token in line.tokens:
                        if token.type == InstructionTextTokenType.InstructionToken and token.text.strip() == 'sc':
                            syscall = func.get_reg_value_at(line.address, "r11").value

                            if syscall is None or syscall == 0:
                                log.log_warn(f"could not find value of 'r11' at 0x{line.address:02x}, backtracking for an assignment...")
                                syscall = self.find_r11_value_by_backtrack(func, line.address)
                                if syscall is None or syscall == 0:
                                    log.log_error(f"failed to find syscall number for 0x{line.address:02x}")
                                    continue

                            syscall_name = self.get_syscall_name_by_num(lib, syscall)
                            log.log_info(f"0x{line.address:02x} sc {syscall} ('{syscall_name}')")
                            self.bv.set_comment_at(line.address, syscall_name)

        log.log_info("Finished looking for syscalls!")

    def get_syscall_name_by_num(self, lib: TypeLibrary, num: int) -> str:
        for name, type in lib.named_types.items():
            if type.system_call_number == num:
                return name.__str__()
        log.log_warn(f"called unknown LV2 syscall number: {num}")
        return f"_syscall_{num}"

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
                    return int(value, 0) if value.startswith('0x') else int(value)
                except ValueError:
                    continue
        
        return None