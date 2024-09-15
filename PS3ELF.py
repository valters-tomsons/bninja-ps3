from binaryninja import *
from .elf_sce import *

class PS3ELF(BinaryView):
    name = "PS3ELF"
    long_name = "PlayStation 3 ELF"

    def __init__(self, data):
        BinaryView.__init__(self, parent_view = data, file_metadata = data.file)
        self.data = data

    @classmethod
    def is_valid_for_data(cls, data) -> bool:
        header = data.read(0, 64)
        return (
            header[0:4] == b'\x7fELF'    and # elf_ident magic
            header[7] == 0x66            and # OS (CELL_LV2)
            header[18:20] == b'\x00\x15'     # e_machine (PPC64)
        )

    def perform_get_default_endianness(self) -> Endianness:
        return Endianness.BigEndian
    
    def perform_is_executable(self) -> bool:
        return True
    
    def perform_get_entry_point(self) -> int:
        return struct.unpack(">Q", self.data.read(0x18, 8))[0]

    def _get_address_size(self, ctxt):
        return self.arch.address_size

    def init(self):
        self.arch = Architecture["ppc64"]
        self.arch.address_size = 4
        self.arch.address_size = 4
        self.arch.default_int_size = 4
        self.arch.instr_alignment = 4
        self.arch.max_instr_length = 4
        self.arch.stack_pointer = "r1"
        self.arch.link_reg = "lr"
        self.arch.flags = ["cr", "vscr", "fpscr", "xer"]
        self.arch.regs = {
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
        self.platform = self.arch.standalone_platform
        log.log_info('ppc64-cellbe')
        define_elf_header(self)

        base_addr = 0x10000
        self.define_data_var(base_addr, Type.structure(elf64_header), "Elf64_Ehdr")

        # Read ELF header
        e_phoff = struct.unpack(">Q", self.data.read(0x20, 8))[0]
        e_phentsize = struct.unpack(">H", self.data.read(0x36, 2))[0]
        e_phnum = struct.unpack(">H", self.data.read(0x38, 2))[0]

        self.define_data_var(base_addr + e_phoff, Type.array(elf64_phdr, e_phnum), "Elf64_Phdrs")

        # Parse program headers (segments)
        for i in range(e_phnum):
            ph_offset = e_phoff + i * e_phentsize
            p_type = struct.unpack(">I", self.data.read(ph_offset, 4))[0]
            p_flags = struct.unpack(">I", self.data.read(ph_offset + 4, 4))[0]
            p_offset = struct.unpack(">Q", self.data.read(ph_offset + 8, 8))[0]
            p_vaddr = struct.unpack(">Q", self.data.read(ph_offset + 16, 8))[0]
            p_paddr = struct.unpack(">Q", self.data.read(ph_offset + 24, 8))[0]
            p_filesz = struct.unpack(">Q", self.data.read(ph_offset + 32, 8))[0]
            p_memsz = struct.unpack(">Q", self.data.read(ph_offset + 40, 8))[0]
            p_align = struct.unpack(">Q", self.data.read(ph_offset + 48, 8))[0]

            # Add segment to binary view
            if p_type == 1:  # PT_LOAD
                segment_name = "TEXT" if p_flags & 1 else "DATA"
                self.add_auto_segment(
                    p_vaddr, 
                    p_memsz,
                    p_offset,
                    p_filesz,
                    SegmentFlag.SegmentReadable | 
                    SegmentFlag.SegmentExecutable if p_flags & 1 else SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable
                )
                self.add_auto_section(
                    segment_name,
                    p_vaddr,
                    p_memsz,
                    SectionSemantics.ReadOnlyCodeSectionSemantics if p_flags & 1 else SectionSemantics.ReadWriteDataSectionSemantics
                )

        return True