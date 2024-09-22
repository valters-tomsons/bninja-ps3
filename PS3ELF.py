from binaryninja import *
from .elf_sce import *

class PS3ELF(BinaryView):
    name = "PS3ELF"
    long_name = "PlayStation 3 ELF"
    base_addr = 0x10000

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
        self.create_tag_type(self.name, "🎮")

        # elf header

        define_elf_types(self)
        self.add_auto_segment(self.base_addr, 0x40, 0x0, 0x40, SegmentFlag.SegmentReadable | SegmentFlag.SegmentContainsData)
        self.define_data_var(self.base_addr, "Elf64_Ehdr", "_file_header")
        elf_header = self.get_data_var_at(self.base_addr)

        # elf segments

        e_phoff = elf_header["e_phoff"].value
        e_phentsize = elf_header["e_phentsize"].value
        e_phnum = elf_header["e_phnum"].value
        self.add_auto_segment(self.base_addr + e_phoff, e_phentsize * e_phnum, e_phoff, e_phentsize * e_phnum, SegmentFlag.SegmentReadable | SegmentFlag.SegmentContainsData)
        self.define_data_var(self.base_addr + e_phoff, Type.array(self.get_type_by_id("Elf64_Phdr"), e_phnum), "_program_headers")
        program_headers = self.get_data_var_at(self.base_addr + e_phoff)

        for i in range(e_phnum):
            phdr = program_headers[i]
            p_flags = phdr["p_flags"].value
            p_offset = phdr["p_offset"].value
            p_vaddr = phdr["p_vaddr"].value
            p_filesz = phdr["p_filesz"].value
            p_memsz = phdr["p_memsz"].value

            flags = get_segment_flags(p_flags)
            self.add_auto_segment(p_vaddr, p_memsz, p_offset, p_filesz, flags)

        # elf sections

        e_shoff = elf_header["e_shoff"].value
        e_shentsize = elf_header["e_shentsize"].value
        e_shnum = elf_header["e_shnum"].value
        
        self.add_auto_segment(self.base_addr + e_shoff, e_shentsize * e_shnum, e_shoff, e_shentsize * e_shnum, SegmentFlag.SegmentReadable | SegmentFlag.SegmentContainsData)
        self.define_data_var(self.base_addr + e_shoff, Type.array(self.get_type_by_id("Elf64_Shdr"), e_shnum), "_section_headers")
        self.add_tag(self.base_addr + e_shoff, self.name, "_section_headers", False)
        section_headers = self.get_data_var_at(self.base_addr + e_shoff)

        # section header string table
        e_shstrndx = elf_header["e_shstrndx"].value
        shstrtab_hdr = section_headers[e_shstrndx]
        shstrtab_offset = shstrtab_hdr["sh_offset"].value
        shstrtab_size = shstrtab_hdr["sh_size"].value
        shstrtab = self.data.read(shstrtab_offset, shstrtab_size)
        self.add_tag(self.base_addr + shstrtab_offset, self.name, "_shdr_string_table")

        for i in range(e_shnum):
            shdr = section_headers[i]
            sh_name_offset = shdr["sh_name"].value

            sh_name = shstrtab[sh_name_offset:].split(b'\x00', 1)[0].decode('utf-8')
            sh_type = shdr["sh_type"].value
            if not sh_name:
                shtype_name = str(sh_type).removeprefix('<SHT_').split()[0]
                sh_name = f"{shtype_name} ({i})"
            
            sh_addr = shdr["sh_addr"].value
            sh_offset = shdr["sh_offset"].value
            sh_size = shdr["sh_size"].value
            sh_flags = shdr["sh_flags"].value

            flags = get_section_semantics(sh_type, sh_flags)

            addr = sh_addr if sh_addr != 0 else self.base_addr + sh_offset
            self.add_auto_section(sh_name, addr, sh_size, flags)

        # e_entry points to an address in TOC
        e_entry = elf_header["e_entry"].value
        self.define_data_var(e_entry, Type.pointer_of_width(4, Type.function()), "_TOC_start")
        start_addr = struct.unpack(">I", self.data.read(e_entry-self.base_addr, 4))[0]
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, start_addr, "_start"))
        self.add_function(start_addr)
        self.add_entry_point(start_addr)
        self.add_tag(start_addr, self.name, "_start", False)

        return True

def get_segment_flags(p_flags: int):
    flag_mappings = [
        # PF_*, PF_SPU_*, PF_RSX_*
        (0x1 | 0x00100000 | 0x01000000, SegmentFlag.SegmentExecutable),
        (0x2 | 0x00200000 | 0x02000000, SegmentFlag.SegmentWritable),
        (0x4 | 0x00400000 | 0x04000000, SegmentFlag.SegmentReadable)
    ]

    return sum(flag for mask, flag in flag_mappings if int(p_flags) & mask)

def get_section_semantics(sh_type: int, sh_flags: int):
    type_mappings = {
        0: SectionSemantics.DefaultSectionSemantics,  # SHT_NULL
        1: SectionSemantics.ReadOnlyDataSectionSemantics,  # SHT_PROGBITS
        2: SectionSemantics.ReadOnlyDataSectionSemantics,  # SHT_SYMTAB
        3: SectionSemantics.ReadOnlyDataSectionSemantics,  # SHT_STRTAB
        4: SectionSemantics.ReadOnlyDataSectionSemantics,  # SHT_RELA
        5: SectionSemantics.ReadOnlyDataSectionSemantics,  # SHT_HASH
        6: SectionSemantics.ReadWriteDataSectionSemantics,  # SHT_DYNAMIC
        7: SectionSemantics.ReadOnlyDataSectionSemantics,  # SHT_NOTE
        8: SectionSemantics.ReadWriteDataSectionSemantics,  # SHT_NOBITS
        9: SectionSemantics.ReadOnlyDataSectionSemantics,  # SHT_REL
        10: SectionSemantics.DefaultSectionSemantics,  # SHT_SHLIB
        11: SectionSemantics.ReadOnlyDataSectionSemantics,  # SHT_DYNSYM
    }

    sce_types = {
        0x60000000,  # SHT_SCE_RELA
        0x61000001,  # SHT_SCE_NID
        0x70000080,  # SHT_SCE_IOPMOD
        0x70000090,  # SHT_SCE_EEMOD
        0x700000A0,  # SHT_SCE_PSPRELA
        0x700000A4,  # SHT_SCE_PPURELA
    }

    semantics = SectionSemantics.DefaultSectionSemantics

    if sh_type in type_mappings:
        semantics = type_mappings[sh_type]
    elif sh_type in sce_types:
        semantics = SectionSemantics.ReadOnlyDataSectionSemantics

    if sh_flags & 0x1:  # SHF_WRITE
        semantics = SectionSemantics.ReadWriteDataSectionSemantics
    elif sh_flags & 0x4:  # SHF_EXECINSTR
        semantics = SectionSemantics.ReadOnlyCodeSectionSemantics

    return semantics