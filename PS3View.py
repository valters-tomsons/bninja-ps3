from binaryninja import *
from .ElfSce import *
from .CellPPE import create_cellbe_ppc64

class PS3View(BinaryView):
    name = "PS3ELF"
    long_name = "PlayStation 3 ELF"
    base_addr = 0x10000
    syscall_addr = 0x08000000

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
        self.arch = create_cellbe_ppc64(self)
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

        # e_entry points to a function descriptor in opd segment
        e_entry = elf_header["e_entry"].value
        self.add_tag(e_entry, self.name, "_toc_.start")

        # populate opd descriptors
        func_desc_t = self.get_type_by_id("func_desc")
        opd_segment = self.get_segment_at(e_entry)
        self.add_auto_section(".opd", opd_segment.start, opd_segment.length, SectionSemantics.ReadOnlyDataSectionSemantics)
        opd_entry_count = opd_segment.length // 8
        for i in range(opd_entry_count):
            offset = opd_segment.start + (i * 8)
            self.define_data_var(offset, func_desc_t, f"PTR_{i}")

            entry = self.get_data_var_at(offset)
            addr = entry["func_entry"].value

            if(offset == e_entry):
                entry.name = "PTR_start"
                entry_toc = entry["toc_base"].value
                self.add_entry_point(addr)
                self.add_tag(addr, self.name, "_start", False)
                self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, addr, f".start"))
                continue

            self.get_data_var_at(offset).name = f"PTR_{addr:02x}"

            sections = self.get_sections_at(addr)
            for section in sections:
                if(section.semantics == SectionSemantics.ReadOnlyCodeSectionSemantics):
                    self.add_function(addr)
                    break

        # .start TOC base value
        self.define_data_var(entry_toc, func_desc_t, "TOC_BASE")

        # Syscall segment
        self.memory_map.add_memory_region("SYSCALLS", self.syscall_addr, bytearray(0x10000))
        self.define_data_var(self.syscall_addr, "void", "_syscalls")

        return True