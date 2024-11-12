from binaryninja import BinaryView, EnumerationBuilder, SectionSemantics, SegmentFlag, StructureBuilder, Type

def define_elf_types(bv: BinaryView):

    elf_encoding = EnumerationBuilder.create()
    elf_encoding.width = 1
    elf_encoding.append("BigEndian", 2)
    bv.define_type("ELF_ENCODING", "ELF_ENCODING", elf_encoding)

    elf_os = EnumerationBuilder.create()
    elf_os.width = 1
    elf_os.append("none", 0)
    elf_os.append("CELL_LV2", 0x66)
    bv.define_type("ELF_OS", "ELF_OS", elf_os)

    elf_etype = EnumerationBuilder.create()
    elf_etype.width = 2
    elf_etype.append("ET_NONE", 0)
    elf_etype.append("ET_REL", 1)
    elf_etype.append("ET_EXEC", 2)
    elf_etype.append("ET_DYN", 3)
    elf_etype.append("ET_CORE", 4)
    elf_etype.append("ET_SCE_PRX", 0xffa4)
    elf_etype.append("ET_SCE_EXEC", 0xfe00)
    elf_etype.append("ET_SCE_RELEXEC", 0xfe04)
    bv.define_type("ELF_ETYPE", "ELF_ETYPE", elf_etype)

    elf_emachine = EnumerationBuilder.create()
    elf_emachine.width = 2
    elf_emachine.append("EM_PPC64", 0x15)
    bv.define_type("ELF_EMACHINE", "ELF_EMACHINE", elf_emachine)

    elf_eident = StructureBuilder.create()
    elf_eident.append(Type.array(Type.char(), 4), "magic")
    elf_eident.append(Type.int(1, False), "class")
    elf_eident.append(Type.enumeration_type(bv.arch, elf_encoding), "encoding")
    elf_eident.append(Type.int(1, False), "version")
    elf_eident.append(Type.enumeration_type(bv.arch, elf_os), "os")
    elf_eident.append(Type.int(1, False), "abi")
    elf_eident.append(Type.array(Type.char(), 7), "pad")
    bv.define_type("e_ident", "e_ident", elf_eident)

    func_descriptor = StructureBuilder.create()
    func_descriptor.append(Type.pointer_of_width(4, Type.function()), "func_entry")
    func_descriptor.append(Type.pointer_of_width(4, Type.void()), "toc_base")
    bv.define_type("func_desc", "func_desc", func_descriptor)

    elf64_header = StructureBuilder.create()
    elf64_header.append(Type.structure_type(elf_eident), "e_ident")
    elf64_header.append(Type.enumeration_type(bv.arch, elf_etype), "e_type")
    elf64_header.append(Type.enumeration_type(bv.arch, elf_emachine), "e_machine")
    elf64_header.append(Type.int(4, False), "e_version")
    elf64_header.append(Type.pointer_of_width(8, bv.get_type_by_id("func_desc")), "e_entry")
    elf64_header.append(Type.int(8, False), "e_phoff")
    elf64_header.append(Type.int(8, False), "e_shoff")
    elf64_header.append(Type.int(4, False), "e_flags")
    elf64_header.append(Type.int(2, False), "e_ehsize")
    elf64_header.append(Type.int(2, False), "e_phentsize")
    elf64_header.append(Type.int(2, False), "e_phnum")
    elf64_header.append(Type.int(2, False), "e_shentsize")
    elf64_header.append(Type.int(2, False), "e_shnum")
    elf64_header.append(Type.int(2, False), "e_shstrndx")
    bv.define_type("Elf64_Ehdr", "Elf64_Ehdr", elf64_header)

    elf_ptype = EnumerationBuilder.create()
    elf_ptype.width = 4
    elf_ptype.signed = False
    elf_ptype.append("PT_NULL", 0)
    elf_ptype.append("PT_LOAD", 1)
    elf_ptype.append("PT_DYNAMIC", 2)
    elf_ptype.append("PT_INTERP", 3)
    elf_ptype.append("PT_NOTE", 4)
    elf_ptype.append("PT_SHLIB", 5)
    elf_ptype.append("PT_PHDR", 6)
    elf_ptype.append("PT_SCE_RELA", 0x60000000)
    elf_ptype.append("PT_PROC_PARAM", 0x60000001)
    elf_ptype.append("PT_PROC_PRX", 0x60000002)
    bv.define_type("p_type", "p_type", elf_ptype)

    elf_pflags = EnumerationBuilder.create()
    elf_pflags.width = 4
    elf_pflags.signed = False
    elf_pflags.append("PF_X", 0x1)
    elf_pflags.append("PF_W", 0x2)
    elf_pflags.append("PF_R", 0x4)
    elf_pflags.append("PF_SPU_X", 0x00100000)
    elf_pflags.append("PF_SPU_W", 0x00200000)
    elf_pflags.append("PF_SPU_R", 0x00400000)
    elf_pflags.append("PF_RSX_X", 0x01000000)
    elf_pflags.append("PF_RSX_W", 0x02000000)
    elf_pflags.append("PF_RSX_R", 0x04000000)
    bv.define_type("p_flags", "p_flags", elf_pflags)

    elf64_phdr = StructureBuilder.create()
    elf64_phdr.append(Type.enumeration_type(bv.arch, elf_ptype), "p_type")
    elf64_phdr.append(Type.enumeration_type(bv.arch, elf_pflags), "p_flags")
    elf64_phdr.append(Type.int(8, False), "p_offset")
    elf64_phdr.append(Type.int(8, False), "p_vaddr")
    elf64_phdr.append(Type.int(8, False), "p_paddr")
    elf64_phdr.append(Type.int(8, False), "p_filesz")
    elf64_phdr.append(Type.int(8, False), "p_memsz")
    elf64_phdr.append(Type.int(8, False), "p_align")
    elf64_phdr.packed = True
    bv.define_type("Elf64_Phdr", "Elf64_Phdr", elf64_phdr)

    elf_shtype = EnumerationBuilder.create()
    elf_shtype.width = 4
    elf_shtype.append("SHT_NULL", 0)
    elf_shtype.append("SHT_PROGBITS", 1)
    elf_shtype.append("SHT_SYMTAB", 2)
    elf_shtype.append("SHT_STRTAB", 3)
    elf_shtype.append("SHT_RELA", 4)
    elf_shtype.append("SHT_HASH", 5)
    elf_shtype.append("SHT_DYNAMIC", 6)
    elf_shtype.append("SHT_NOTE", 7)
    elf_shtype.append("SHT_NOBITS", 8)
    elf_shtype.append("SHT_REL", 9)
    elf_shtype.append("SHT_SHLIB", 10)
    elf_shtype.append("SHT_DYNSYM", 11)
    elf_shtype.append("SHT_SCE_RELA", 0x60000000)
    elf_shtype.append("SHT_SCE_NID", 0x61000001)
    elf_shtype.append("SHT_SCE_IOPMOD", 0x70000080)
    elf_shtype.append("SHT_SCE_EEMOD", 0x70000090)
    elf_shtype.append("SHT_SCE_PSPRELA", 0x700000A0)
    elf_shtype.append("SHT_SCE_PPURELA", 0x700000A4)
    bv.define_type("sh_type", "sh_type", elf_shtype)

    elf_shflags = EnumerationBuilder.create()
    elf_shflags.width = 8
    elf_shflags.append("SHF_WRITE", 0x1)
    elf_shflags.append("SHF_ALLOC", 0x2)
    elf_shflags.append("SHF_EXECINSTR", 0x4)
    bv.define_type("sh_flags", "sh_flags", elf_shflags)

    elf64_shdr = StructureBuilder.create()
    elf64_shdr.append(Type.int(4, False), "sh_name")
    elf64_shdr.append(Type.enumeration_type(bv.arch, elf_shtype), "sh_type")
    elf64_shdr.append(Type.int(8, False), "sh_flags")
    elf64_shdr.append(Type.int(8, False), "sh_addr")
    elf64_shdr.append(Type.int(8, False), "sh_offset")
    elf64_shdr.append(Type.int(8, False), "sh_size")
    elf64_shdr.append(Type.int(4, False), "sh_link")
    elf64_shdr.append(Type.int(4, False), "sh_info")
    elf64_shdr.append(Type.int(8, False), "sh_align")
    elf64_shdr.append(Type.int(8, False), "sh_entsize")
    bv.define_type("Elf64_Shdr", "Elf64_Shdr", elf64_shdr)

def define_sce_types(bv: BinaryView):

    sys_process_param = StructureBuilder.create()
    sys_process_param.append(Type.int(4, False), "size")
    sys_process_param.append(Type.int(4, False), "magic")
    sys_process_param.append(Type.int(4, False), "version")
    sys_process_param.append(Type.int(4, False), "sdk_version")
    sys_process_param.append(Type.int(4, True), "primary_prio")
    sys_process_param.append(Type.int(4, False), "primary_stacksize")
    sys_process_param.append(Type.int(4, False), "malloc_pagesize")
    sys_process_param.append(Type.int(4, False), "ppc_seg")
    sys_process_param.append(Type.int(4, False), "crash_dump_param_addr")
    bv.define_type("sys_process_param_t", "sys_process_param_t", sys_process_param)

    prx_info = StructureBuilder.create()
    prx_info.append(Type.int(4, False), "size")
    prx_info.append(Type.int(4, False), "magic")
    prx_info.append(Type.int(4, False), "version")
    prx_info.append(Type.int(4, False), "sdk_version")
    prx_info.append(Type.int(4, False), "libent_start")
    prx_info.append(Type.int(4, False), "libent_end")
    prx_info.append(Type.int(4, False), "libstub_start")
    prx_info.append(Type.int(4, False), "libstub_end")
    prx_info.append(Type.int(1, False), "major_version")
    prx_info.append(Type.int(1, False), "minor_version")
    prx_info.append(Type.array(Type.int(1, False), 6), "reserved")
    bv.define_type("sys_process_prx_info_t", "sys_process_prx_info_t", prx_info)

    common_info = StructureBuilder.create()
    common_info.append(Type.int(2, False), "module_attribute")
    common_info.append(Type.array(Type.int(1, False), 2), "module_version")
    common_info.append(Type.array(Type.char(), 27), "module_name")
    common_info.append(Type.int(1, False), "infover")
    bv.define_type("scemoduleinfo_common", "scemoduleinfo_common", common_info)

    module_info_ppu64 = StructureBuilder.create()
    module_info_ppu64.append(Type.structure_type(common_info), "common")
    module_info_ppu64.append(Type.int(8, False, "gp_value"))
    module_info_ppu64.append(Type.int(8, False, "ent_top"))
    module_info_ppu64.append(Type.int(8, False, "ent_end"))
    module_info_ppu64.append(Type.int(8, False, "stub_top"))
    module_info_ppu64.append(Type.int(8, False, "stub_end"))
    bv.define_type("scemoduleinfo_ppu64", "scemoduleinfo_ppu64", module_info_ppu64)

    scelibstub_common = StructureBuilder.create()
    scelibstub_common.append(Type.int(1, False), "structsize")
    scelibstub_common.append(Type.array(Type.int(1, False), 1), "reserved1")
    scelibstub_common.append(Type.int(2, False), "version")
    scelibstub_common.append(Type.int(2, False), "attribute")
    scelibstub_common.append(Type.int(2, False), "num_func")
    scelibstub_common.append(Type.int(2, False), "num_var")
    scelibstub_common.append(Type.int(2, False), "num_tlsvar")
    scelibstub_common.append(Type.array(Type.int(1, False), 4), "reserved2")
    bv.define_type("scelibstub_common", "scelibstub_common", scelibstub_common)

    scelibstub_ppu32 = StructureBuilder.create()
    scelibstub_ppu32.append(Type.structure_type(scelibstub_common), "common")
    scelibstub_ppu32.append(Type.pointer_of_width(4, Type.char()), "libname")
    scelibstub_ppu32.append(Type.pointer_of_width(4, Type.void()), "func_nidtable")
    scelibstub_ppu32.append(Type.pointer_of_width(4, Type.void()), "func_table")
    scelibstub_ppu32.append(Type.pointer_of_width(4, Type.void()), "var_nidtable")
    scelibstub_ppu32.append(Type.pointer_of_width(4, Type.void()), "var_table")
    scelibstub_ppu32.append(Type.pointer_of_width(4, Type.void()), "tls_nidtable")
    scelibstub_ppu32.append(Type.pointer_of_width(4, Type.void()), "tls_table")
    bv.define_type("scelibstub_ppu32", "scelibstub_ppu32", scelibstub_ppu32)

def get_segment_flags(p_flags: int) -> SegmentFlag:
    flag_mappings = [
        # PF_*, PF_SPU_*, PF_RSX_*
        (0x1 | 0x00100000 | 0x01000000, SegmentFlag.SegmentExecutable),
        (0x2 | 0x00200000 | 0x02000000, SegmentFlag.SegmentWritable),
        (0x4 | 0x00400000 | 0x04000000, SegmentFlag.SegmentReadable)
    ]

    return sum(flag for mask, flag in flag_mappings if int(p_flags) & mask)

def get_section_semantics(sh_type: int, sh_flags: int) -> SectionSemantics:
    type_semantics = {
        0: SectionSemantics.DefaultSectionSemantics,  # SHT_NULL
        1: SectionSemantics.ReadOnlyDataSectionSemantics,  # SHT_PROGBITS
        6: SectionSemantics.ReadWriteDataSectionSemantics,  # SHT_DYNAMIC
        8: SectionSemantics.ReadWriteDataSectionSemantics,  # SHT_NOBITS
    }

    if sh_type in type_semantics:
        return type_semantics[sh_type]

    if sh_flags & 0x4:  # SHF_EXECINSTR
        return SectionSemantics.ReadOnlyCodeSectionSemantics
    elif sh_flags & 0x1:  # SHF_WRITE
        return SectionSemantics.ReadWriteDataSectionSemantics
    elif sh_flags & 0x2:  # SHF_ALLOC
        return SectionSemantics.ReadOnlyDataSectionSemantics

    return SectionSemantics.DefaultSectionSemantics
