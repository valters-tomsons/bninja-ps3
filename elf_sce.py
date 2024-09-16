from binaryninja import BinaryView, EnumerationBuilder, StructureBuilder, Type

elf_encoding = EnumerationBuilder.create()
elf_os = EnumerationBuilder.create()
elf_etype = EnumerationBuilder.create()
elf_emachine = EnumerationBuilder.create()
elf_ptype = EnumerationBuilder.create()
elf_pflags = EnumerationBuilder.create()

elf_eident = StructureBuilder.create()
elf64_header = StructureBuilder.create()
elf64_phdr = StructureBuilder.create()
elf64_shdr = StructureBuilder.create()

def define_elf_types(bv: BinaryView):
    elf_encoding.width = 1
    elf_encoding.append("BigEndian", 2)
    bv.define_type("ELF_ENCODING", "ELF_ENCODING", elf_encoding)

    elf_os.width = 1
    elf_os.append("none", 0)
    elf_os.append("CELL_LV2", 0x66)
    bv.define_type("ELF_OS", "ELF_OS", elf_os)

    elf_etype.width = 2
    elf_etype.append("ET_EXEC", 2)
    bv.define_type("ELF_ETYPE", "ELF_ETYPE", elf_etype)

    elf_emachine.width = 2
    elf_emachine.append("EM_PPC64", 0x15)
    bv.define_type("ELF_EMACHINE", "ELF_EMACHINE", elf_emachine)

    # ELF Identification
    elf_eident.append(Type.array(Type.char(), 4), "magic")
    elf_eident.append(Type.int(1, False), "class")
    elf_eident.append(Type.enumeration_type(bv.arch, elf_encoding), "encoding")
    elf_eident.append(Type.int(1, False), "version")
    elf_eident.append(Type.enumeration_type(bv.arch, elf_os), "os")
    elf_eident.append(Type.int(1, False), "abi")
    elf_eident.append(Type.array(Type.char(), 7), "pad")
    bv.define_type("e_ident", "e_ident", elf_eident)

    # ELF64 file header
    elf64_header.append(Type.structure_type(elf_eident), "e_ident")
    elf64_header.append(Type.enumeration_type(bv.arch, elf_etype), "e_type")
    elf64_header.append(Type.enumeration_type(bv.arch, elf_emachine), "e_machine")
    elf64_header.append(Type.int(4, False), "e_version")
    elf64_header.append(Type.pointer_of_width(8, Type.pointer_of_width(4, Type.function(Type.void()))), "e_entry")
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

    elf_ptype.width = 4
    elf_ptype.append("PT_NULL", 0)
    elf_ptype.append("PT_LOAD", 1)
    elf_ptype.append("PT_DYNAMIC", 2)
    elf_ptype.append("PT_SCE_UNK_70000000", 0x7)
    elf_ptype.append("PT_SCE_RELA", 0x60000000)
    elf_ptype.append("PT_SCE_LICINFO_1", 0x60000001)
    elf_ptype.append("PT_SCE_LICINFO_2", 0x60000002)
    bv.define_type("p_type", "p_type", elf_ptype)

    elf_pflags.width = 4
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

    # Program header
    elf64_phdr.append(Type.enumeration_type(bv.arch, elf_ptype), "p_type")
    elf64_phdr.append(Type.enumeration_type(bv.arch, elf_pflags), "p_flags")
    elf64_phdr.append(Type.int(8, False), "p_offset")
    elf64_phdr.append(Type.int(8, False), "p_vaddr")
    elf64_phdr.append(Type.int(8, False), "p_paddr")
    elf64_phdr.append(Type.int(8, False), "p_filesz")
    elf64_phdr.append(Type.int(8, False), "p_memsz")
    elf64_phdr.append(Type.int(8, False), "p_align")
    bv.define_type("Elf64_Phdr", "Elf64_Phdr", elf64_phdr)