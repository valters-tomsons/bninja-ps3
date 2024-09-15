from binaryninja import BinaryView, EnumerationBuilder, StructureBuilder, Type

elf_encoding = EnumerationBuilder.create()
elf_os = EnumerationBuilder.create()
elf_etype = EnumerationBuilder.create()
elf_emachine = EnumerationBuilder.create()

e_ident = StructureBuilder.create()
elf64_header = StructureBuilder.create()
elf64_phdr = StructureBuilder.create()
elf64_shdr = StructureBuilder.create()

def define_elf_header(bv: BinaryView):
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
    e_ident.append(Type.array(Type.char(), 4), "magic")
    e_ident.append(Type.int(1, False), "class")
    e_ident.append(Type.enumeration_type(bv.arch, elf_encoding), "encoding")
    e_ident.append(Type.int(1, False), "version")
    e_ident.append(Type.enumeration_type(bv.arch, elf_os), "os")
    e_ident.append(Type.int(1, False), "abi")
    e_ident.append(Type.array(Type.char(), 7), "pad")
    bv.define_type("e_ident", "e_ident", e_ident)

    # ELF64 file header
    elf64_header.append(Type.structure_type(e_ident), "e_ident")
    elf64_header.append(Type.enumeration_type(bv.arch, elf_etype), "e_type")
    elf64_header.append(Type.enumeration_type(bv.arch, elf_emachine), "e_machine")
    elf64_header.append(Type.int(4, False), "e_version")
    elf64_header.append(Type.pointer_of_width(8, Type.int(4, False)), "e_entry")
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

    # Program header
    elf64_phdr.append(Type.int(4, False), "p_type")
    elf64_phdr.append(Type.int(4, False), "p_flags")
    elf64_phdr.append(Type.int(8, False), "p_offset")
    elf64_phdr.append(Type.int(8, False), "p_vaddr")
    elf64_phdr.append(Type.int(8, False), "p_paddr")
    elf64_phdr.append(Type.int(8, False), "p_filesz")
    elf64_phdr.append(Type.int(8, False), "p_memsz")
    elf64_phdr.append(Type.int(8, False), "p_align")
    bv.define_type("Elf64_Phdr", "Elf64_Phdr", elf64_phdr)