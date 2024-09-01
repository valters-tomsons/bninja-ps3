from binaryninja import *

class PS3ELF(BinaryView):
    name = "PS3 ELF"
    long_name = "PlayStation 3 ELF"

    def __init__(self, data):
        BinaryView.__init__(self, parent_view = data, file_metadata = data.file)
        self.platform = Architecture["CellBE-ppc64"].standalone_platform
        self.data = data

    @classmethod
    def is_valid_for_data(cls, data) -> bool:
        header = data.read(0, 64)
        return (
            header[0:4] == b'\x7fELF'    and # magic (elf)
            header[7] == 0x66            and # OS (f)
            header[18:20] == b'\x00\x15'     # e_machine (ppc64)
        )
    
    def perform_is_executable(self) -> bool:
        return True
    
    def perform_get_entry_point(self) -> int:
        return struct.unpack(">Q", self.data.read(0x18, 8))[0]

    def _get_address_size(self, ctxt):
        return self.arch.address_size

    def init(self):
        # Read ELF header
        e_phoff = struct.unpack(">Q", self.data.read(0x20, 8))[0]
        e_phentsize = struct.unpack(">H", self.data.read(0x36, 2))[0]
        e_phnum = struct.unpack(">H", self.data.read(0x38, 2))[0]

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