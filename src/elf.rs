pub const EHDR_SIZE: usize = 64;
pub const PHDR_SIZE: usize = 56;
pub const SHDR_SIZE: usize = 64;

pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;
pub const EM_X86_64: u16 = 62;
pub const EM_RISCV: u16 = 243;

pub const PT_LOAD: u32 = 1;
pub const PT_PHDR: u32 = 6;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_NOTE: u32 = 4;

pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_RELA: u32 = 4;
pub const SHT_DYNAMIC: u32 = 6;
pub const SHT_DYNSYM: u32 = 11;
pub const SHT_GNU_HASH: u32 = 0x6ffffff6;
pub const SHT_GNU_VERDEF: u32 = 0x6ffffffd;
pub const SHT_GNU_VERNEED: u32 = 0x6ffffffe;
pub const SHT_GNU_VERSYM: u32 = 0x6fffffff;

pub const SHF_INFO_LINK: u64 = 0x40;

pub const DT_NULL: i64 = 0;
pub const DT_HASH: i64 = 4;
pub const DT_STRTAB: i64 = 5;
pub const DT_SYMTAB: i64 = 6;
pub const DT_STRSZ: i64 = 10;
pub const DT_SYMENT: i64 = 11;
pub const DT_REL: i64 = 17;
pub const DT_RELSZ: i64 = 18;
pub const DT_RELENT: i64 = 19;
pub const DT_PLTREL: i64 = 20;
pub const DT_JMPREL: i64 = 23;
pub const DT_RELRSZ: i64 = 35;
pub const DT_RELR: i64 = 36;
pub const DT_RELRENT: i64 = 37;
pub const DT_GNU_HASH: i64 = 0x6ffffef5;
pub const DT_VERSYM: i64 = 0x6ffffff0;
pub const DT_VERNEED: i64 = 0x6ffffffe;
pub const DT_VERNEEDNUM: i64 = 0x6fffffff;

pub struct Image {
    bytes: Vec<u8>,
}

pub struct ImageSpec {
    pub size: usize,
    pub ehdr: Ehdr,
    pub phdrs: Vec<Phdr>,
    pub shdrs: Vec<Shdr>,
    pub extras: Vec<(usize, Vec<u8>)>,
}

impl ImageSpec {
    pub fn new(size: usize, ehdr: Ehdr) -> Self {
        Self {
            size,
            ehdr,
            phdrs: Vec::new(),
            shdrs: Vec::new(),
            extras: Vec::new(),
        }
    }

    pub fn phdr(mut self, header: Phdr) -> Self {
        self.phdrs.push(header);
        self
    }

    pub fn shdr(mut self, header: Shdr) -> Self {
        self.shdrs.push(header);
        self
    }

    pub fn bytes(mut self, offset: usize, bytes: Vec<u8>) -> Self {
        self.extras.push((offset, bytes));
        self
    }

    pub fn into_image(self) -> Image {
        let mut image = Image::new(self.size);
        image.write_ehdr(self.ehdr);
        for (index, header) in self.phdrs.into_iter().enumerate() {
            image.write_phdr(self.ehdr.phoff, index, header);
        }
        for (index, header) in self.shdrs.into_iter().enumerate() {
            image.write_shdr(self.ehdr.shoff, index, header);
        }
        for (offset, bytes) in self.extras {
            image.write_bytes(offset, &bytes);
        }
        image
    }
}

impl Image {
    pub fn new(size: usize) -> Self {
        Self {
            bytes: vec![0; size],
        }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn write_ehdr(&mut self, header: Ehdr) {
        self.put_bytes(0, &header.magic);
        self.put_bytes(
            4,
            &[
                header.class,
                header.data,
                header.ident_version,
                header.osabi,
            ],
        );
        self.put_u8(8, header.abiver);
        self.put_bytes(9, &header.pad);
        self.put_u16(16, header.ty);
        self.put_u16(18, header.machine);
        self.put_u32(20, header.version);
        self.put_u64(24, header.entry);
        self.put_u64(32, header.phoff);
        self.put_u64(40, header.shoff);
        self.put_u32(48, header.flags);
        self.put_u16(52, header.ehsize);
        self.put_u16(54, header.phentsize);
        self.put_u16(56, header.phnum);
        self.put_u16(58, header.shentsize);
        self.put_u16(60, header.shnum);
        self.put_u16(62, header.shstrndx);
    }

    pub fn write_phdr(&mut self, phoff: u64, index: usize, header: Phdr) {
        let offset = phoff as usize + index * PHDR_SIZE;
        self.put_u32(offset, header.ty);
        self.put_u32(offset + 4, header.flags);
        self.put_u64(offset + 8, header.offset);
        self.put_u64(offset + 16, header.vaddr);
        self.put_u64(offset + 24, header.paddr);
        self.put_u64(offset + 32, header.filesz);
        self.put_u64(offset + 40, header.memsz);
        self.put_u64(offset + 48, header.align);
    }

    pub fn write_shdr(&mut self, shoff: u64, index: usize, header: Shdr) {
        let offset = shoff as usize + index * SHDR_SIZE;
        self.put_u32(offset, header.name);
        self.put_u32(offset + 4, header.ty);
        self.put_u64(offset + 8, header.flags);
        self.put_u64(offset + 16, header.addr);
        self.put_u64(offset + 24, header.offset);
        self.put_u64(offset + 32, header.size);
        self.put_u32(offset + 40, header.link);
        self.put_u32(offset + 44, header.info);
        self.put_u64(offset + 48, header.addralign);
        self.put_u64(offset + 56, header.entsize);
    }

    pub fn write_bytes(&mut self, offset: usize, bytes: &[u8]) {
        self.put_bytes(offset, bytes);
    }

    fn put_bytes(&mut self, offset: usize, bytes: &[u8]) {
        self.ensure_len(offset + bytes.len());
        self.bytes[offset..offset + bytes.len()].copy_from_slice(bytes);
    }

    fn put_u8(&mut self, offset: usize, value: u8) {
        self.put_bytes(offset, &[value]);
    }

    fn put_u16(&mut self, offset: usize, value: u16) {
        self.put_bytes(offset, &value.to_le_bytes());
    }

    fn put_u32(&mut self, offset: usize, value: u32) {
        self.put_bytes(offset, &value.to_le_bytes());
    }

    fn put_u64(&mut self, offset: usize, value: u64) {
        self.put_bytes(offset, &value.to_le_bytes());
    }

    fn ensure_len(&mut self, len: usize) {
        if self.bytes.len() < len {
            self.bytes.resize(len, 0);
        }
    }
}

#[derive(Clone, Copy)]
pub struct Ehdr {
    pub magic: [u8; 4],
    pub class: u8,
    pub data: u8,
    pub ident_version: u8,
    pub osabi: u8,
    pub abiver: u8,
    pub pad: [u8; 7],
    pub ty: u16,
    pub machine: u16,
    pub version: u32,
    pub entry: u64,
    pub phoff: u64,
    pub shoff: u64,
    pub flags: u32,
    pub ehsize: u16,
    pub phentsize: u16,
    pub phnum: u16,
    pub shentsize: u16,
    pub shnum: u16,
    pub shstrndx: u16,
}

impl Default for Ehdr {
    fn default() -> Self {
        Self {
            magic: [0x7f, b'E', b'L', b'F'],
            class: 2,
            data: 1,
            ident_version: 1,
            osabi: 0,
            abiver: 0,
            pad: [0; 7],
            ty: ET_EXEC,
            machine: EM_X86_64,
            version: 1,
            entry: 0x400080,
            phoff: EHDR_SIZE as u64,
            shoff: 0,
            flags: 0,
            ehsize: EHDR_SIZE as u16,
            phentsize: PHDR_SIZE as u16,
            phnum: 0,
            shentsize: SHDR_SIZE as u16,
            shnum: 0,
            shstrndx: 0,
        }
    }
}

impl Ehdr {
    pub fn exec64() -> Self {
        Self::default()
    }

    pub fn phnum(mut self, value: u16) -> Self {
        self.phnum = value;
        self
    }

    pub fn magic(mut self, value: [u8; 4]) -> Self {
        self.magic = value;
        self
    }

    pub fn class(mut self, value: u8) -> Self {
        self.class = value;
        self
    }

    pub fn data(mut self, value: u8) -> Self {
        self.data = value;
        self
    }

    pub fn ident_version(mut self, value: u8) -> Self {
        self.ident_version = value;
        self
    }

    pub fn ty(mut self, value: u16) -> Self {
        self.ty = value;
        self
    }

    pub fn machine(mut self, value: u16) -> Self {
        self.machine = value;
        self
    }

    pub fn version(mut self, value: u32) -> Self {
        self.version = value;
        self
    }

    pub fn entry(mut self, value: u64) -> Self {
        self.entry = value;
        self
    }

    pub fn phoff(mut self, value: u64) -> Self {
        self.phoff = value;
        self
    }

    pub fn shoff(mut self, value: u64) -> Self {
        self.shoff = value;
        self
    }

    pub fn shnum(mut self, value: u16) -> Self {
        self.shnum = value;
        self
    }

    pub fn shstrndx(mut self, value: u16) -> Self {
        self.shstrndx = value;
        self
    }

    pub fn ehsize(mut self, value: u16) -> Self {
        self.ehsize = value;
        self
    }

    pub fn phentsize(mut self, value: u16) -> Self {
        self.phentsize = value;
        self
    }

    pub fn shentsize(mut self, value: u16) -> Self {
        self.shentsize = value;
        self
    }
}

#[derive(Clone, Copy, Default)]
pub struct Phdr {
    pub ty: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub paddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

impl Phdr {
    pub fn new(ty: u32) -> Self {
        Self {
            ty,
            ..Self::default()
        }
    }

    pub fn flags(mut self, value: u32) -> Self {
        self.flags = value;
        self
    }

    pub fn offset(mut self, value: u64) -> Self {
        self.offset = value;
        self
    }

    pub fn vaddr(mut self, value: u64) -> Self {
        self.vaddr = value;
        self
    }

    pub fn paddr(mut self, value: u64) -> Self {
        self.paddr = value;
        self
    }

    pub fn filesz(mut self, value: u64) -> Self {
        self.filesz = value;
        self
    }

    pub fn memsz(mut self, value: u64) -> Self {
        self.memsz = value;
        self
    }

    pub fn align(mut self, value: u64) -> Self {
        self.align = value;
        self
    }
}

#[derive(Clone, Copy, Default)]
pub struct Shdr {
    pub name: u32,
    pub ty: u32,
    pub flags: u64,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub info: u32,
    pub addralign: u64,
    pub entsize: u64,
}

impl Shdr {
    pub fn null() -> Self {
        Self::default()
    }

    pub fn new(ty: u32) -> Self {
        Self {
            ty,
            ..Self::default()
        }
    }

    pub fn name(mut self, value: u32) -> Self {
        self.name = value;
        self
    }

    pub fn offset(mut self, value: u64) -> Self {
        self.offset = value;
        self
    }

    pub fn flags(mut self, value: u64) -> Self {
        self.flags = value;
        self
    }

    pub fn addr(mut self, value: u64) -> Self {
        self.addr = value;
        self
    }

    pub fn size(mut self, value: u64) -> Self {
        self.size = value;
        self
    }

    pub fn link(mut self, value: u32) -> Self {
        self.link = value;
        self
    }

    pub fn info(mut self, value: u32) -> Self {
        self.info = value;
        self
    }

    pub fn addralign(mut self, value: u64) -> Self {
        self.addralign = value;
        self
    }

    pub fn entsize(mut self, value: u64) -> Self {
        self.entsize = value;
        self
    }
}

#[derive(Clone, Copy)]
pub struct Dyn {
    pub tag: i64,
    pub value: u64,
}

impl Dyn {
    pub fn new(tag: i64, value: u64) -> Self {
        Self { tag, value }
    }

    pub fn to_bytes(self) -> [u8; 16] {
        let mut bytes = [0; 16];
        bytes[0..8].copy_from_slice(&self.tag.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.value.to_le_bytes());
        bytes
    }
}

pub fn dyn_bytes(entries: &[Dyn]) -> Vec<u8> {
    entries.iter().flat_map(|entry| entry.to_bytes()).collect()
}

pub fn le16(value: u16) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

pub fn le32(value: u32) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

pub fn le64(value: u64) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}
