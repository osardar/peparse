pub const IMAGE_FILE_MACHINE_I386: usize = 0x014c;
pub const IMAGE_FILE_MACHINE_IA64: usize = 0x0200;
pub const IMAGE_FILE_MACHINE_AMD64: usize = 0x8664;

pub const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10b;
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20b;
pub const IMAGE_ROM_OPTIONAL_HDR_MAGIC: u16 = 0x107;

pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize           = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize           = 1;
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize         = 2;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize        = 3;
pub const IMAGE_DIRECTORY_ENTRY_SECURITY: usize         = 4;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize        = 5;
pub const IMAGE_DIRECTORY_ENTRY_DEBUG: usize            = 6;
pub const IMAGE_DIRECTORY_ENTRY_COPYRIGHT: usize        = 7;
pub const IMAGE_DIRECTORY_ENTRY_GLOBALPTR: usize        = 8 ;
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize              = 9;
pub const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: usize      = 10;
pub const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: usize     = 11;
pub const IMAGE_DIRECTORY_ENTRY_IAT: usize              = 12 ;
pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize     = 13;
pub const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize   = 14;