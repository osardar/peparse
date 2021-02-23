#![allow(non_snake_case)]
#[allow(non_camel_case_types)]

use std::mem;
use std::slice;
use std::io::Read;

const IMAGE_SIZEOF_SHORT_NAME: usize = 8;

#[derive(Debug)]
#[repr(C, packed)]
pub struct ImageDosHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: u32,
}

impl NewHeader for ImageDosHeader {}

impl ImageDosHeader {
    pub fn validate(&self) -> bool {
        if self.e_magic == 0x5A4D {
            return true;
        }
        false
    }
}

#[derive(Debug)]
#[repr(C, packed)]
pub struct ImageNtHeaders {
    pub Signature: u32,
    pub FileHeader: ImageFileHeader,
    pub OptionalHeaderStub: ImageOptionalHeaderStub,
}

impl NewHeader for ImageNtHeaders {}

#[derive(Debug)]
#[repr(C, packed)]
pub struct ImageOptionalHeader32 {
    pub Magic: u16,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub BaseOfData: u32,
    pub ImageBase: u32,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: u16,
    pub DllCharacteristics: u16,
    pub SizeOfStackReserve: u32,
    pub SizeOfStackCommit: u32,
    pub SizeOfHeapReserve: u32,
    pub SizeOfHeapCommit: u32,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [ImageDataDirectory; 16],
}

impl NewHeader for ImageOptionalHeader32 {}

#[derive(Debug)]
#[repr(C, packed)]
pub struct ImageOptionalHeader64 {
    pub Magic: u16,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub ImageBase: u64,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: u16,
    pub DllCharacteristics: u16,
    pub SizeOfStackReserve: u64,
    pub SizeOfStackCommit: u64,
    pub SizeOfHeapReserve: u64,
    pub SizeOfHeapCommit: u64,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [ImageDataDirectory; 16],
}

impl NewHeader for ImageOptionalHeader64 {}

#[derive(Debug)]
#[repr(C, packed)]
pub struct ImageOptionalHeaderStub {
    pub Magic: u16,
}

#[derive(Debug)]
#[repr(C, packed)]
pub struct ImageFileHeader {
    pub Machine: u16,
    pub NumberOfSections: u16,
    pub TimeDateStamp: u32,
    pub PointerToSymbolTable: u32,
    pub NumberOfSymbols: u32,
    pub SizeOfOptionalHeader: u16,
    pub Characteristics: u16,
}

impl NewHeader for ImageFileHeader {}

#[derive(Debug)]
#[repr(C, packed)]
pub struct ImageDataDirectory {
    pub VirtualAddress: u32,
    pub Size: u32,
}

impl NewHeader for ImageDataDirectory {}

#[repr(C, packed)]
pub union ImageSectionHeaderMisc{
    pub PhysicalAddress: u32,
    pub VirtualSize: u32,
}

#[repr(C, packed)]
pub struct ImageSectionHeader {
    pub Name: [u8; IMAGE_SIZEOF_SHORT_NAME],
    pub Misc: ImageSectionHeaderMisc,
    pub VirtualAddress: u32,
    pub SizeOfRawData: u32,
    pub PointerToRawData: u32,
    pub PointerToRelocations: u32,
    pub PointerToLinenumbers: u32,
    pub NumberOfRelocations: u16,
    pub NumberOfLinenumbers: u16,
    pub Characteristics: u32,
}

impl NewHeader for ImageSectionHeader {}


pub trait NewHeader {
    fn new<T>(fdata: &mut [u8]) -> T {
        let mut s: T = unsafe { mem::zeroed() };
        let len = mem::size_of::<T>();
    
        unsafe {
            let data_slice = slice::from_raw_parts_mut(&mut s as *mut _ as *mut u8, len);
            (&fdata[..]).read_exact(data_slice).unwrap();
        }

        s
    }
}