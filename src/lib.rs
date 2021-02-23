mod pe;
mod pe_const;

use std::io::Read;
use std::fs::File;
use std::process;
use std::mem;
use std::str;

use crate::pe::NewHeader;

pub fn fopen_read(fname: &str) -> Vec<u8> {
    let mut fd = match File::open(fname) {
        Ok(fd) => fd,
        Err(err) => {
            println!("Error: {}", err);
            process::exit(0);
        },
    };

    let mut fdata: Vec<u8> = Vec::new();
    fd.read_to_end(&mut fdata);

    fdata
}

pub fn parse(fdata: &mut [u8]) -> Option<u8> {
    let mut offset = 0;
    let s_ImgDosHeader: pe::ImageDosHeader = pe::ImageDosHeader::new(&mut fdata[offset..]);
    println!("Magic ImgDosHeader: {:x}", s_ImgDosHeader.e_magic);

    offset += s_ImgDosHeader.e_lfanew as usize;
    let s_ImgNtHeaders: pe::ImageNtHeaders = pe::ImageNtHeaders::new(&mut fdata[offset..]);
    println!("Sig: NtHeaders {:x}", s_ImgNtHeaders.Signature);

    // Get arch to determine IMAGE_OPTIONAL_HEADER32 or 64
    offset += mem::size_of::<u32>(); // Skip past NtHeaders.Signature
    offset += mem::size_of::<pe::ImageFileHeader>();

    enum ImgOptionalHeaderEnum {
        Stub(pe::ImageOptionalHeaderStub),
        PE32(pe::ImageOptionalHeader32),
        PE64(pe::ImageOptionalHeader64),
    }

    let mut e_ImgOptionalHeader: ImgOptionalHeaderEnum = ImgOptionalHeaderEnum::Stub( unsafe { mem::zeroed() });


    let s_ImgOptionalHeader: pe::ImageOptionalHeaderStub = unsafe { mem::zeroed() };
    if s_ImgNtHeaders.OptionalHeaderStub.Magic == pe_const::IMAGE_NT_OPTIONAL_HDR32_MAGIC {
        e_ImgOptionalHeader = ImgOptionalHeaderEnum::PE32(pe::ImageOptionalHeader32::new(&mut fdata[offset..]));
        offset += mem::size_of::<pe::ImageOptionalHeader32>();
    } else if s_ImgNtHeaders.OptionalHeaderStub.Magic == pe_const::IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        e_ImgOptionalHeader = ImgOptionalHeaderEnum::PE64(pe::ImageOptionalHeader64::new(&mut fdata[offset..]));
        offset += mem::size_of::<pe::ImageOptionalHeader64>();
    } else {
        println!("Unrecognized OptionalHeader.Magic (arch)");
        process::exit(0);
    }

    let n_sections = s_ImgNtHeaders.FileHeader.NumberOfSections;
    println!("# Sections: {}", n_sections);
    println!("Magic OptHeader: {:x}", s_ImgOptionalHeader.Magic);
    println!("Offset: {:x}", offset);
    println!("Sizeof ImgNtHeaders: {:x}", mem::size_of::<pe::ImageNtHeaders>());

    // Dump section 
    let mut v_ImgSectionHeaders: Vec<pe::ImageSectionHeader> = Vec::new();
    for i in 0..n_sections as usize{
        v_ImgSectionHeaders.push(pe::ImageSectionHeader::new(&mut fdata[offset..]));
        println!("* Section Name: {:?}", str::from_utf8(&v_ImgSectionHeaders[i].Name));
        offset += mem::size_of::<pe::ImageSectionHeader>();
    }

    // Exports
    let s_ImgDirEntryExport: pe::ImageDataDirectory = match e_ImgOptionalHeader {
        ImgOptionalHeaderEnum::PE32(optheader32) => optheader32.DataDirectory[pe_const::IMAGE_DIRECTORY_ENTRY_EXPORT],
        ImgOptionalHeaderEnum::PE64(optheader64) => optheader64.DataDirectory[pe_const::IMAGE_DIRECTORY_ENTRY_EXPORT],
        ImgOptionalHeaderEnum::Stub(optstub) => {   
            println!("Invalid OptHeader type");
            process::exit(0);
        }
    };

    if s_ImgDirEntryExport.VirtualAddress & s_ImgDirEntryExport.Size == 0 {
        println!("No exports found");
    } else {
        println!("Exports found but not supported");
    }

    Some(0)
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
