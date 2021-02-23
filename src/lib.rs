mod pe;
mod pe_const;

use std::io::Read;
use std::fs::File;
use std::process;
use std::mem;

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

    let s_ImgOptionalHeader: pe::ImageOptionalHeaderStub = unsafe { mem::zeroed() };
    if s_ImgNtHeaders.OptionalHeaderStub.Magic == pe_const::IMAGE_NT_OPTIONAL_HDR32_MAGIC {
        let s_ImgOptionalHeader: pe::ImageOptionalHeader32 = pe::ImageOptionalHeader32::new(&mut fdata[offset..]);
        offset += mem::size_of::<pe::ImageOptionalHeader32>();
    } else if s_ImgNtHeaders.OptionalHeaderStub.Magic == pe_const::IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        let s_ImgOptionalHeader: pe::ImageOptionalHeader64 = pe::ImageOptionalHeader64::new(&mut fdata[offset..]);
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

    for i in 0..=n_sections {
        let s_ImgSectionHeader: pe::ImageSectionHeader = pe::ImageSectionHeader::new(&mut fdata[offset..]);
        println!("* Section Name: {:?}", s_ImgSectionHeader.Name);
        offset += mem::size_of::<pe::ImageSectionHeader>();
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
