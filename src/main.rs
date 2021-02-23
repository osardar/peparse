mod cli;
mod pe;

use std::fs::File;
use std::io::prelude::*;

use peparse;

fn main() {
    println!("peparse");
    let matches = cli::build_cli();
    let matches = matches.unwrap_or_else(|e| e.exit());
    cli::dump_args(&matches);
    
    let fname = matches.value_of("in_file").unwrap();
    let mut fdata = peparse::fopen_read(fname);
    println!("fdata: {:?}", &fdata[..3]);

    peparse::parse(&mut fdata[..]);

    // sub in struct parsing call here
    /*
    if s_imgdosheader.validate() {
        println!("Valid PE");
    } else {
        println!("Invalid PE");
    }
    */
}
