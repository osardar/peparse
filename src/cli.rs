use clap::{Arg, ArgMatches, App};

pub fn build_cli() -> clap::Result<ArgMatches<'static>> {
    App::new(String::from("peparse"))
            .version("0.1")
            .author("@osardar1")
            .about("Parse PE files")
            .arg(Arg::with_name("in_file")
                .required(true)
                .value_name("IN_FILE")
                .help("Input PE file")
                .takes_value(true))
            .get_matches_safe()
}

pub fn dump_args(matches: &ArgMatches) {
    let filename = matches.value_of("in_file").unwrap_or("Unspecified");
    println!("- File: {}", filename);
}