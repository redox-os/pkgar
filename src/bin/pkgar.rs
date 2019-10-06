use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use pkgar::Header;

fn create<'a, I: Iterator<Item = &'a str>>(key: &str, files: I) {
    println!("key: {}", key);
    for file in files {
        println!("file: {}", file);
    }
}

fn main() {
    let matches = App::new("pkgar")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommand(SubCommand::with_name("create")
            .about("Create archive")
            .arg(Arg::with_name("key")
                .help("Private key")
                .short("k")
                .long("key")
                .required(true)
                .takes_value(true)
            )
            .arg(Arg::with_name("path")
                .help("Paths to archive")
                .multiple(true)
                .required(true)
            )
        )
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("create") {
        create(
            matches.value_of("key").unwrap(),
            matches.values_of("path").unwrap()
        );
    }
}
