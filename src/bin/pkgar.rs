use clap::{App, AppSettings, Arg, SubCommand};
use pkgar::bin::{
    create,
    extract,
    keygen,
    list,
};
use std::process;

fn main() {
    let matches = App::new("pkgar")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommand(SubCommand::with_name("create")
            .about("Create archive")
            .arg(Arg::with_name("secret")
                .help("Secret key")
                .short("s")
                .long("secret")
                .required(true)
                .takes_value(true)
            )
            .arg(Arg::with_name("file")
                .help("Archive file")
                .short("f")
                .long("file")
                .required(true)
                .takes_value(true)
            )
            .arg(Arg::with_name("folder")
                .help("Folder to archive, defaults to \".\"")
                .required(true)
                .default_value(".")
            )
        )
        .subcommand(SubCommand::with_name("extract")
            .about("Extract archive")
            .arg(Arg::with_name("public")
                .help("Public key")
                .short("p")
                .long("public")
                .required(true)
                .takes_value(true)
            )
            .arg(Arg::with_name("file")
                .help("Archive file")
                .short("f")
                .long("file")
                .required(true)
                .takes_value(true)
            )
            .arg(Arg::with_name("folder")
                .help("Folder to archive, defaults to \".\"")
                .required(true)
                .default_value(".")
            )
        )
        .subcommand(SubCommand::with_name("keygen")
            .about("Generate keys")
            .arg(Arg::with_name("secret")
                .help("Secret key")
                .short("s")
                .long("secret")
                .required(true)
                .takes_value(true)
            )
            .arg(Arg::with_name("public")
                .help("Public key")
                .short("p")
                .long("public")
                .required(true)
                .takes_value(true)
            )
        )
        .subcommand(SubCommand::with_name("list")
            .about("List archive")
            .arg(Arg::with_name("public")
                .help("Public key")
                .short("p")
                .long("public")
                .required(true)
                .takes_value(true)
            )
            .arg(Arg::with_name("file")
                .help("Archive file")
                .short("f")
                .long("file")
                .required(true)
                .takes_value(true)
            )
        )
        .get_matches();

    let res = if let Some(matches) = matches.subcommand_matches("create") {
        create(
            matches.value_of("secret").unwrap(),
            matches.value_of("file").unwrap(),
            matches.value_of("folder").unwrap()
        )
    } else if let Some(matches) = matches.subcommand_matches("extract") {
        extract(
            matches.value_of("public").unwrap(),
            matches.value_of("file").unwrap(),
            matches.value_of("folder").unwrap()
        )
    } else if let Some(matches) = matches.subcommand_matches("keygen") {
        keygen(
            matches.value_of("secret").unwrap(),
            matches.value_of("public").unwrap(),
        )
    } else if let Some(matches) = matches.subcommand_matches("list") {
        list(
            matches.value_of("public").unwrap(),
            matches.value_of("file").unwrap()
        )
    } else {
        Ok(())
    };

    match res {
        Ok(()) => (),
        Err(err) => {
            eprintln!("pkgar error: {:?}", err);
            process::exit(1);
        }
    }
}
