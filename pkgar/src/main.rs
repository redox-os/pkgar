use clap::{crate_authors, crate_description, crate_name, crate_version};
use clap::{Arg, ArgAction, Command};
use pkgar::{create_with_flags, extract, list, remove, replace, split, verify, Error};
use pkgar_keys::{DEFAULT_PUBKEY, DEFAULT_SECKEY};

fn cli() -> Result<(), Error> {
    let (default_pkey, default_skey) = (DEFAULT_PUBKEY.as_os_str(), DEFAULT_SECKEY.as_os_str());

    let help_pkey = format!("Public key file (defaults to '{}')", default_pkey.display());
    let help_skey = format!("Secret key file (defaults to '{}')", default_skey.display());

    let arg_pkey = Arg::new("pkey")
        .help(help_pkey)
        .short('p')
        .long("pkey")
        .required(true)
        .value_name("FILE")
        .default_value(default_pkey);

    let arg_skey = Arg::new("skey")
        .help(help_skey)
        .short('s')
        .long("skey")
        .required(true)
        .value_name("FILE")
        .default_value(default_skey);

    let arg_archive = Arg::new("archive")
        .help("Archive file")
        .short('a')
        .long("archive")
        .required(true)
        .value_name("FILE");

    let arg_old_pkey = Arg::new("old-pkey")
        .help("Old Public key file (defaults to old pkey)")
        .long("old-pkey")
        .value_name("FILE");

    let arg_old_archive = Arg::new("old-archive")
        .help("Old Archive file")
        .long("old-archive")
        .value_name("FILE");

    let arg_basedir = Arg::new("basedir")
        .help("Directory to unpack to (defaults to '.')")
        .required(true)
        .value_name("DIR")
        .default_value(".");

    let arg_compress = Arg::new("compress")
        .help("Enable compression for the archive")
        .short('c')
        .long("compress")
        .action(ArgAction::SetTrue);

    let matches = Command::new(crate_name!())
        .author(crate_authors!(", "))
        .about(crate_description!())
        .version(crate_version!())
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("create")
                .about("Create archive")
                .arg(&arg_skey)
                .arg(&arg_archive)
                .arg(&arg_basedir)
                .arg(&arg_compress),
        )
        .subcommand(
            Command::new("extract")
                .about("Extract archive")
                .arg(&arg_pkey)
                .arg(&arg_archive)
                .arg(&arg_basedir),
        )
        .subcommand(
            Command::new("list")
                .about("List archive")
                .arg(&arg_pkey)
                .arg(&arg_archive),
        )
        .subcommand(
            Command::new("replace")
                .about("Replace old archive")
                .arg(&arg_pkey)
                .arg(&arg_old_pkey)
                .arg(&arg_old_archive)
                .arg(&arg_archive)
                .arg(&arg_basedir),
        )
        .subcommand(
            Command::new("remove")
                .about("Unextract archive")
                .arg(&arg_pkey)
                .arg(&arg_archive)
                .arg(&arg_basedir),
        )
        .subcommand(
            Command::new("split")
                .about("Split archive into head and data files")
                .arg(&arg_pkey)
                .arg(&arg_archive)
                .arg(
                    Arg::new("head")
                        .help("Header file")
                        .required(true)
                        .value_name("head"),
                )
                .arg(Arg::new("data").help("Data file").value_name("data")),
        )
        .subcommand(
            Command::new("verify")
                .about("Verify archive")
                .arg(&arg_pkey)
                .arg(&arg_archive)
                .arg(&arg_basedir),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("create", sub_matches)) => create_with_flags(
            sub_matches.get_one::<String>("skey").unwrap().as_str(),
            sub_matches.get_one::<String>("archive").unwrap().as_str(),
            sub_matches.get_one::<String>("basedir").unwrap().as_str(),
            pkgar_core::HeaderFlags::latest(
                pkgar_core::Architecture::Independent,
                match sub_matches.get_flag("compress") {
                    true => pkgar_core::Packaging::LZMA2,
                    false => pkgar_core::Packaging::Uncompressed,
                },
            ),
        ),
        Some(("extract", sub_matches)) => extract(
            sub_matches.get_one::<String>("pkey").unwrap().as_str(),
            sub_matches.get_one::<String>("archive").unwrap().as_str(),
            sub_matches.get_one::<String>("basedir").unwrap().as_str(),
        ),
        Some(("replace", sub_matches)) => {
            let Some(old_archive) = sub_matches.get_one::<String>("old-archive") else {
                return Err(Error::DataNotInitialized);
            };
            let old_pkey = sub_matches
                .get_one::<String>("old-pkey")
                .unwrap_or_else(|| sub_matches.get_one::<String>("pkey").unwrap());

            replace(
                old_pkey.as_str(),
                sub_matches.get_one::<String>("pkey").unwrap().as_str(),
                old_archive.as_str(),
                sub_matches.get_one::<String>("archive").unwrap().as_str(),
                sub_matches.get_one::<String>("basedir").unwrap().as_str(),
            )
        }
        Some(("remove", sub_matches)) => remove(
            sub_matches.get_one::<String>("pkey").unwrap().as_str(),
            sub_matches.get_one::<String>("archive").unwrap().as_str(),
            sub_matches.get_one::<String>("basedir").unwrap().as_str(),
        ),
        Some(("list", sub_matches)) => list(
            sub_matches.get_one::<String>("pkey").unwrap().as_str(),
            sub_matches.get_one::<String>("archive").unwrap().as_str(),
        ),
        Some(("split", sub_matches)) => split(
            sub_matches.get_one::<String>("pkey").unwrap().as_str(),
            sub_matches.get_one::<String>("archive").unwrap().as_str(),
            sub_matches.get_one::<String>("head").unwrap().as_str(),
            sub_matches.get_one::<String>("data").map(|s| s.as_str()),
        ),
        Some(("verify", sub_matches)) => verify(
            sub_matches.get_one::<String>("pkey").unwrap().as_str(),
            sub_matches.get_one::<String>("archive").unwrap().as_str(),
            sub_matches.get_one::<String>("basedir").unwrap().as_str(),
        ),
        _ => Ok(()),
    }
}

fn main() {
    cli().unwrap_or_else(|err| {
        eprintln!("error: {err}");
        std::process::exit(1);
    });
}
