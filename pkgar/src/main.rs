//TODO: update clap to remove the need for this
#![allow(dangerous_implicit_autorefs)]

use clap::{
    crate_authors, crate_description, crate_name, crate_version, App, AppSettings, Arg, SubCommand,
};
use pkgar::{create, extract, list, remove, split, verify};
use pkgar_keys::{DEFAULT_PUBKEY, DEFAULT_SECKEY};

fn main() -> anyhow::Result<()> {
    let (default_pkey, default_skey) = (
        DEFAULT_PUBKEY.to_string_lossy(),
        DEFAULT_SECKEY.to_string_lossy(),
    );

    let help_pkey = format!("Public key file (defaults to '{}')", &default_pkey);
    let help_skey = format!("Secret key file (defaults to '{}')", &default_skey);

    let arg_pkey = Arg::with_name("pkey")
        .help(&help_pkey)
        .short("p")
        .long("pkey")
        .required(true)
        .takes_value(true)
        .value_name("FILE")
        .default_value(&default_pkey);

    let arg_skey = Arg::with_name("skey")
        .help(&help_skey)
        .short("s")
        .long("skey")
        .required(true)
        .takes_value(true)
        .value_name("FILE")
        .default_value(&default_skey);

    let arg_archive = Arg::with_name("archive")
        .help("Archive file")
        .short("a")
        .long("archive")
        .required(true)
        .takes_value(true)
        .value_name("FILE");

    let arg_basedir = Arg::with_name("basedir")
        .help("Directory to unpack to (defaults to '.')")
        .required(true)
        .value_name("DIR")
        .default_value(".");

    let matches = App::new(crate_name!())
        .author(crate_authors!(", "))
        .about(crate_description!())
        .version(crate_version!())
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommand(
            SubCommand::with_name("create")
                .about("Create archive")
                .arg(&arg_skey)
                .arg(&arg_archive)
                .arg(&arg_basedir),
        )
        .subcommand(
            SubCommand::with_name("extract")
                .about("Extract archive")
                .arg(&arg_pkey)
                .arg(&arg_archive)
                .arg(&arg_basedir),
        )
        .subcommand(
            SubCommand::with_name("list")
                .about("List archive")
                .arg(&arg_pkey)
                .arg(&arg_archive),
        )
        .subcommand(
            SubCommand::with_name("remove")
                .about("Unextract archive")
                .arg(&arg_pkey)
                .arg(&arg_archive)
                .arg(&arg_basedir),
        )
        .subcommand(
            SubCommand::with_name("split")
                .about("Split archive into head and data files")
                .arg(&arg_pkey)
                .arg(&arg_archive)
                .arg(
                    Arg::with_name("head")
                        .help("Header file")
                        .required(true)
                        .value_name("head"),
                )
                .arg(Arg::with_name("data").help("Data file").value_name("data")),
        )
        .subcommand(
            SubCommand::with_name("verify")
                .about("Verify archive")
                .arg(&arg_pkey)
                .arg(&arg_archive)
                .arg(&arg_basedir),
        )
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("create") {
        create(
            matches.value_of("skey").unwrap(),
            matches.value_of("archive").unwrap(),
            matches.value_of("basedir").unwrap(),
        )
    } else if let Some(matches) = matches.subcommand_matches("extract") {
        extract(
            matches.value_of("pkey").unwrap(),
            matches.value_of("archive").unwrap(),
            matches.value_of("basedir").unwrap(),
        )
    } else if let Some(matches) = matches.subcommand_matches("remove") {
        remove(
            matches.value_of("pkey").unwrap(),
            matches.value_of("archive").unwrap(),
            matches.value_of("basedir").unwrap(),
        )
    } else if let Some(matches) = matches.subcommand_matches("list") {
        list(
            matches.value_of("pkey").unwrap(),
            matches.value_of("archive").unwrap(),
        )
        .map_err(anyhow::Error::new)
    } else if let Some(matches) = matches.subcommand_matches("split") {
        split(
            matches.value_of("pkey").unwrap(),
            matches.value_of("archive").unwrap(),
            matches.value_of("head").unwrap(),
            matches.value_of("data"),
        )
    } else if let Some(matches) = matches.subcommand_matches("verify") {
        verify(
            matches.value_of("pkey").unwrap(),
            matches.value_of("archive").unwrap(),
            matches.value_of("basedir").unwrap(),
        )
        .map_err(anyhow::Error::new)
    } else {
        Ok(())
    }
}
