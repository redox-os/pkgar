use std::fs;
use std::io;
use std::path::PathBuf;
use std::process;

use anyhow::{Context, Result};
use clap::clap_app;

use pkgar_keys::{
    gen_keypair, get_skey, re_encrypt, Error, SecretKeyFile, DEFAULT_PUBKEY, DEFAULT_SECKEY,
};

fn cli() -> Result<i32> {
    let matches = clap_app!(("pkgar-keys") =>
        (author: "Wesley Hershberger <mggmugginsmc@gmail.com>")
        (about: "NaCl key management for pkgar")
        (@arg skey: -s --skey [FILE] +global "Alternate secret keyfile (defaults to '~/.pkgar/keys/id_ed25519.toml')")
        (@setting SubcommandRequired)
        (@subcommand gen =>
            (about: "Generate a keypair and store on the filesystem")
            (@arg pkey: -p --pkey [FILE]
                "Alternate public keyfile (defaults to `~/.pkgar/keys/id_ed25519.pub.toml`)")
            (@arg plaintext:  -P --plaintext
                "Do not prompt for a passphrase and store the secret key as plain text")
            (@arg force:      -f --force
                "Don't check for existing files before generating a new keypair")
        )
        (@subcommand rencrypt =>
            (about: "Re-encrypt the secret key provided by --skey")
        )
        (@subcommand export =>
            (about: "Print the public key corresponding to the key given with --skey in the pkgar pubkey format")
            (@arg file: -f --file [FILE] "Output to a file instead of stdout")
        )
    ).get_matches();

    let skey_path = matches
        .value_of("skey")
        .map(PathBuf::from)
        .unwrap_or(DEFAULT_SECKEY.clone());

    let (subcommand, submatches) = matches.subcommand();
    let submatches = submatches.expect("A subcommand should have been provided");

    match subcommand {
        "gen" => {
            if let Some(keydir) = skey_path.parent() {
                fs::create_dir_all(keydir).with_context(|| keydir.display().to_string())?;
            }

            if !submatches.is_present("force") && skey_path.exists() {
                return Err(Error::Io(io::Error::from(io::ErrorKind::AlreadyExists)))
                    .with_context(|| skey_path.display().to_string());
            }

            let pkey_path = submatches
                .value_of("pkey")
                .map(PathBuf::from)
                .unwrap_or(DEFAULT_PUBKEY.clone());

            if !submatches.is_present("plaintext") {
                gen_keypair(&pkey_path, &skey_path)?;
            } else {
                let (pkey, skey) = SecretKeyFile::new();
                pkey.save(&pkey_path)?;
                skey.save(&skey_path)?;
            }
        }
        "export" => {
            let skey = get_skey(&skey_path)?;
            let pkey = skey
                .public_key_file()
                .expect("Secret key was encrypted after being decrypted");

            if let Some(file) = submatches.value_of("file") {
                pkey.save(file)?;
            } else {
                pkey.write(io::stdout().lock()).context("stdout")?;
            }
        }
        "rencrypt" => {
            re_encrypt(&skey_path)?;
            println!("Successfully re-encrypted {}", skey_path.display());
        }
        _ => unreachable!(),
    }

    Ok(0)
}

#[cfg(feature = "cli")]
fn main() {
    let code = cli().unwrap_or_else(|err| {
        eprintln!("{err:?}");
        process::exit(1);
    });
    process::exit(code);
}
