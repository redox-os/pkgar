use clap::{App, AppSettings, Arg, SubCommand};
use pkgar::{Header, PackedEntry, PackedHeader, PublicKey, SecretKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::convert::TryFrom;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

fn folder_entries<P, Q>(base: P, path: Q, entries: &mut Vec<PackedEntry>) -> io::Result<()>
    where P: AsRef<Path>, Q: AsRef<Path>
{
    let base = base.as_ref();
    let path = path.as_ref();

    // Sort each folder's entries by the file name
    let mut read_dir = Vec::new();
    for entry_res in fs::read_dir(path)? {
        read_dir.push(entry_res?);
    }
    read_dir.sort_by(|a, b| a.file_name().cmp(&b.file_name()));

    for entry in read_dir {
        let metadata = entry.metadata()?;
        let entry_path = entry.path();
        if metadata.is_dir() {
            folder_entries(base, entry_path, entries)?;
        } else {
            let relative = entry_path.strip_prefix(base).map_err(|err| {
                io::Error::new(
                    io::ErrorKind::Other,
                    err
                )
            })?;

            let mut path_bytes = [0; 256];
            let relative_bytes = relative.as_os_str().as_bytes();
            if relative_bytes.len() >= path_bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "relative path longer than supported"
                ));
            }
            path_bytes[..relative_bytes.len()].copy_from_slice(relative_bytes);

            entries.push(PackedEntry {
                sha256: [0; 32],
                offset: 0,
                size: metadata.len(),
                mode: metadata.permissions().mode(),
                path: path_bytes,
            });
        }
    }

    Ok(())
}

fn create(secret_path: &str, archive_path: &str, folder: &str) {
    let secret_key = {
        let mut data = [0; 64];
        fs::OpenOptions::new()
            .read(true)
            .open(secret_path)
            .expect("failed to open secret key file")
            .read_exact(&mut data)
            .expect("failed to read secret key file");
        SecretKey::from_data(data)
    };

    println!("create {} from {}", archive_path, folder);

    //TODO: move functions to library

    let mut archive_file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o400)
        .open(archive_path)
        .expect("failed to create archive file");

    // Create a list of entries
    let mut entries = Vec::new();
    folder_entries(folder, folder, &mut entries)
        .expect("failed to read folder");

    // Create initial header
    let mut header = PackedHeader {
        signature: [0; 64],
        public_key: secret_key.public_key().into_data(),
        sha256: [0; 32],
        count: entries.len() as u64
    };

    // Assign offsets to each entry
    let mut data_size: u64 = 0;
    for entry in &mut entries {
        entry.offset = data_size;
        data_size = data_size.checked_add(entry.size)
            .expect("overflow when calculating entry offset");

        println!("{}: {:?}", { entry.offset }, ::std::str::from_utf8(entry.path()));
    }

    // Seek to data offset
    let data_offset = header.size()
        .expect("overflow when calculating data offset");
    archive_file.seek(SeekFrom::Start(data_offset as u64))
        .expect("failed to seek to data offset");
    //TODO: fallocate data_offset + data_size

    // Stream each file, writing data and calculating shasums
    let mut header_hasher = Sha256::new();
    let mut buf = vec![0; 4 * 1024 * 1024];
    for entry in &mut entries {
        let relative = Path::new(OsStr::from_bytes(entry.path()));
        let path = Path::new(folder).join(relative);
        let mut entry_file = fs::OpenOptions::new()
            .read(true)
            .open(path)
            .expect("failed to open entry file");

        let mut hasher = Sha256::new();
        loop {
            let count = entry_file.read(&mut buf)
                .expect("failed to read entry file");
            if count == 0 {
                break;
            }
            //TODO: Progress
            archive_file.write_all(&buf[..count])
                .expect("failed to write entry data");
            hasher.input(&buf[..count]);
        }
        entry.sha256.copy_from_slice(hasher.result().as_slice());

        header_hasher.input(unsafe {
            plain::as_bytes(entry)
        });
    }
    header.sha256.copy_from_slice(header_hasher.result().as_slice());

    // Calculate signature
    let unsigned = header.clone();
    sodalite::sign_attached(
        unsafe { plain::as_mut_bytes(&mut header) },
        unsafe { &plain::as_bytes(&unsigned)[64..] },
        secret_key.as_data()
    );

    // Write archive header
    archive_file.seek(SeekFrom::Start(0))
        .expect("failed to seek to start");
    archive_file.write_all(unsafe {
        plain::as_bytes(&header)
    }).expect("failed to write header");

    // Write each entry header
    for entry in &entries {
        archive_file.write_all(unsafe {
            plain::as_bytes(entry)
        }).expect("failed to write entry header");
    }
}

fn extract(public_path: &str, archive_path: &str, folder: &str) {
    let public_key = {
        let mut data = [0; 32];
        fs::OpenOptions::new()
            .read(true)
            .open(public_path)
            .expect("failed to open public key file")
            .read_exact(&mut data)
            .expect("failed to read public key file");
        PublicKey::from_data(data)
    };

    println!("extract {} to {}", archive_path, folder);

    //TODO: read just header
    let data = fs::read(archive_path)
        .expect("failed to read archive file");

    let header = Header::new(&data, &public_key)
        .expect("failed to parse header");

    let data_offset = header.header.size()
        .expect("overflow when calculating data offset");

    for entry in header.entries {
        let relative = Path::new(OsStr::from_bytes(entry.path()));
        let path = Path::new(folder).join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .expect("failed to create entry parent directory");
        }

        let mut entry_file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(entry.mode)
            .open(path)
            .expect("failed to create entry file");

        let start = data_offset.checked_add(entry.offset)
            .and_then(|x| usize::try_from(x).ok())
            .expect("overflow when calculating entry start");
        let end = usize::try_from(entry.size).ok()
            .and_then(|x| x.checked_add(start))
            .expect("overflow when calculating entry end");
        let entry_data = data.get(start..end)
            .expect("failed to find entry data");
        entry_file.write_all(&entry_data)
            .expect("failed to write entry file");
    }
}

fn keygen(secret_path: &str, public_path: &str) {
    let secret_key = SecretKey::new(&mut OsRng)
        .expect("failed to generate secret key");
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o400)
        .open(secret_path)
        .expect("failed to create secret key file")
        .write_all(secret_key.as_data())
        .expect("failed to write secret key file");

    let public_key = secret_key.public_key();
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o400)
        .open(public_path)
        .expect("failed to create public key file")
        .write_all(public_key.as_data())
        .expect("failed to write public key file");
}

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
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("create") {
        create(
            matches.value_of("secret").unwrap(),
            matches.value_of("file").unwrap(),
            matches.value_of("folder").unwrap()
        );
    } else if let Some(matches) = matches.subcommand_matches("extract") {
        extract(
            matches.value_of("public").unwrap(),
            matches.value_of("file").unwrap(),
            matches.value_of("folder").unwrap()
        );
    } else if let Some(matches) = matches.subcommand_matches("keygen") {
        keygen(
            matches.value_of("secret").unwrap(),
            matches.value_of("public").unwrap(),
        );
    }
}
