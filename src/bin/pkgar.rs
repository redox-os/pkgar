use ansi_term::Colour::{Green, Yellow, Red};
use pkgar::{Entry, Error, Header, PublicKey, SecretKey};
use rand::rngs::OsRng;
use std::convert::TryFrom;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::mem;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path};

fn folder_entries<P, Q>(base: P, path: Q, entries: &mut Vec<Entry>) -> io::Result<()>
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

            entries.push(Entry {
                blake3: [0; 32],
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
        .open(archive_path)
        .expect("failed to create archive file");

    // Create a list of entries
    let mut entries = Vec::new();
    folder_entries(folder, folder, &mut entries)
        .expect("failed to read folder");

    // Create initial header
    let mut header = Header {
        signature: [0; 64],
        public_key: secret_key.public_key().into_data(),
        blake3: [0; 32],
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
    let data_offset = header.total_size()
        .expect("overflow when calculating data offset");
    archive_file.seek(SeekFrom::Start(data_offset as u64))
        .expect("failed to seek to data offset");
    //TODO: fallocate data_offset + data_size

    // Stream each file, writing data and calculating b3sums
    let mut header_hasher = blake3::Hasher::new();
    let mut buf = vec![0; 4 * 1024 * 1024];
    for entry in &mut entries {
        let relative = Path::new(OsStr::from_bytes(entry.path()));
        let path = Path::new(folder).join(relative);
        let mut entry_file = fs::OpenOptions::new()
            .read(true)
            .open(path)
            .expect("failed to open entry file");

        let mut hasher = blake3::Hasher::new();
        loop {
            let count = entry_file.read(&mut buf)
                .expect("failed to read entry file");
            if count == 0 {
                break;
            }
            //TODO: Progress
            archive_file.write_all(&buf[..count])
                .expect("failed to write entry data");
            hasher.update_with_join::<blake3::join::RayonJoin>(&buf[..count]);
        }
        entry.blake3.copy_from_slice(hasher.finalize().as_bytes());

        header_hasher.update_with_join::<blake3::join::RayonJoin>(unsafe {
            plain::as_bytes(entry)
        });
    }
    header.blake3.copy_from_slice(header_hasher.finalize().as_bytes());

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

    let mut archive_file = fs::OpenOptions::new()
        .read(true)
        .open(archive_path)
        .expect("failed to open archive file");

    // Read header first
    let mut header_data = [0; mem::size_of::<Header>()];
    archive_file.read_exact(&mut header_data)
        .expect("failed to read archive file");
    let header = Header::new(&header_data, &public_key)
        .expect("failed to parse header");

    // Read entries next
    let entries_size = header.entries_size()
        .and_then(|x| usize::try_from(x).map_err(Error::TryFromInt))
        .expect("overflow when calculating entries size");
    let mut entries_data = vec![0; entries_size];
    archive_file.read_exact(&mut entries_data)
        .expect("failed to read archive file");
    let entries = header.entries(&entries_data)
        .expect("failed to parse entries");

    // TODO: Validate that all entries can be installed, before installing

    let data_offset = header.total_size()
        .expect("overflow when calculating data offset");
    let folder_path = Path::new(folder);
    for entry in entries {
        let offset = data_offset.checked_add(entry.offset)
            .expect("overflow when calculating entry offset");
        archive_file.seek(SeekFrom::Start(offset))
            .expect("failed to seek to entry offset");

        // TODO: Do not read entire file into memory
        let size = usize::try_from(entry.size)
            .expect("overflow when calculating entry size");
        let mut data = vec![0; size];
        archive_file.read_exact(&mut data)
            .expect("failed to read entry data");

        let hash = {
            let mut hasher = blake3::Hasher::new();
            hasher.update_with_join::<blake3::join::RayonJoin>(&data);
            hasher.finalize()
        };

        if &entry.blake3 != hash.as_bytes() {
            panic!("failed to verify entry data");
        }

        let relative = Path::new(OsStr::from_bytes(entry.path()));
        for component in relative.components() {
            match component {
                Component::Normal(_) => (),
                invalid => panic!("entry path contains invalid component: {:?}", invalid),
            }
        }
        let entry_path = folder_path.join(relative);
        if ! entry_path.starts_with(&folder_path) {
            panic!("entry path escapes from folder");
        }
        if let Some(parent) = entry_path.parent() {
            fs::create_dir_all(parent)
                .expect("failed to create entry parent directory");
        }

        fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(entry.mode)
            .open(entry_path)
            .expect("failed to create entry file")
            .write_all(&data)
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

fn list(public_path: &str, archive_path: &str) {
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

    let mut archive_file = fs::OpenOptions::new()
        .read(true)
        .open(archive_path)
        .expect("failed to open archive file");

    // Read header first
    let mut header_data = [0; mem::size_of::<Header>()];
    archive_file.read_exact(&mut header_data)
        .expect("failed to read archive file");
    let header = Header::new(&header_data, &public_key)
        .expect("failed to parse header");

    // Read entries next
    let entries_size = header.entries_size()
        .and_then(|x| usize::try_from(x).map_err(Error::TryFromInt))
        .expect("overflow when calculating entries size");
    let mut entries_data = vec![0; entries_size];
    archive_file.read_exact(&mut entries_data)
        .expect("failed to read archive file");
    let entries = header.entries(&entries_data)
        .expect("failed to parse entries");

    for entry in entries {
        let relative = Path::new(OsStr::from_bytes(entry.path()));
        println!("{}", relative.display());
    }
}

fn help_print() {
    println!(
        "{} {}

{}
    pkgar <SUBCOMMAND>

{}
    {},{}       Prints help information
    {},{}    Prints version information

{}
    {}     Create archive
    {}    Extract archive
    {}       Prints this message or the help of the given subcommand(s)
    {}     Generate keys
    {}       List archive",
        Green.paint("pkgar"),
        env!("CARGO_PKG_VERSION"),
        Yellow.paint("USAGE:"),
        Yellow.paint("FLAGS:"),
        Green.paint("-h"),
        Green.paint("--help"),
        Green.paint("-V"),
        Green.paint("--version"),
        Yellow.paint("SUBCOMMANDS:"),
        Green.paint("create"),
        Green.paint("extract"),
        Green.paint("help"),
        Green.paint("keygen"),
        Green.paint("list"),
    );
}

fn version_print() {
    println!("pkgar {}", env!("CARGO_PKG_VERSION"))
}

#[derive(Debug)]
enum AppArgs {
    Flags {
        help: bool,
        version: bool
    },
    Create {
        secret: String,
        file: String,
        folder: Vec<String>
    },
    Extract {
        public: String,
        file: String,
        folder: Vec<String>
    },
    Keygen {
        public: String,
        secret: String,
    },
    List {
        public: String,
        file: String,
    }
}

fn main() {
    match submain() {
        AppArgs::Flags { help, version } => {
            if help {
                help_print();
            } else if version {
                version_print();
            } else {
                help_print();
            }
        },
        AppArgs::Create { file, secret, folder } => {
            if !folder.is_empty() {
                create(&secret, &file, &folder[0]);
            } else {
                create(&secret, &file, ".");
                }
        },
        AppArgs::Extract{public, file, folder} => {
            if !folder.is_empty() {
                extract(&public,  &file, &folder[0]);
            } else {
                extract(&public,  &file, ".");
            }
        },
        AppArgs::Keygen{public,secret} => {
            keygen(&secret, &public)
        },
        AppArgs::List{public,file} => {
            list(&public,  &file) 
        },
    }
}

fn submain() -> AppArgs {
    let mut args = pico_args::Arguments::from_env();

    let subcommand = match args.subcommand() {
        Ok(s) => s,
        Err(_) => {
            eprintln!("Error: Invalid subcommand.");
            std::process::exit(1);
        }
    };

    match subcommand.as_deref() {
        Some("create") => match parse_create(args) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("{} {}

{}
    pkgar create <folder> --file <file> --secret <secret>

For more information try {}", Red.paint("Error:"), e, Yellow.paint("USAGE:"), Green.paint("--help"));
                std::process::exit(1);
            }
        },
        Some("extract") => match parse_extract(args) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("{} {}

{}
    pkgar extract <folder> --file <file> --public <public>

For more information try {}", Red.paint("Error:"), e, Yellow.paint("USAGE:"), Green.paint("--help"));                
                std::process::exit(1);
            }
        },
        Some("keygen") => match parse_keygen(args) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("{} {}

{}
    pkgar keygen <folder> --secret <secret> --secret <secret>

For more information try {}", Red.paint("Error:"), e, Yellow.paint("USAGE:"), Green.paint("--help"));                
                std::process::exit(1);
            }
        },
        Some("list") => match parse_list(args) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("{} {}

{}
    pkgar list <folder> --public <public> --file <file>\n\n\

For more information try {}", Red.paint("Error:"), e, Yellow.paint("USAGE:"), Green.paint("--help"));                   
                std::process::exit(1);
            }
        },
        None => {
            match parse_flags(args) {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("{} {}

{}
pkgar {}", Red.paint("Error:"), e, Yellow.paint("USAGE:"), Green.paint("--help")); 
                    std::process::exit(1);
                }
            }
        }
        Some(s) => {
            eprintln!("Error: '{}' is an unknown subcommand.", s);
            std::process::exit(1);
        }
    }
}

// Determines how the create subcommand's arguements are parsed
fn parse_create(mut args: pico_args::Arguments) -> Result<AppArgs, pico_args::Error> {
    let app_args = AppArgs::Create {
        file: args.value_from_str("--file")?,
        secret: args.value_from_str("--secret")?,
        folder: args.free()?,
    };
    Ok(app_args)
}

// Determines how the extract subcommand's arguements are parsed
fn parse_extract(mut args: pico_args::Arguments) -> Result<AppArgs, pico_args::Error> {
    let app_args = AppArgs::Extract {
        file: args.value_from_str("--file")?,
        public: args.value_from_str("--public")?,
        folder: args.free()?,
    };
    Ok(app_args)
}

// Determines how the keygen subcommand's arguements are parsed
fn parse_keygen(mut args: pico_args::Arguments) -> Result<AppArgs, pico_args::Error> {
    let app_args = AppArgs::Keygen {
        public: args.value_from_str("--public")?,
        secret: args.value_from_str("--secret")?,
    };

    args.finish()?;
    Ok(app_args)
}

// Determines how the list subcommand's arguements are parsed
fn parse_list(mut args: pico_args::Arguments) -> Result<AppArgs, pico_args::Error> {
    let app_args = AppArgs::List {
        file: args.value_from_str("--file")?,
            public: args.value_from_str("--secret")?,
    };

    args.finish()?;
    Ok(app_args)
}

// Determines how the flags are parsed
fn parse_flags(mut args: pico_args::Arguments) -> Result<AppArgs, pico_args::Error> {
    let app_args = AppArgs::Flags {
        help: args.contains(["-h", "--help"]),
        version: args.contains(["-V", "--version"])
    };

    args.finish()?;
    Ok(app_args)
}