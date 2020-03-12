use std::convert::TryFrom;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::mem;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path};

use crate::{Entry, Error, Header, Package, PackageSrc, PublicKey, SecretKey};

// This ensures that all platforms use the same mode defines
const MODE_PERM: u32 = 0o7777;
const MODE_KIND: u32 = 0o170000;
const MODE_FILE: u32 = 0o100000;
const MODE_SYMLINK: u32 = 0o120000;

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
                    format!("relative path longer than supported: {} > {}", relative_bytes.len(), path_bytes.len())
                ));
            }
            path_bytes[..relative_bytes.len()].copy_from_slice(relative_bytes);

            let file_type = metadata.file_type();
            let mut mode = metadata.permissions().mode() & MODE_PERM;
            if file_type.is_file() {
                mode |= MODE_FILE;
            } else if file_type.is_symlink() {
                mode |= MODE_SYMLINK;
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Unsupported entry at {:?}: {:?}", relative, metadata),
                ));
            }
            entries.push(Entry {
                blake3: [0; 32],
                offset: 0,
                size: metadata.len(),
                mode,
                path: path_bytes,
            });
        }
    }

    Ok(())
}

pub fn create(secret_path: &str, archive_path: &str, folder: &str) -> Result<(), Error> {
    let secret_key = {
        let mut data = [0; 64];
        fs::OpenOptions::new()
            .read(true)
            .open(secret_path)
            .map_err(Error::Io)?
            .read_exact(&mut data)
            .map_err(Error::Io)?;
        SecretKey::from_data(data)
    };

    //TODO: move functions to library

    let mut archive_file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(archive_path)
        .map_err(Error::Io)?;

    // Create a list of entries
    let mut entries = Vec::new();
    folder_entries(folder, folder, &mut entries)
        .map_err(Error::Io)?;

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
            .ok_or(Error::Overflow)?;
    }

    // Seek to data offset
    let data_offset = header.total_size()?;
    archive_file.seek(SeekFrom::Start(data_offset as u64))
        .map_err(Error::Io)?;
    //TODO: fallocate data_offset + data_size

    // Stream each file, writing data and calculating b3sums
    let mut header_hasher = blake3::Hasher::new();
    let mut buf = vec![0; 4 * 1024 * 1024];
    for entry in &mut entries {
        let relative = Path::new(OsStr::from_bytes(entry.path()));
        let path = Path::new(folder).join(relative);

        let mut hasher = blake3::Hasher::new();
        let mode_kind = entry.mode & MODE_KIND;
        match mode_kind {
            MODE_FILE => {
                let mut entry_file = fs::OpenOptions::new()
                    .read(true)
                    .open(path)
                    .map_err(Error::Io)?;

                let mut total = 0;
                loop {
                    let count = entry_file.read(&mut buf)
                        .map_err(Error::Io)?;
                    if count == 0 {
                        break;
                    }
                    total += count as u64;
                    //TODO: Progress
                    archive_file.write_all(&buf[..count])
                        .map_err(Error::Io)?;
                    hasher.update_with_join::<blake3::join::RayonJoin>(&buf[..count]);
                }
                assert_eq!(total, { entry.size });
            },
            MODE_SYMLINK => {
                let destination = fs::read_link(path)
                    .map_err(Error::Io)?;
                let data = destination.as_os_str().as_bytes();
                assert_eq!(data.len() as u64, { entry.size });

                archive_file.write_all(&data)
                    .map_err(Error::Io)?;
                hasher.update_with_join::<blake3::join::RayonJoin>(&data);
            },
            _ => {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Unsupported mode {:#o}", { entry.mode })
                )));
            }
        }
        entry.blake3.copy_from_slice(hasher.finalize().as_bytes());

        header_hasher.update_with_join::<blake3::join::RayonJoin>(unsafe {
            plain::as_bytes(entry)
        });
    }
    header.blake3.copy_from_slice(header_hasher.finalize().as_bytes());

    //TODO: ensure file size matches

    // Calculate signature
    let unsigned = header.clone();
    sodalite::sign_attached(
        unsafe { plain::as_mut_bytes(&mut header) },
        unsafe { &plain::as_bytes(&unsigned)[64..] },
        secret_key.as_data()
    );

    // Write archive header
    archive_file.seek(SeekFrom::Start(0))
        .map_err(Error::Io)?;
    archive_file.write_all(unsafe {
        plain::as_bytes(&header)
    }).map_err(Error::Io)?;

    // Write each entry header
    for entry in &entries {
        archive_file.write_all(unsafe {
            plain::as_bytes(entry)
        }).map_err(Error::Io)?;
    }

    Ok(())
}

pub fn extract(public_path: &str, archive_path: &str, folder: &str) -> Result<(), Error> {
    let public_key = {
        let mut data = [0; 32];
        fs::OpenOptions::new()
            .read(true)
            .open(public_path)
            .map_err(Error::Io)?
            .read_exact(&mut data)
            .map_err(Error::Io)?;
        PublicKey::from_data(data)
    };

    let mut archive_file = fs::OpenOptions::new()
        .read(true)
        .open(archive_path)
        .map_err(Error::Io)?;

    let mut package = Package::new(
        PackageSrc::File(&mut archive_file),
        &public_key
    )?;
    let entries = package.entries()?;

    // TODO: Validate that all entries can be installed, before installing

    let folder_path = Path::new(folder);
    for entry in entries {
        // TODO: Do not read entire file into memory
        let size = usize::try_from(entry.size())
            .map_err(Error::TryFromInt)?;
        let mut data = vec![0; size];
        entry.read_at(&mut package, 0, &mut data)?;

        let hash = {
            let mut hasher = blake3::Hasher::new();
            hasher.update_with_join::<blake3::join::RayonJoin>(&data);
            hasher.finalize()
        };

        if &entry.hash() != hash.as_bytes() {
            return Err(Error::InvalidBlake3);
        }

        let relative = Path::new(OsStr::from_bytes(entry.path()));
        for component in relative.components() {
            match component {
                Component::Normal(_) => (),
                invalid => {
                    return Err(Error::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("entry path contains invalid component: {:?}", invalid)
                    )));
                }
            }
        }
        let entry_path = folder_path.join(relative);
        if ! entry_path.starts_with(&folder_path) {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("entry path escapes from folder: {:?}", relative)
            )));
        }
        if let Some(parent) = entry_path.parent() {
            fs::create_dir_all(parent)
                .map_err(Error::Io)?;
        }

        let mode = entry.mode();
        let mode_kind = mode & MODE_KIND;
        let mode_perm = mode & MODE_PERM;
        match mode_kind {
            MODE_FILE => {
                fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(mode_perm)
                    .open(entry_path)
                    .map_err(Error::Io)?
                    .write_all(&data)
                    .map_err(Error::Io)?;
            },
            MODE_SYMLINK => {
                let os_str: &OsStr = OsStrExt::from_bytes(data.as_slice());
                symlink(os_str, entry_path)
                    .map_err(Error::Io)?;
            },
            _ => {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Unsupported mode {:#o}", mode)
                )));
            }
        }
    }

    Ok(())
}

#[cfg(feature = "rand")]
pub fn keygen(secret_path: &str, public_path: &str) -> Result<(), Error> {
    use rand::rngs::OsRng;

    let secret_key = SecretKey::new(&mut OsRng)
        .map_err(Error::Rand)?;
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o400)
        .open(secret_path)
        .map_err(Error::Io)?
        .write_all(secret_key.as_data())
        .map_err(Error::Io)?;

    let public_key = secret_key.public_key();
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o400)
        .open(public_path)
        .map_err(Error::Io)?
        .write_all(public_key.as_data())
        .map_err(Error::Io)?;

    Ok(())
}

pub fn list(public_path: &str, archive_path: &str) -> Result<(), Error> {
    let public_key = {
        let mut data = [0; 32];
        fs::OpenOptions::new()
            .read(true)
            .open(public_path)
            .map_err(Error::Io)?
            .read_exact(&mut data)
            .map_err(Error::Io)?;
        PublicKey::from_data(data)
    };

    let mut archive_file = fs::OpenOptions::new()
        .read(true)
        .open(archive_path)
        .map_err(Error::Io)?;

    // Read header first
    let mut header_data = [0; mem::size_of::<Header>()];
    archive_file.read_exact(&mut header_data)
        .map_err(Error::Io)?;
    let header = Header::new(&header_data, &public_key)?;

    // Read entries next
    let entries_size = header.entries_size()
        .and_then(|x| usize::try_from(x).map_err(Error::TryFromInt))?;
    let mut entries_data = vec![0; entries_size];
    archive_file.read_exact(&mut entries_data)
        .map_err(Error::Io)?;
    let entries = header.entries(&entries_data)?;

    for entry in entries {
        let relative = Path::new(OsStr::from_bytes(entry.path()));
        println!("{}", relative.display());
    }

    Ok(())
}
