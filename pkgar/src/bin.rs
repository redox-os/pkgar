use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path};

use blake3::{Hash, Hasher};
use pkgar_core::{Entry, Header, PackageSrc};
use pkgar_keys::PublicKeyFile;
use sodiumoxide::crypto::sign;

use crate::Error;
use crate::package::PackageFile;

// This ensures that all platforms use the same mode defines
const MODE_PERM: u32 = 0o7777;
const MODE_KIND: u32 = 0o170000;
const MODE_FILE: u32 = 0o100000;
const MODE_SYMLINK: u32 = 0o120000;

//TODO: Refactor to reduce duplication between these functions
fn copy_and_hash<R: Read, W: Write>(mut read: R, mut write: W, buf: &mut [u8]) -> Result<(u64, Hash), Error> {
    let mut hasher = Hasher::new();
    let mut total = 0;
    loop {
        let count = read.read(buf)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        //TODO: Progress
        write.write_all(&buf[..count])?;
        hasher.update_with_join::<blake3::join::RayonJoin>(&buf[..count]);
    }
    Ok((total, hasher.finalize()))
}

fn copy_entry_and_hash<W: Write>(
    src: &mut PackageFile,
    entry: Entry,
    mut write: W,
    buf: &mut [u8]
) -> Result<(u64, Hash), Error> {
    let mut hasher = Hasher::new();
    let mut total = 0;
    loop {
        let count = src.read_entry(entry, total, buf)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        write.write_all(&buf[..count])?;
        hasher.update_with_join::<blake3::join::RayonJoin>(&buf[..count]);
    }
    Ok((total, hasher.finalize()))
}

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
    let secret_key = pkgar_keys::get_skey(&secret_path.as_ref())?
        .key()
        .expect(&format!("{} was encrypted?", secret_path));

    //TODO: move functions to library

    let mut archive_file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(archive_path)?;

    // Create a list of entries
    let mut entries = Vec::new();
    folder_entries(folder, folder, &mut entries)?;

    // Create initial header
    let mut header = Header {
        signature: [0; 64],
        public_key: [0; 32],
        blake3: [0; 32],
        count: entries.len() as u64
    };

    header.public_key.copy_from_slice(secret_key.public_key().as_ref());

    // Assign offsets to each entry
    let mut data_size: u64 = 0;
    for entry in &mut entries {
        entry.offset = data_size;
        data_size = data_size.checked_add(entry.size)
            .ok_or(Error::Core(pkgar_core::Error::Overflow))?;
    }

    // Seek to data offset
    let data_offset = header.total_size()?;
    archive_file.seek(SeekFrom::Start(data_offset as u64))?;
    //TODO: fallocate data_offset + data_size

    // Stream each file, writing data and calculating b3sums
    let mut header_hasher = blake3::Hasher::new();
    let mut buf = vec![0; 4 * 1024 * 1024];
    for entry in &mut entries {
        let relative = Path::new(OsStr::from_bytes(entry.path()));
        let path = Path::new(folder).join(relative);

        let mode_kind = entry.mode & MODE_KIND;
        let (total, hash) = match mode_kind {
            MODE_FILE => {
                let mut entry_file = fs::OpenOptions::new()
                    .read(true)
                    .open(path)?;
                copy_and_hash(&mut entry_file, &mut archive_file, &mut buf)?
            },
            MODE_SYMLINK => {
                let destination = fs::read_link(path)?;
                let mut data = destination.as_os_str().as_bytes();
                copy_and_hash(&mut data, &mut archive_file, &mut buf)?
            },
            _ => {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Unsupported mode {:#o}", { entry.mode })
                )));
            }
        };
        if total != { entry.size } {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Copied {} instead of {}", total, { entry.size })
            )));
        }
        entry.blake3.copy_from_slice(hash.as_bytes());

        header_hasher.update_with_join::<blake3::join::RayonJoin>(unsafe {
            plain::as_bytes(entry)
        });
    }
    header.blake3.copy_from_slice(header_hasher.finalize().as_bytes());

    //TODO: ensure file size matches

    header.signature = sign::sign_detached(unsafe { &plain::as_bytes(&header)[64..] }, &secret_key).0;

    // Write archive header
    archive_file.seek(SeekFrom::Start(0))?;
    archive_file.write_all(unsafe {
        plain::as_bytes(&header)
    })?;

    // Write each entry header
    for entry in &entries {
        archive_file.write_all(unsafe {
            plain::as_bytes(entry)
        })?;
    }

    Ok(())
}

pub fn extract(public_path: &str, archive_path: &str, folder: &str) -> Result<(), Error> {
    let public_key = PublicKeyFile::open(&public_path.as_ref())?.pkey;

    let mut package = PackageFile::new(archive_path)?;
    let entries = package.entries(&public_key)?;

    // TODO: Validate that all entries can be installed, before installing

    let folder_path = Path::new(folder);
    let mut buf = vec![0; 4 * 1024 * 1024];
    let mut renames = Vec::new();
    for entry in entries {
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

        let entry_hash = Hash::from(entry.blake3);
        let temp_name = if let Some(file_name) = entry_path.file_name().and_then(|x| x.to_str())
        {
            format!(".pkgar.{}", file_name)
        } else {
            format!(".pkgar.{}", entry_hash.to_hex())
        };
        let temp_path = if let Some(parent) = entry_path.parent() {
            fs::create_dir_all(parent)?;
            parent.join(temp_name)
        } else {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("entry path has no parent: {:?}", entry_path)
            )));
        };

        let mode = entry.mode;
        let mode_kind = mode & MODE_KIND;
        let mode_perm = mode & MODE_PERM;
        let (total, hash) = match mode_kind {
            MODE_FILE => {
                //TODO: decide what to do when temp files are left over
                let mut temp_file = fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(mode_perm)
                    .open(&temp_path)?;
                copy_entry_and_hash(&mut package, entry, &mut temp_file, &mut buf)?
            },
            MODE_SYMLINK => {
                let mut data = Vec::new();
                let (total, hash) = copy_entry_and_hash(&mut package, entry, &mut data, &mut buf)?;
                let os_str: &OsStr = OsStrExt::from_bytes(data.as_slice());
                symlink(os_str, &temp_path)?;
                (total, hash)
            },
            _ => {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Unsupported mode {:#o}", mode)
                )));
            }
        };
        if total != entry.size {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Copied {} instead of {}", total, entry.size)
            )));
        }
        if entry_hash != hash {
            let _ = fs::remove_file(temp_path);
            return Err(Error::Core(pkgar_core::Error::InvalidBlake3));
        }

        renames.push((temp_path, entry_path));
    }

    for (temp_path, entry_path) in renames {
        fs::rename(&temp_path, &entry_path)?;
    }

    Ok(())
}

pub fn list(public_path: &str, archive_path: &str) -> Result<(), Error> {
    let public_key = PublicKeyFile::open(&public_path.as_ref())?.pkey;

    // Read header first
    let mut package = PackageFile::new(archive_path)?;
    let entries = package.entries(&public_key)?;
    for entry in entries {
        let relative = Path::new(OsStr::from_bytes(entry.path()));
        println!("{}", relative.display());
    }

    Ok(())
}

