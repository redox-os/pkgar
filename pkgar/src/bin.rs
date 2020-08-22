use std::fs;
use std::io::{self, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use pkgar_core::{Entry, Header, PackageSrc};
use pkgar_keys::PublicKeyFile;
use sodiumoxide::crypto::sign;

use crate::{Error, ErrorKind, MODE_PERM, MODE_KIND, MODE_FILE, MODE_SYMLINK};
use crate::ext::{copy_and_hash, EntryExt};
use crate::package::PackageFile;
use crate::transaction::Transaction;

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

pub fn create(
    secret_path: impl AsRef<Path>,
    archive_path: impl AsRef<Path>,
    folder: impl AsRef<Path>,
) -> Result<(), Error> {
    let secret_key = pkgar_keys::get_skey(&secret_path.as_ref())?
        .key()
        .expect(&format!("{} was encrypted?", secret_path.as_ref().display()));

    //TODO: move functions to library

    let mut archive_file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&archive_path)
        .map_err(|e| Error::from(e).path(&archive_path) )?;

    // Create a list of entries
    let mut entries = Vec::new();
    folder_entries(&folder, &folder, &mut entries)
        .map_err(|e| Error::from(e)
            .reason("Recursing buildroot")
            .path(&folder)
        )?;

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
            .ok_or(pkgar_core::Error::Overflow)?;
    }

    let data_offset = header.total_size()?;
    archive_file.seek(SeekFrom::Start(data_offset as u64))
        .map_err(|e| Error::from(e)
            .reason(format!("Seek to {} (data offset)", data_offset))
            .path(&archive_path)
        )?;

    //TODO: fallocate data_offset + data_size

    // Stream each file, writing data and calculating b3sums
    let mut header_hasher = blake3::Hasher::new();
    let mut buf = vec![0; 4 * 1024 * 1024];
    for entry in &mut entries {
        let relative = entry.check_path()?;
        let path = folder.as_ref().join(relative);

        let mode_kind = entry.mode & MODE_KIND;
        let (total, hash) = match mode_kind {
            MODE_FILE => {
                let mut entry_file = fs::OpenOptions::new()
                    .read(true)
                    .open(&path)
                    .map_err(|e| Error::from(e).path(&path) )?;
                copy_and_hash(&mut entry_file, &mut archive_file, &mut buf)
                    .map_err(|e| Error::from(e)
                        .reason(format!("Writing entry to archive: '{}'", relative.display()))
                        .path(&path)
                    )?
            },
            MODE_SYMLINK => {
                let destination = fs::read_link(&path)
                    .map_err(|e| Error::from(e).path(&path) )?;

                let mut data = destination.as_os_str().as_bytes();
                copy_and_hash(&mut data, &mut archive_file, &mut buf)
                    .map_err(|e| Error::from(e)
                        .reason(format!("Writing entry to archive: '{}'", relative.display()))
                        .path(&path)
                    )?
            },
            _ => {
                return Err(ErrorKind::UnsupportedMode {
                    entry: relative.to_path_buf(),
                    mode: entry.mode(),
                }.into());
            }
        };
        if total != entry.size() {
            return Err(ErrorKind::LengthMismatch {
                entry: relative.to_path_buf(),
                actual: total,
                expected: entry.size(),
            }.into());
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
    archive_file.seek(SeekFrom::Start(0))
        .map_err(|e| Error::from(e).path(&archive_path) )?;

    archive_file.write_all(unsafe {
        plain::as_bytes(&header)
    })
        .map_err(|e| Error::from(e).path(&archive_path) )?;

    // Write each entry header
    for entry in &entries {
        let checked_path = entry.check_path()?;
        archive_file.write_all(unsafe {
            plain::as_bytes(entry)
        })
            .map_err(|e| Error::from(e)
                .reason(format!("Write entry {}", checked_path.display()))
                .path(&archive_path)
            )?;
    }

    Ok(())
}

pub fn extract(
    pkey_path: impl AsRef<Path>,
    archive_path: impl AsRef<Path>,
    base_dir: impl AsRef<Path>,
) -> Result<(), Error> {
    let pkey = PublicKeyFile::open(&pkey_path.as_ref())?.pkey;

    let mut package = PackageFile::new(archive_path, &pkey)?;

    let mut transaction = Transaction::new(base_dir);
    transaction.install(&mut package)?;
    transaction.commit()?;

    Ok(())
}

pub fn remove(
    pkey_path: impl AsRef<Path>,
    archive_path: impl AsRef<Path>,
    base_dir: impl AsRef<Path>,
) -> Result<(), Error> {
    let pkey = PublicKeyFile::open(&pkey_path.as_ref())?.pkey;

    let mut package = PackageFile::new(archive_path, &pkey)?;

    let mut transaction = Transaction::new(base_dir);
    transaction.remove(&mut package)?;
    transaction.commit()?;

    Ok(())
}

pub fn list(
    pkey_path: impl AsRef<Path>,
    archive_path: impl AsRef<Path>,
) -> Result<(), Error> {
    let pkey = PublicKeyFile::open(&pkey_path.as_ref())?.pkey;

    let mut package = PackageFile::new(archive_path, &pkey)?;
    for entry in package.read_entries()? {
        let relative = entry.check_path()?;
        println!("{}", relative.display());
    }

    Ok(())
}

