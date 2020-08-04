use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use blake3::{Hash, Hasher};
use pkgar_core::{Entry, Header, PackageSrc};
use pkgar_keys::PublicKeyFile;
use sodiumoxide::crypto::sign;

use crate::{Error, MODE_PERM, MODE_KIND, MODE_FILE, MODE_SYMLINK};
use crate::package::PackageFile;
use crate::transaction::Transaction;

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

pub(crate) fn copy_entry_and_hash<P, W>(
    src: &mut P,
    entry: Entry,
    mut write: W,
    buf: &mut [u8]
) -> Result<(u64, Hash), Error>
where
    P: PackageSrc<Err = Error>,
    W: Write,
{
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

    let mut package = PackageFile::new(archive_path, &public_key)?;
    
    let mut transaction = Transaction::new();
    transaction.install(&mut package, folder)?;
    transaction.commit()?;

    Ok(())
}

pub fn list(public_path: &str, archive_path: &str) -> Result<(), Error> {
    let public_key = PublicKeyFile::open(&public_path.as_ref())?.pkey;

    let mut package = PackageFile::new(archive_path, &public_key)?;
    let entries = package.read_entries()?;
    for entry in entries {
        let relative = Path::new(OsStr::from_bytes(entry.path()));
        println!("{}", relative.display());
    }

    Ok(())
}

