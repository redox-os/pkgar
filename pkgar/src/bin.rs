use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::Context;
use pkgar_core::{
    dryoc::classic::crypto_sign::crypto_sign_detached, Entry, Header, Mode, PackageSrc,
};
use pkgar_keys::PublicKeyFile;

use crate::ext::{copy_and_hash, EntryExt};
use crate::package::PackageFile;
use crate::transaction::Transaction;
use crate::{Error, READ_WRITE_HASH_BUF_SIZE};

fn folder_entries<P, Q>(base: P, path: Q, entries: &mut Vec<Entry>) -> io::Result<()>
where
    P: AsRef<Path>,
    Q: AsRef<Path>,
{
    let base = base.as_ref();
    let path = path.as_ref();

    // Sort each folder's entries by the file name
    let mut read_dir = Vec::new();
    for entry_res in fs::read_dir(path)? {
        read_dir.push(entry_res?);
    }
    read_dir.sort_by_key(|path| path.file_name());

    for entry in read_dir {
        let metadata = entry.metadata()?;
        let entry_path = entry.path();
        if metadata.is_dir() {
            folder_entries(base, entry_path, entries)?;
        } else {
            let relative = entry_path
                .strip_prefix(base)
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;

            let mut path_bytes = [0; 256];
            let relative_bytes = relative.as_os_str().as_bytes();
            if relative_bytes.len() >= path_bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "relative path longer than supported: {} > {}",
                        relative_bytes.len(),
                        path_bytes.len()
                    ),
                ));
            }
            path_bytes[..relative_bytes.len()].copy_from_slice(relative_bytes);

            let file_type = metadata.file_type();
            let file_mode = metadata.permissions().mode();

            //TODO: Use pkgar_core::Mode for all ops. This is waiting on error
            // handling.
            let mut mode = file_mode & Mode::PERM.bits();
            if file_type.is_file() {
                mode |= Mode::FILE.bits();
            } else if file_type.is_symlink() {
                mode |= Mode::SYMLINK.bits();
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
) -> anyhow::Result<()> {
    let keyfile = pkgar_keys::get_skey(secret_path.as_ref())?;
    let secret_key = keyfile
        .secret_key()
        .unwrap_or_else(|| panic!("{} was encrypted?", secret_path.as_ref().display()));
    let public_key = keyfile
        .public_key()
        .unwrap_or_else(|| panic!("{} was encrypted?", secret_path.as_ref().display()));

    //TODO: move functions to library

    let archive_path = archive_path.as_ref();
    let mut archive_file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(archive_path)
        .map_err(|source| Error::Io {
            source,
            path: Some(archive_path.to_path_buf()),
        })?;

    // Create a list of entries
    let mut entries = Vec::new();
    let folder = folder.as_ref();
    folder_entries(folder, folder, &mut entries)
        .map_err(|source| Error::Io {
            source,
            path: Some(folder.to_path_buf()),
        })
        .context("Recursing buildroot")?;

    // Create initial header
    let mut header = Header {
        signature: [0; 64],
        public_key,
        blake3: [0; 32],
        count: entries.len() as u64,
    };

    // Assign offsets to each entry
    let mut data_size: u64 = 0;
    for entry in &mut entries {
        entry.offset = data_size;
        data_size = data_size
            .checked_add(entry.size)
            .ok_or(pkgar_core::Error::Overflow)
            .map_err(Error::from)
            .context("Overflowed processing entry offsets")
            .with_context(|| {
                let offset = entry.offset;
                let size = entry.size;
                format!(
                    "Offset: {}, size: {}, path: {:?}",
                    offset,
                    size,
                    entry.check_path().unwrap_or_else(|_| Path::new(""))
                )
            })?;
    }

    let data_offset = header.total_size()?;
    archive_file
        .seek(SeekFrom::Start(data_offset as u64))
        .map_err(|source| Error::Io {
            source,
            path: Some(archive_path.to_path_buf()),
        })
        .with_context(|| format!("Seek to {} (data offset)", data_offset))?;

    //TODO: fallocate data_offset + data_size

    // Stream each file, writing data and calculating b3sums
    let mut header_hasher = blake3::Hasher::new();
    let mut buf = vec![0; 4 * 1024 * 1024];
    for entry in &mut entries {
        let relative = entry.check_path()?;
        let path = folder.join(relative);

        let mode = entry
            .mode()
            .map_err(Error::from)
            .with_context(|| path.display().to_string())?;

        let (total, hash) = match mode.kind() {
            Mode::FILE => {
                let mut entry_file =
                    fs::OpenOptions::new()
                        .read(true)
                        .open(&path)
                        .map_err(|source| Error::Io {
                            source,
                            path: Some(path.to_path_buf()),
                        })?;

                copy_and_hash(&mut entry_file, &mut archive_file, &mut buf)
                    .map_err(|source| Error::Io {
                        source,
                        path: Some(path.to_path_buf()),
                    })
                    .with_context(|| {
                        format!("Writing entry to archive: '{}'", relative.display())
                    })?
            }
            Mode::SYMLINK => {
                let destination = fs::read_link(&path).map_err(|source| Error::Io {
                    source,
                    path: Some(path.to_path_buf()),
                })?;

                let mut data = destination.as_os_str().as_bytes();
                copy_and_hash(&mut data, &mut archive_file, &mut buf)
                    .map_err(|source| Error::Io {
                        source,
                        path: Some(path.to_path_buf()),
                    })
                    .with_context(|| {
                        format!("Writing entry to archive: '{}'", relative.display())
                    })?
            }
            _ => {
                return Err(Error::from(pkgar_core::Error::InvalidMode(mode.bits())))
                    .with_context(|| path.display().to_string());
            }
        };
        if total != entry.size() {
            return Err(Error::LengthMismatch {
                actual: total,
                expected: entry.size(),
            })
            .with_context(|| path.display().to_string());
        }
        entry.blake3.copy_from_slice(hash.as_bytes());

        header_hasher.update_with_join::<blake3::join::RayonJoin>(bytemuck::bytes_of(entry));
    }
    header
        .blake3
        .copy_from_slice(header_hasher.finalize().as_bytes());

    //TODO: ensure file size matches

    let mut signature = [0; 64];
    crypto_sign_detached(
        &mut signature,
        &bytemuck::bytes_of(&header)[64..],
        &secret_key,
    )
    .map_err(pkgar_core::Error::Dryoc)?;
    header.signature.copy_from_slice(&signature);

    // Write archive header
    archive_file
        .seek(SeekFrom::Start(0))
        .map_err(|source| Error::Io {
            source,
            path: Some(archive_path.to_path_buf()),
        })?;

    archive_file
        .write_all(bytemuck::bytes_of(&header))
        .map_err(|source| Error::Io {
            source,
            path: Some(archive_path.to_path_buf()),
        })?;

    // Write each entry header
    for entry in &entries {
        let checked_path = entry.check_path()?;
        archive_file
            .write_all(bytemuck::bytes_of(entry))
            .map_err(|source| Error::Io {
                source,
                path: Some(archive_path.to_path_buf()),
            })
            .with_context(|| format!("Write entry {}", checked_path.display()))?;
    }

    Ok(())
}

pub fn extract(
    pkey_path: impl AsRef<Path>,
    archive_path: impl AsRef<Path>,
    base_dir: impl AsRef<Path>,
) -> anyhow::Result<()> {
    let pkey = PublicKeyFile::open(pkey_path.as_ref())?.pkey;

    let mut package = PackageFile::new(archive_path, &pkey)?;

    Transaction::install(&mut package, base_dir)?.commit()?;

    Ok(())
}

pub fn remove(
    pkey_path: impl AsRef<Path>,
    archive_path: impl AsRef<Path>,
    base_dir: impl AsRef<Path>,
) -> anyhow::Result<()> {
    let pkey = PublicKeyFile::open(pkey_path.as_ref())?.pkey;

    let mut package = PackageFile::new(archive_path, &pkey)?;

    Transaction::remove(&mut package, base_dir)?.commit()?;

    Ok(())
}

pub fn list(pkey_path: impl AsRef<Path>, archive_path: impl AsRef<Path>) -> Result<(), Error> {
    let pkey = PublicKeyFile::open(pkey_path.as_ref())?.pkey;

    let mut package = PackageFile::new(archive_path, &pkey)?;
    for entry in package.read_entries()? {
        let relative = entry.check_path()?;
        println!("{}", relative.display());
    }

    Ok(())
}

pub fn split(
    pkey_path: impl AsRef<Path>,
    archive_path: impl AsRef<Path>,
    head_path: impl AsRef<Path>,
    data_path_opt: Option<impl AsRef<Path>>,
) -> anyhow::Result<()> {
    let pkey_path = pkey_path.as_ref();
    let archive_path = archive_path.as_ref();
    let head_path = head_path.as_ref();

    let pkey = PublicKeyFile::open(pkey_path)?.pkey;

    let package = PackageFile::new(archive_path, &pkey)?;
    let data_offset = package.header().total_size()?;
    let mut src = package.src.into_inner();

    if let Some(data_path) = data_path_opt {
        let data_path = data_path.as_ref();
        let mut data_file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(data_path)
            .map_err(|source| Error::Io {
                source,
                path: Some(data_path.to_path_buf()),
            })?;

        src.seek(SeekFrom::Start(data_offset))
            .map_err(|source| Error::Io {
                source,
                path: Some(archive_path.to_path_buf()),
            })?;
        io::copy(&mut src, &mut data_file)
            .with_context(|| format!("Archive path: {}", archive_path.display()))
            .with_context(|| format!("Data path: {}", data_path.display()))?;
    }

    {
        let mut head_file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(head_path)
            .map_err(|source| Error::Io {
                source,
                path: Some(head_path.to_path_buf()),
            })?;

        src.seek(SeekFrom::Start(0)).map_err(|source| Error::Io {
            source,
            path: Some(archive_path.to_path_buf()),
        })?;
        io::copy(&mut src.take(data_offset), &mut head_file)
            .with_context(|| format!("Archive path: {}", archive_path.display()))
            .with_context(|| format!("Head path: {}", head_path.display()))?;
    }

    Ok(())
}

pub fn verify(
    pkey_path: impl AsRef<Path>,
    archive_path: impl AsRef<Path>,
    base_dir: impl AsRef<Path>,
) -> Result<(), Error> {
    let pkey = PublicKeyFile::open(pkey_path)?.pkey;

    let mut package = PackageFile::new(archive_path, &pkey)?;

    let mut buf = vec![0; READ_WRITE_HASH_BUF_SIZE];
    for entry in package.read_entries()? {
        let expected_path = base_dir.as_ref().join(entry.check_path()?);

        let expected = File::open(&expected_path).map_err(|source| Error::Io {
            source,
            path: Some(expected_path.to_path_buf()),
        })?;

        let (count, hash) =
            copy_and_hash(expected, io::sink(), &mut buf).map_err(|source| Error::Io {
                source,
                path: Some(expected_path.to_path_buf()),
            })?;

        entry.verify(hash, count)?;
    }
    Ok(())
}
