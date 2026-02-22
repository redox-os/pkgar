use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use pkgar_core::HeaderFlags;
use pkgar_core::{
    dryoc::classic::crypto_sign::crypto_sign_detached, Entry, Header, Mode, PackageSrc,
};
use pkgar_keys::PublicKeyFile;

use crate::ext::{copy_and_hash, DataReader, DataWriter, EntryExt, PackageSrcExt};
use crate::package::PackageFile;
use crate::transaction::Transaction;
use crate::{wrap_io_err, Error, READ_WRITE_HASH_BUF_SIZE};

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
) -> Result<(), Error> {
    create_with_flags(
        secret_path,
        archive_path,
        folder,
        HeaderFlags::latest(
            pkgar_core::Architecture::Independent,
            pkgar_core::Packaging::Uncompressed,
        ),
    )
}

pub fn create_with_flags(
    secret_path: impl AsRef<Path>,
    archive_path: impl AsRef<Path>,
    folder: impl AsRef<Path>,
    flags: HeaderFlags,
) -> Result<(), Error> {
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
        .map_err(wrap_io_err!(archive_path, "Opening source"))?;

    // Create a list of entries
    let mut entries = Vec::new();
    let folder = folder.as_ref();
    folder_entries(folder, folder, &mut entries)
        .map_err(wrap_io_err!(archive_path, "Recursing buildroot"))?;

    // Create initial header
    let mut header = Header {
        signature: [0; 64],
        public_key,
        blake3: [0; 32],
        count: entries.len() as u32,
        flags,
    };

    let data_offset = header.total_size()?;
    archive_file
        .seek(SeekFrom::Start(data_offset as u64))
        .map_err(wrap_io_err!(archive_path, "Seeking archive file"))?;

    //TODO: fallocate data_offset + data_size

    // Stream each file, writing data and calculating b3sums
    let mut header_hasher = blake3::Hasher::new();
    let mut buf = vec![0; 4 * 1024 * 1024];
    let mut data_offset: u64 = 0;
    for entry in &mut entries {
        let relative = entry.check_path()?;
        let path = folder.join(relative);

        let mode = entry.mode().map_err(Error::from)?;

        // uncompressed size, compressed size, real size
        let (ulen, clen, rlen, hash) = match mode.kind() {
            Mode::FILE => {
                let mut entry_file = fs::OpenOptions::new()
                    .read(true)
                    .open(&path)
                    .map_err(wrap_io_err!(path, "Opening entry data"))?;
                let entry_meta = entry_file
                    .metadata()
                    .map_err(wrap_io_err!(path, "Checking entry data size"))?;
                let start_pos = archive_file
                    .stream_position()
                    .map_err(wrap_io_err!(path, "Getting file position"))?;
                let rlen = entry_meta.len();
                let mut writer = DataWriter::new(header.flags.packaging(), archive_file, rlen)
                    .map_err(wrap_io_err!(path, "Writing entry data size"))?;
                let (ulen, hash) = copy_and_hash(&mut entry_file, &mut writer, &mut buf)
                    .map_err(wrap_io_err!(path, "Writing data to archive"))?;
                archive_file = writer
                    .finish()
                    .map_err(wrap_io_err!(path, "Finalize archive"))?;
                let end_pos = archive_file
                    .stream_position()
                    .map_err(wrap_io_err!(path, "Getting file position"))?;
                (ulen, end_pos - start_pos, rlen, hash)
            }
            Mode::SYMLINK => {
                let destination =
                    fs::read_link(&path).map_err(wrap_io_err!(path, "Reading entry symlink"))?;
                let start_pos = archive_file
                    .stream_position()
                    .map_err(wrap_io_err!(path, "Getting file position"))?;
                let mut data = destination.as_os_str().as_bytes();
                let rlen = data.len() as u64;
                let mut writer = DataWriter::new(header.flags.packaging(), archive_file, rlen)
                    .map_err(wrap_io_err!(path, "Writing entry data size"))?;
                let (ulen, hash) = copy_and_hash(&mut data, &mut writer, &mut buf)
                    .map_err(wrap_io_err!(path, "Writing data to archive"))?;
                archive_file = writer
                    .finish()
                    .map_err(wrap_io_err!(path, "Finalize archive"))?;
                let end_pos = archive_file
                    .stream_position()
                    .map_err(wrap_io_err!(path, "Getting file position"))?;
                (ulen, end_pos - start_pos, rlen, hash)
            }
            _ => {
                return Err(Error::from(pkgar_core::Error::InvalidMode(mode.bits())));
            }
        };
        if ulen != rlen {
            return Err(Error::LengthMismatch {
                actual: ulen,
                expected: rlen,
            });
        }

        entry.size = clen;
        entry.offset = data_offset;
        entry.blake3.copy_from_slice(hash.as_bytes());
        data_offset = data_offset
            .checked_add(clen)
            .ok_or(pkgar_core::Error::Overflow)
            .map_err(Error::from)?;

        header_hasher.update_rayon(bytemuck::bytes_of(entry));
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
            context: "Seeking archive_file back to 0",
        })?;

    archive_file
        .write_all(bytemuck::bytes_of(&header))
        .map_err(|source| Error::Io {
            source,
            path: Some(archive_path.to_path_buf()),
            context: "Writing header",
        })?;

    // Write each entry header
    for entry in &entries {
        let _ = entry.check_path()?;
        archive_file
            .write_all(bytemuck::bytes_of(entry))
            .map_err(|source| Error::Io {
                source,
                path: Some(archive_path.to_path_buf()),
                context: "Writing entry",
            })?;
    }

    Ok(())
}

pub fn extract(
    pkey_path: impl AsRef<Path>,
    archive_path: impl AsRef<Path>,
    base_dir: impl AsRef<Path>,
) -> Result<(), Error> {
    let pkey = PublicKeyFile::open(pkey_path.as_ref())?.pkey;

    let mut package = PackageFile::new(archive_path, &pkey)?;

    Transaction::install(&mut package, base_dir)?.commit()?;

    Ok(())
}

pub fn remove(
    pkey_path: impl AsRef<Path>,
    archive_path: impl AsRef<Path>,
    base_dir: impl AsRef<Path>,
) -> Result<(), Error> {
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
) -> Result<(), Error> {
    let pkey_path = pkey_path.as_ref();
    let archive_path = archive_path.as_ref();
    let head_path = head_path.as_ref();

    let pkey = PublicKeyFile::open(pkey_path)?.pkey;

    let mut package = PackageFile::new(archive_path, &pkey)?;
    let data_offset = package.header().total_size()? as u64;
    let mut src = package.take_reader()?;

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
                context: "Opening data",
            })?;

        src.seek(SeekFrom::Start(data_offset))
            .map_err(|source| Error::Io {
                source,
                path: Some(archive_path.to_path_buf()),
                context: "Seeking data",
            })?;
        io::copy(&mut src, &mut data_file).map_err(|source| Error::Io {
            source,
            path: Some(head_path.to_path_buf()),
            context: "Writing data",
        })?;
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
                context: "Opening head",
            })?;

        src.seek(SeekFrom::Start(0)).map_err(|source| Error::Io {
            source,
            path: Some(archive_path.to_path_buf()),
            context: "Seeking head",
        })?;
        io::copy(&mut src.take(data_offset), &mut head_file).map_err(|source| Error::Io {
            source,
            path: Some(head_path.to_path_buf()),
            context: "Writing head",
        })?;
    }

    Ok(())
}

pub fn verify(
    pkey_path: impl AsRef<Path>,
    archive_path: impl AsRef<Path>,
    base_dir: impl AsRef<Path>,
) -> Result<(), Error> {
    let pkey = PublicKeyFile::open(pkey_path)?.pkey;

    let mut package = PackageFile::new(&archive_path, &pkey)?;
    let entries = package.read_entries()?;
    let mut pkg_file = package.take_reader()?;
    let header = package.header();

    let mut buf = vec![0; READ_WRITE_HASH_BUF_SIZE];
    for entry in entries {
        let expected_path = base_dir.as_ref().join(entry.check_path()?);

        let mut expected =
            File::open(&expected_path).map_err(wrap_io_err!(expected_path, "Opening file"))?;

        let (count, hash) = copy_and_hash(&mut expected, &mut io::sink(), &mut buf)
            .map_err(wrap_io_err!(expected_path, "Writing file to to black hole"))?;

        // TODO: Just the head is enough for uncompressed, but requires full data for compressed pkgar
        let reader = DataReader::new_with_seek(&header, pkg_file, &entry).map_err(wrap_io_err!(
            archive_path.as_ref(),
            "Reading pkg data (make sure to provide full package instead of just head)"
        ))?;
        entry.verify(hash, count, &reader)?;
        pkg_file = reader.into_inner();
    }
    Ok(())
}
