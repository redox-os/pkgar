use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use pkgar_core::{
    dryoc::classic::crypto_sign::crypto_sign_detached, Entry, Header, Mode, PackageSrc,
};
use pkgar_core::{HeaderFlags, PublicKey, SecretKey};
use pkgar_keys::PublicKeyFile;

use crate::ext::{copy_and_hash, DataWriter, EntryExt};
use crate::package::PackageFile;
use crate::transaction::Transaction;
use crate::{wrap_io_err, Error};

/// Iterate a directory and return its entries
pub fn folder_entries<P>(base: P) -> Result<Vec<Entry>, Error>
where
    P: AsRef<Path>,
{
    let mut entries = Vec::new();
    folder_entries_inner(&base, &base, &mut entries)?;
    Ok(entries)
}

fn folder_entries_inner<P, Q>(base: P, path: Q, entries: &mut Vec<Entry>) -> Result<(), Error>
where
    P: AsRef<Path>,
    Q: AsRef<Path>,
{
    let base = base.as_ref();
    let path = path.as_ref();

    // Sort each folder's entries by the file name
    let mut read_dir = Vec::new();
    for entry_res in fs::read_dir(path).map_err(wrap_io_err!(path, "Reading entries"))? {
        let Ok(entry) = entry_res else {
            continue;
        };
        read_dir.push(entry);
    }

    read_dir.sort_by_key(|path| path.file_name());

    for entry in read_dir {
        let entry_path = entry.path();
        let metadata = entry
            .metadata()
            .map_err(wrap_io_err!(entry_path, "Getting entry metadata"))?;
        let entry_type = metadata.file_type();
        if entry_type.is_dir() {
            folder_entries_inner(base, entry_path, entries)?;
        } else {
            let Ok(relative) = entry_path.strip_prefix(base) else {
                continue;
            };
            let mode = Mode::new_file(
                metadata.permissions().mode(),
                entry_type.is_file(),
                entry_type.is_symlink(),
            )?;
            entries.push(Entry::new_uninit(relative.as_os_str().as_bytes(), mode)?);
        }
    }

    Ok(())
}

/// Create a new pkgar file with given secret and source path
pub fn create(
    secret_path: impl AsRef<Path>,
    archive_path: impl AsRef<Path>,
    source_path: impl AsRef<Path>,
) -> Result<(), Error> {
    create_with_flags(
        secret_path,
        archive_path,
        source_path,
        HeaderFlags::latest(
            pkgar_core::Architecture::Independent,
            pkgar_core::Packaging::Uncompressed,
        ),
    )
}

/// Create a new pkgar file with given secret and source path and header flags
pub fn create_with_flags(
    secret_path: impl AsRef<Path>,
    archive_path: impl AsRef<Path>,
    source_path: impl AsRef<Path>,
    flags: HeaderFlags,
) -> Result<(), Error> {
    let keyfile = pkgar_keys::get_skey(secret_path.as_ref())?;
    let Some(secret_key) = keyfile.secret_key() else {
        return Err(Error::DataNotInitialized);
    };
    let Some(public_key) = keyfile.public_key() else {
        return Err(Error::DataNotInitialized);
    };

    let entries = folder_entries(&source_path)?;

    create_with_entries(
        secret_key,
        public_key,
        archive_path,
        flags,
        entries,
        source_path,
    )
}

/// Create a new pkgar file with extracted secret keys from `pkgar_keys::get_skey` and entries from `folder_entries`
fn create_with_entries(
    secret_key: SecretKey,
    public_key: PublicKey,
    archive_path: impl AsRef<Path>,
    flags: HeaderFlags,
    mut entries: Vec<Entry>,
    source_path: impl AsRef<Path>,
) -> Result<(), Error> {
    let archive_path = archive_path.as_ref();
    let source_path = source_path.as_ref();
    let mut archive_file =
        fs::File::create(archive_path).map_err(wrap_io_err!(archive_path, "Opening source"))?;

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
        let path = source_path.join(relative);

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

        entry.init(hash.into(), data_offset, clen);
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
    archive_file.seek(SeekFrom::Start(0)).map_err(wrap_io_err!(
        archive_path.to_path_buf(),
        "Seeking archive_file back to 0"
    ))?;

    archive_file
        .write_all(bytemuck::bytes_of(&header))
        .map_err(wrap_io_err!(archive_path.to_path_buf(), "Writing header"))?;

    // Write each entry header
    for entry in &entries {
        let _ = entry.check_path()?;
        archive_file
            .write_all(bytemuck::bytes_of(entry))
            .map_err(wrap_io_err!(archive_path.to_path_buf(), "Writing entry"))?;
    }

    archive_file
        .flush()
        .map_err(wrap_io_err!("Flushing archive"))?;

    Ok(())
}

/// Extract a pkgar file to a directory
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

/// Update a directory from a pkgar file
pub fn replace(
    old_pkey_path: impl AsRef<Path>,
    pkey_path: impl AsRef<Path>,
    old_head_path: impl AsRef<Path>,
    archive_path: impl AsRef<Path>,
    base_dir: impl AsRef<Path>,
) -> Result<(), Error> {
    let pkey = PublicKeyFile::open(pkey_path.as_ref())?.pkey;
    let old_pkey = PublicKeyFile::open(old_pkey_path.as_ref())?.pkey;

    let mut new_package = PackageFile::new(archive_path, &pkey)?;
    let mut old_package = PackageFile::new(old_head_path, &old_pkey)?;

    Transaction::replace(&mut old_package, &mut new_package, base_dir)?.commit()?;

    Ok(())
}

/// Remove directory entries from a pkgar file
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

/// Print a pkgar file entries path
pub fn list(pkey_path: impl AsRef<Path>, archive_path: impl AsRef<Path>) -> Result<(), Error> {
    let pkey = PublicKeyFile::open(pkey_path.as_ref())?.pkey;

    let mut package = PackageFile::new(archive_path, &pkey)?;
    for entry in package.read_entries()? {
        let relative = entry.check_path()?;
        println!("{}", relative.display());
    }

    Ok(())
}

/// Split a package file into head and optional data
pub fn split(
    pkey_path: impl AsRef<Path>,
    archive_path: impl AsRef<Path>,
    head_path: impl AsRef<Path>,
    data_path_opt: Option<impl AsRef<Path>>,
) -> Result<(), Error> {
    let pkey_path = pkey_path.as_ref();
    let archive_path = archive_path.as_ref();

    let pkey = PublicKeyFile::open(pkey_path)?.pkey;
    let mut package = PackageFile::new(archive_path, &pkey)?;
    package.split(head_path, data_path_opt)
}

/// Split a package file into head and optional data
pub fn verify(
    pkey_path: impl AsRef<Path>,
    archive_path: impl AsRef<Path>,
    base_dir: impl AsRef<Path>,
) -> Result<(), Error> {
    let pkey = PublicKeyFile::open(pkey_path)?.pkey;
    let mut package = PackageFile::new(&archive_path, &pkey)?;
    package.verify(base_dir)
}
