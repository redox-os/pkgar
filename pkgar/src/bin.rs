use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

use crate::{
    copy_and_hash,
    core::PackageHead,
    EntryExt,
    Error,
    keys::PublicKeyFile,
    PackageBuilder,
    PackageFile,
    READ_WRITE_HASH_BUF_SIZE,
    ResultExt,
    Transaction,
};

pub fn create(
    secret_path: impl AsRef<Path>,
    archive_path: impl AsRef<Path>,
    folder: impl AsRef<Path>,
) -> Result<(), Error> {
    let secret_key = pkgar_keys::get_skey(&secret_path.as_ref())?;

    let mut archive_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&archive_path)
        .chain_err(|| archive_path.as_ref() )?;

    let mut builder = PackageBuilder::new(secret_key);
    builder.dir(&folder)
        .chain_err(|| folder.as_ref() )?;
    builder.write_archive(&mut archive_file)
        .chain_err(|| archive_path.as_ref() )?;

    Ok(())
}

pub fn extract(
    pkey_path: impl AsRef<Path>,
    archive_path: impl AsRef<Path>,
    base_dir: impl AsRef<Path>,
) -> Result<(), Error> {
    let pkey = PublicKeyFile::open(&pkey_path.as_ref())?.pkey;

    let pkg = PackageFile::open(archive_path, &pkey)?;

    Transaction::install(&pkg, base_dir)?
        .commit()?;

    Ok(())
}

pub fn remove(
    pkey_path: impl AsRef<Path>,
    archive_path: impl AsRef<Path>,
    base_dir: impl AsRef<Path>,
) -> Result<(), Error> {
    let pkey = PublicKeyFile::open(&pkey_path.as_ref())?.pkey;

    let package = PackageFile::open(archive_path, &pkey)?;

    Transaction::remove(&package, base_dir)?
        .commit()?;

    Ok(())
}

pub fn list(
    pkey_path: impl AsRef<Path>,
    archive_path: impl AsRef<Path>,
) -> Result<(), Error> {
    let pkey = PublicKeyFile::open(&pkey_path.as_ref())?.pkey;

    let package = PackageFile::open(archive_path, &pkey)?;
    for entry in package.entries() {
        println!("{}", entry.check_path()?.display());
    }

    Ok(())
}

pub fn verify(
    pkey_path: impl AsRef<Path>,
    archive_path: impl AsRef<Path>,
    base_dir: impl AsRef<Path>,
) -> Result<(), Error> {
    let pkey = PublicKeyFile::open(pkey_path)?.pkey;

    let package = PackageFile::open(archive_path, &pkey)?;

    let mut buf = vec![0; READ_WRITE_HASH_BUF_SIZE];
    for entry in package.entries() {
        let expected_path = base_dir.as_ref()
            .join(entry.check_path()?);

        let expected = File::open(&expected_path)
            .chain_err(|| &expected_path )?;

        let (count, hash) = copy_and_hash(expected, io::sink(), &mut buf)?;

        entry.verify(hash, count)?;
    }
    Ok(())
}

