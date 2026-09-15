use std::{
    borrow::Cow,
    io::{Seek, SeekFrom},
    path::Path,
};

use std::{io::Read, sync::OnceLock};

use pkgar_core::Header;
use pkgar_core::{PackageSrc, PublicKey};

use pkgar_repo::{PackageUrl, PublicKeyRemote};

use crate::{Error, PackageFile, ext::PackageSrcExt};
use std::io::Result as IoResult;

pub fn open_or_download_pubkey(pkey_path: impl AsRef<Path>) -> Result<PublicKey, Error> {
    let pkey_path = pkey_path.as_ref();

    let file = PublicKeyRemote::download_or_read(&pkgar_repo::new_client(), pkey_path)?;
    Ok(file.pkey)
}

static REPO_CLIENT: OnceLock<pkgar_repo::Agent> = OnceLock::new();

pub enum GenericPackage {
    File(PackageFile),

    Url(PackageUrl<'static>),
}

impl GenericPackage {
    pub fn verify(&mut self, base_dir: impl AsRef<Path>) -> Result<(), Error> {
        let base_dir = base_dir.as_ref();
        let entries = self.read_entries()?;
        let mut pkg_file = self.take_reader()?;
        let header = self.header();

        PackageFile::verify_inner(
            Path::new(self.path().as_ref()),
            base_dir,
            entries,
            &mut pkg_file,
            header,
        )?;

        self.restore_reader(pkg_file)?;

        Ok(())
    }
}
impl PackageSrc for GenericPackage {
    type Err = Error;

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, Self::Err> {
        match self {
            GenericPackage::File(package_file) => package_file.read_at(offset, buf),
            GenericPackage::Url(package_url) => {
                package_url.read_at(offset, buf).map_err(Error::from)
            }
        }
    }

    fn header(&self) -> Header {
        match self {
            GenericPackage::File(package_file) => package_file.header(),
            GenericPackage::Url(package_url) => package_url.header(),
        }
    }
}

impl<'a> PackageSrcExt<GenericReader<'static>> for GenericPackage {
    fn path(&self) -> Cow<'_, str> {
        match self {
            GenericPackage::File(package_file) => package_file.path(),
            GenericPackage::Url(package_url) => package_url.url().into(),
        }
    }

    fn take_reader(&mut self) -> Result<GenericReader<'static>, Error> {
        match self {
            GenericPackage::File(package_file) => {
                package_file.take_reader().map(GenericReader::File)
            }
            GenericPackage::Url(package_url) => Ok(GenericReader::Url(package_url.get_reader())),
        }
    }

    fn restore_reader(&mut self, reader: GenericReader<'static>) -> Result<(), Error> {
        match self {
            GenericPackage::File(package_file) => {
                let GenericReader::File(reader) = reader else {
                    return Err(Error::DataNotInitialized);
                };
                package_file.restore_reader(reader)
            }
            GenericPackage::Url(_) => Ok(()),
        }
    }
}

pub enum GenericReader<'a> {
    File(std::fs::File),

    Url(pkgar_repo::PackageUrlReader<'a>),
}

impl<'a> Read for GenericReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        match self {
            Self::File(f) => f.read(buf),

            Self::Url(u) => u.read(buf),
        }
    }
}

impl<'a> Seek for GenericReader<'a> {
    fn seek(&mut self, pos: SeekFrom) -> IoResult<u64> {
        match self {
            Self::File(f) => f.seek(pos),

            Self::Url(u) => u.seek(pos),
        }
    }
}

pub fn open_or_download_pkgar(
    archive_path: impl AsRef<Path>,
    pkey: &PublicKey,
) -> Result<GenericPackage, Error> {
    let archive_path = archive_path.as_ref();

    {
        if let Some(archive_path_str) = archive_path.to_str()
            && pkgar_repo::is_remote(archive_path_str)
        {
            let agent = REPO_CLIENT.get_or_init(pkgar_repo::new_client);

            let pkg = PackageUrl::new(agent, archive_path_str.to_string(), pkey)?;

            return Ok(GenericPackage::Url(pkg));
        }
    }

    Ok(GenericPackage::File(PackageFile::new(archive_path, pkey)?))
}
