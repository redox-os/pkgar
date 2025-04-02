use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use pkgar_core::{Header, PackageSrc, PublicKey, HEADER_SIZE};

use crate::ext::PackageSrcExt;
use crate::Error;

#[derive(Debug)]
pub struct PackageFile {
    path: PathBuf,
    pub(crate) src: BufReader<File>,
    header: Header,
}

impl PackageFile {
    pub fn new(path: impl AsRef<Path>, public_key: &PublicKey) -> Result<PackageFile, Error> {
        let zeroes = [0; HEADER_SIZE];
        let path = path.as_ref().to_path_buf();

        let file = OpenOptions::new()
            .read(true)
            .open(&path)
            .map_err(|source| Error::Io {
                source,
                path: Some(path.clone()),
            })?;

        let mut new = PackageFile {
            path,
            src: BufReader::new(file),

            // Need a blank header to construct the PackageFile, since we need to
            //   use a method of PackageSrc in order to get the actual header...
            header: unsafe { *Header::new_unchecked(&zeroes)? },
        };

        new.header = new.read_header(public_key)?;
        Ok(new)
    }
}

impl PackageSrc for PackageFile {
    type Err = Error;

    fn header(&self) -> Header {
        self.header
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, Self::Err> {
        self.src
            .seek(SeekFrom::Start(offset))
            .map_err(|source| Error::Io { source, path: None })?;
        self.src
            .read_exact(buf)
            .map_err(|source| Error::Io { source, path: None })?;
        Ok(buf.len())
    }
}

impl PackageSrcExt for PackageFile {
    fn path(&self) -> &Path {
        &self.path
    }
}
