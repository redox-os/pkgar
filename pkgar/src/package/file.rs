use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use bytemuck::Zeroable;
use pkgar_core::{Header, PackageSrc, PublicKey};

use crate::ext::PackageSrcExt;
use crate::{wrap_io_err, Error};

#[derive(Debug)]
pub struct PackageFile {
    path: PathBuf,
    src: Option<BufReader<File>>,
    header: Header,
}

impl PackageFile {
    pub fn new(path: impl AsRef<Path>, public_key: &PublicKey) -> Result<PackageFile, Error> {
        let path = path.as_ref().to_path_buf();

        let file = OpenOptions::new()
            .read(true)
            .open(&path)
            .map_err(|source| Error::Io {
                source,
                path: Some(path.clone()),
                context: "Open",
            })?;

        let mut new = PackageFile {
            path,
            src: Some(BufReader::new(file)),

            // Need a blank header to construct the PackageFile, since we need to
            //   use a method of PackageSrc in order to get the actual header...
            header: Header::zeroed(),
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
        let Some(src) = &mut self.src else {
            return Err(Error::DataNotInitialized);
        };
        src.seek(SeekFrom::Start(offset))
            .map_err(wrap_io_err!("Seek at read_at"))?;
        src.read_exact(buf)
            .map_err(wrap_io_err!("Read at read_at"))?;
        Ok(buf.len())
    }
}

impl PackageSrcExt<File> for PackageFile {
    fn path(&self) -> &Path {
        &self.path
    }

    fn take_reader(&mut self) -> Result<File, Error> {
        match self.src.take() {
            Some(reader) => Ok(reader.into_inner()),
            None => Err(Error::DataNotInitialized),
        }
    }

    fn restore_reader(&mut self, reader: File) -> Result<(), Error> {
        match self.src {
            Some(_) => Err(Error::Core(pkgar_core::Error::NotSupported)),
            ref mut src => {
                *src = Some(BufReader::new(reader));
                Ok(())
            }
        }
    }
}
