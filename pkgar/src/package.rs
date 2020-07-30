use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use pkgar_core::PackageSrc;

use crate::Error;

pub struct PackageFile {
    pub(crate) src: File,
}

impl PackageFile {
    pub fn new(path: impl AsRef<Path>) -> Result<PackageFile, Error> {
        Ok(PackageFile {
            src: OpenOptions::new()
                .read(true)
                .open(path)?,
        })
    }
}

impl PackageSrc for PackageFile {
    type Err = Error;
    
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, Self::Err> {
        self.src.seek(SeekFrom::Start(offset))?;
        Ok(self.src.read(buf)?)
    }
}

