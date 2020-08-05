use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use sodiumoxide::crypto::sign::PublicKey;
use pkgar_core::{Header, HEADER_SIZE, PackageSrc};

use crate::Error;

#[derive(Debug)]
pub struct PackageFile {
    path: PathBuf,
    pub(crate) src: File,
    header: Header,
}

impl PackageFile {
    pub fn new(path: impl AsRef<Path>, public_key: &PublicKey) -> Result<PackageFile, Error> {
        let zeroes = [0; HEADER_SIZE];
        let mut new = PackageFile {
            path: path.as_ref().to_path_buf(),
            src: OpenOptions::new()
                .read(true)
                .open(&path)
                .map_err(|e| Error::Io {
                    reason: "Reading header".to_string(),
                    file: path.as_ref().to_path_buf(),
                    source: e,
                })?,
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
        self.src.seek(SeekFrom::Start(offset))
            .map_err(|e| Error::Io {
                reason: format!("Seeking to {}", offset),
                file: self.path.clone(),
                source: e,
            })?;
        Ok(self.src.read(buf)
           .map_err(|e| Error::Io {
               reason: "Read".to_string(),
               file: self.path.clone(),
               source: e,
           })?)
    }
}

