use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use sodiumoxide::crypto::sign::PublicKey;
use pkgar_core::{Header, HEADER_SIZE, PackageSrc};

use crate::{Error, ResultExt};
use crate::ext::PackageSrcExt;

#[derive(Debug)]
pub struct PackageFile {
    path: PathBuf,
    src: BufReader<File>,
    header: Header,
}

impl PackageFile {
    pub fn new(
        path: impl AsRef<Path>,
        public_key: &PublicKey
    ) -> Result<PackageFile, Error> {
        let zeroes = [0; HEADER_SIZE];
        let path = path.as_ref().to_path_buf();
        
        let file = OpenOptions::new()
            .read(true)
            .open(&path)
            .chain_err(|| &path )?;
        
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
        self.src.seek(SeekFrom::Start(offset))?;
        Ok(self.src.read(buf)?)
    }
}

impl PackageSrcExt for PackageFile {
    fn path(&self) -> &Path {
        &self.path
    }
}

