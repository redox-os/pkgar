use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::slice::Iter;

use error_chain::bail;
use sodiumoxide::crypto::sign::PublicKey;
use pkgar_core::{Entry, Header, HEADER_SIZE, PackageData, PackageHead};

use crate::{Error, ErrorKind, ResultExt};
use crate::ext::PackageDataExt;

/// A `.pkgar_head` file on disk
#[derive(Debug)]
pub struct PackageHeadFile {
    header: Header,
    entries: Vec<Entry>,
}

impl PackageHeadFile {
    /// Deserialize the
    pub fn new(
        path: impl AsRef<Path>,
        public_key: &PublicKey,
    ) -> Result<PackageHeadFile, Error> {
        let path = path.as_ref();

        let mut file = File::open(&path)
            .chain_err(|| path )?;

        PackageHeadFile::from_reader(&mut file, public_key)
            .chain_err(|| path )
    }

    fn from_reader(
        reader: &mut impl Read,
        public_key: &PublicKey,
    ) -> Result<PackageHeadFile, Error> {
        let mut header_bytes = [0; HEADER_SIZE];
        let count = reader.read(&mut header_bytes[..])?;

        if count != HEADER_SIZE {
            bail!(ErrorKind::PackageHeadTooShort);
        }

        let header = *Header::new(&header_bytes[..], public_key)?;

        let entries_size = header.entries_size()?;
        let mut entries_bytes = Vec::with_capacity(entries_size as usize);
        let count = reader.read(&mut entries_bytes)?;

        if count != entries_size as usize {
            bail!(ErrorKind::PackageHeadTooShort);
        }

        Ok(PackageHeadFile {
            header,
            entries: header.entries(&entries_bytes)?.to_vec(),
        })
    }
}

/// A `.pkgar_data` file on disk
#[derive(Debug)]
pub struct PackageDataFile {
    path: PathBuf,

    src: File,
}

impl PackageDataFile {
    pub fn new(path: impl AsRef<Path>) -> Result<PackageDataFile, Error> {
        let path = path.as_ref().to_path_buf();
        let src = File::open(&path)
            .chain_err(|| &path )?;
        Ok(PackageDataFile {
            path,
            src,
        })
    }
}

impl PackageData for PackageDataFile {
    type Err = Error;

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        self.src.seek(SeekFrom::Start(offset))
            .chain_err(|| &self.path )?;
        Ok(self.src.read(buf)
           .chain_err(|| &self.path )?)
    }
}

/// A `.pkgar` file on disk (contains both head and data segments)
#[derive(Debug)]
pub struct PackageFile {
    path: PathBuf,
    
    head: PackageHeadFile,
    file: File,
}

impl PackageFile {
    pub fn new(
        path: impl AsRef<Path>,
        public_key: &PublicKey
    ) -> Result<PackageFile, Error> {
        let path = path.as_ref().to_path_buf();
        
        let mut file = File::open(&path)
            .chain_err(|| &path )?;
        
        let head = PackageHeadFile::from_reader(&mut file, public_key)
            .chain_err(|| &path )?;

        Ok(PackageFile {
            path,
            head,
            file,
        })
    }
}

impl PackageHead for PackageFile {
    fn header(&self) -> Header {
        self.head.header
    }

    fn entries(&self) -> Iter<'_, Entry> {
        self.head.entries.iter()
    }
}

impl PackageData for PackageFile {
    type Err = Error;
    
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, Self::Err> {
        let offset = self.head.header.total_size()? + offset;
        self.file.seek(SeekFrom::Start(offset))
            .chain_err(|| &self.path )?;
        Ok(self.file.read(buf)
           .chain_err(|| &self.path )?)
    }
}

impl PackageDataExt for PackageFile {
    fn path(&self) -> &Path {
        &self.path
    }
}

