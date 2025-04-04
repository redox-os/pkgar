use bytemuck::Zeroable;
use pkgar_core::{Entry, Header, PackageSrc, PublicKey};
use std::{
    convert::TryFrom,
    fs::{File, OpenOptions},
    io::{BufReader, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use crate::ext::EntryExt;
use crate::Error;

#[derive(Debug)]
pub struct PackageHead {
    head_path: PathBuf,
    root_path: PathBuf,
    pub(crate) src: BufReader<File>,
    header: Header,
}

impl PackageHead {
    pub fn new(
        head_path: impl AsRef<Path>,
        root_path: impl AsRef<Path>,
        public_key: &PublicKey,
    ) -> Result<PackageHead, Error> {
        let head_path = head_path.as_ref().to_path_buf();
        let root_path = root_path.as_ref().to_path_buf();

        let file = OpenOptions::new()
            .read(true)
            .open(&head_path)
            .map_err(|source| Error::Io {
                source,
                path: Some(head_path.clone()),
            })?;

        let mut new = PackageHead {
            head_path,
            root_path,
            src: BufReader::new(file),

            // Need a blank header to construct the PackageHead, since we need to
            //   use a method of PackageSrc in order to get the actual header...
            header: Header::zeroed(),
        };

        new.header = new.read_header(public_key)?;
        Ok(new)
    }
}

impl PackageSrc for PackageHead {
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
            .map_err(|source| Error::Io { source, path: None })
            .map(|()| buf.len())
    }

    /// Read from this src at a given entry's data with a given offset within that entry
    fn read_entry(
        &mut self,
        entry: Entry,
        offset: usize,
        buf: &mut [u8],
    ) -> Result<usize, Self::Err> {
        if offset as u64 > entry.size {
            return Ok(0);
        }

        let mut end =
            usize::try_from(entry.size - offset as u64).map_err(pkgar_core::Error::TryFromInt)?;

        if end > buf.len() {
            end = buf.len();
        }

        let relative_path = entry.check_path()?;
        let entry_path = self.root_path.join(relative_path);
        let mut entry_file = OpenOptions::new()
            .read(true)
            .open(&entry_path)
            .map_err(|source| Error::Io {
                source,
                path: Some(entry_path.clone()),
            })?;

        entry_file
            .seek(SeekFrom::Start(offset as u64))
            .map_err(|source| Error::Io {
                source,
                path: Some(entry_path.clone()),
            })?;

        entry_file
            .read(&mut buf[..end])
            .map_err(|source| Error::Io {
                source,
                path: Some(entry_path),
            })
    }
}
