use bytemuck::Zeroable;
use pkgar_core::{Entry, Header, PackageSrc, PublicKey};
use std::{
    fs::{File, OpenOptions},
    io::{BufReader, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use crate::ext::EntryExt;
use crate::Error;

#[derive(Debug)]
pub struct PackageHead {
    #[allow(dead_code)]
    head_path: PathBuf,
    root_path: Option<PathBuf>,
    pub(crate) src: BufReader<File>,
    header: Header,
}

impl PackageHead {
    pub fn from_head_only(head_path: impl AsRef<Path>) -> Result<PackageHead, Error> {
        let mut new = new_inner(head_path, None)?;
        let mut header_data = [0; pkgar_core::HEADER_SIZE];
        new.read_at(0, &mut header_data)?;
        new.header = unsafe { *Header::new_unchecked(&header_data)? };

        Ok(new)
    }

    pub fn new(
        head_path: impl AsRef<Path>,
        root_path: impl AsRef<Path>,
        public_key: &PublicKey,
    ) -> Result<PackageHead, Error> {
        let mut new = new_inner(head_path, Some(root_path.as_ref()))?;
        new.header = new.read_header(public_key)?;
        Ok(new)
    }
}

fn new_inner(head_path: impl AsRef<Path>, root_path: Option<&Path>) -> Result<PackageHead, Error> {
    let head_path = head_path.as_ref().to_path_buf();
    let root_path = root_path.map(|p| p.to_path_buf());
    let file = OpenOptions::new()
        .read(true)
        .open(&head_path)
        .map_err(|source| Error::Io {
            source,
            path: Some(head_path.clone()),
            context: "Open",
        })?;
    let new = PackageHead {
        head_path,
        root_path,
        src: BufReader::new(file),

        // Need a blank header to construct the PackageHead, since we need to
        //   use a method of PackageSrc in order to get the actual header...
        header: Header::zeroed(),
    };
    Ok(new)
}

impl PackageSrc for PackageHead {
    type Err = Error;

    fn header(&self) -> Header {
        self.header
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, Self::Err> {
        self.src
            .seek(SeekFrom::Start(offset))
            .map_err(|source| Error::Io {
                source,
                path: None,
                context: "Seek",
            })?;
        self.src
            .read_exact(buf)
            .map_err(|source| Error::Io {
                source,
                path: None,
                context: "Read",
            })
            .map(|()| buf.len())
    }

    /// Read from this src at a given entry's data with a given offset within that entry
    fn read_data(&mut self, entry: Entry, offset: u64, buf: &mut [u8]) -> Result<usize, Self::Err> {
        let end = <PackageHead as PackageSrc>::calculate_end(entry, offset, buf)?;
        let root_path = self
            .root_path
            .clone()
            .ok_or(Error::Core(pkgar_core::Error::NotSupported))?;

        let relative_path = entry.check_path()?;
        let entry_path = root_path.join(relative_path);
        let mut entry_file = OpenOptions::new()
            .read(true)
            .open(&entry_path)
            .map_err(|source| Error::Io {
                source,
                path: Some(entry_path.clone()),
                context: "Open",
            })?;

        entry_file
            .seek(SeekFrom::Start(offset as u64))
            .map_err(|source| Error::Io {
                source,
                path: Some(entry_path.clone()),
                context: "Seek",
            })?;

        entry_file
            .read(&mut buf[..end])
            .map_err(|source| Error::Io {
                source,
                path: Some(entry_path),
                context: "Read",
            })
    }

    fn init_data_read(&mut self, _: u64, _: u64) -> Result<(), Self::Err> {
        Ok(())
    }
}
