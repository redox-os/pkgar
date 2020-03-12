use core::convert::TryFrom;
use core::mem;

use crate::{Entry, Error, Header, PublicKey};

pub enum PackageSrc<'a> {
    #[cfg(feature = "std")]
    File(&'a mut std::fs::File),
    Slice(&'a [u8]),
}

impl<'a> PackageSrc<'a> {
    pub fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), Error> {
        match self {
            #[cfg(feature = "std")]
            Self::File(file) => {
                use std::io::{Read, Seek, SeekFrom};
                file.seek(SeekFrom::Start(offset)).map_err(Error::Io)?;
                file.read_exact(buf).map_err(Error::Io)?;
            },
            Self::Slice(slice) => {
                let start = usize::try_from(offset).map_err(Error::TryFromInt)?;
                let end = start.checked_add(buf.len()).ok_or(Error::Overflow)?;
                if end > slice.len() {
                    //TODO: error type
                    return Err(Error::InvalidData);
                }
                buf.copy_from_slice(&slice[start..end]);
            },
        }
        Ok(())
    }
}

pub struct Package<'a> {
    src: PackageSrc<'a>,
    pub header: Header,
}

impl<'a> Package<'a> {
    pub fn new(mut src: PackageSrc<'a>, public_key: &PublicKey) -> Result<Self, Error> {
        let mut header_data = [0; mem::size_of::<Header>()];
        src.read_at(0, &mut header_data)?;
        let header = Header::new(&header_data, &public_key)?;
        Ok(Self {
            src,
            header: header.clone(),
        })
    }

    pub fn entries(&mut self) -> Result<PackageEntries, Error> {
        let entries_size = self.header.entries_size()
            .and_then(|x| usize::try_from(x).map_err(Error::TryFromInt))?;
        let mut entries_data = vec![0; entries_size];
        self.src.read_at(mem::size_of::<Header>() as u64, &mut entries_data)?;
        let entries = self.header.entries(&entries_data)?;
        Ok(PackageEntries {
            entries: entries.to_vec(),
            i: 0,
        })
    }
}

pub struct PackageEntries {
    entries: Vec<Entry>,
    i: usize,
}

impl Iterator for PackageEntries {
    type Item = PackageEntry;

    fn next(&mut self) -> Option<Self::Item> {
        let entry = self.entries.get(self.i)?;
        self.i += 1;
        Some(PackageEntry {
            entry: entry.clone()
        })
    }
}

pub struct PackageEntry {
    entry: Entry,
}

impl PackageEntry {
    pub fn hash(&self) -> &[u8] {
        &self.entry.blake3
    }

    pub fn mode(&self) -> u32 {
        self.entry.mode
    }

    pub fn path(&self) -> &[u8] {
        self.entry.path()
    }

    pub fn size(&self) -> u64 {
        self.entry.size
    }

    pub fn read_at(&self, package: &mut Package, offset: u64, buf: &mut [u8]) -> Result<(), Error> {
        let end = offset.checked_add(buf.len() as u64).ok_or(Error::Overflow)?;
        if end > self.entry.size {
            //TODO: error type
            return Err(Error::InvalidData);
        }
        package.src.read_at(
            // Offset to first entry data
            package.header.total_size()?
            // Add offset to provided entry data
            .checked_add(self.entry.offset).ok_or(Error::Overflow)?
            // Offset into entry data
            .checked_add(offset).ok_or(Error::Overflow)?,
            buf
        )
    }
}
