use blake3::Hash;
use core::convert::TryFrom;
use core::mem;

use sodiumoxide::crypto::sign::PublicKey;

use crate::{Entry, Error, Header};

pub enum PackageSrc<'a> {
    #[cfg(feature = "std")]
    File(&'a mut std::fs::File),
    Slice(&'a [u8]),
}

impl<'a> PackageSrc<'a> {
    pub fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        match self {
            #[cfg(feature = "std")]
            Self::File(file) => {
                use std::io::{Read, Seek, SeekFrom};
                file.seek(SeekFrom::Start(offset)).map_err(Error::Io)?;
                file.read(buf).map_err(Error::Io)
            },
            Self::Slice(slice) => {
                let start = usize::try_from(offset).map_err(Error::TryFromInt)?;
                if start >= slice.len() {
                    return Ok(0);
                }
                let mut end = start.checked_add(buf.len()).ok_or(Error::Overflow)?;
                if end > slice.len() {
                    end = slice.len();
                }
                buf.copy_from_slice(&slice[start..end]);
                Ok(end.checked_sub(start).unwrap())
            },
        }
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
    pub fn hash(&self) -> [u8; 32] {
        self.entry.blake3
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

    pub fn read_at(&self, package: &mut Package, offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        if offset >= self.entry.size {
            return Ok(0);
        }
        let mut end = offset.checked_add(buf.len() as u64).ok_or(Error::Overflow)?;
        if end > self.entry.size {
            end = self.entry.size;
        }
        let buf_len = usize::try_from(end.checked_sub(offset).unwrap()).map_err(Error::TryFromInt)?;
        package.src.read_at(
            // Offset to first entry data
            package.header.total_size()?
            // Add offset to provided entry data
            .checked_add(self.entry.offset).ok_or(Error::Overflow)?
            // Offset into entry data
            .checked_add(offset).ok_or(Error::Overflow)?,
            &mut buf[..buf_len]
        )
    }

    #[cfg(feature = "std")]
    pub fn copy_hash<W: std::io::Write>(&self, package: &mut Package, mut write: W, buf: &mut [u8]) -> Result<(u64, Hash), Error> {
        let mut hasher = blake3::Hasher::new();
        let mut total = 0;
        loop {
            let count = self.read_at(package, total, buf)?;
            if count == 0 {
                break;
            }
            total += count as u64;
            //TODO: Progress
            write.write_all(&buf[..count])
                .map_err(Error::Io)?;
            hasher.update_with_join::<blake3::join::RayonJoin>(&buf[..count]);
        }
        Ok((total, hasher.finalize()))
    }
}
