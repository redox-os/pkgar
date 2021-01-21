use core::convert::TryFrom;
use core::slice::Iter;

use sodiumoxide::crypto::sign::PublicKey;

use crate::{Entry, Error, Header};

/// The head segment of an archive.
pub trait PackageHead {
    fn header(&self) -> Header;
    
    fn entries(&self) -> Iter<'_, Entry>;
}

/// The data segment of an archive.
pub trait PackageData {
    type Err: From<Error>;
    
    /// Fill `buf` from the given `offset` within the data segment
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, Self::Err>;
    
    /// Fill `buf` from a given entry's data + `offset` within that entry
    fn read_entry(
        &mut self,
        entry: Entry,
        offset: usize,
        buf: &mut [u8],
    ) -> Result<usize, Self::Err> {
        if offset as u64 > entry.size {
            return Ok(0);
        }
        
        let mut end = usize::try_from(entry.size - offset as u64)
            .map_err(Error::TryFromInt)?;
        
        if end > buf.len() {
            end = buf.len();
        }
        
        let offset = entry.offset + offset as u64;
        
        self.read_at(offset as u64, &mut buf[..end])
    }
}

/// A package based on a slice
//TODO: Test this impl...
pub struct PackageBuf<'a> {
    // Head and data segments in a single buffer
    src: &'a [u8],
    
    header: Header,
    entries: &'a [Entry],
}

impl<'a> PackageBuf<'a> {
    /// `src` must have both the head and data segments of the package
    pub fn new(src: &'a [u8], public_key: &PublicKey) -> Result<PackageBuf<'a>, Error> {
        let header = *Header::new(&src, &public_key)?;
        Ok(PackageBuf {
            src,
            header,
            entries: header.entries(&src)?,
        })
    }
}

impl PackageHead for PackageBuf<'_> {
    fn header(&self) -> Header {
        self.header
    }
    
    fn entries(&self) -> Iter<'_, Entry> {
        self.entries.iter()
    }
}

impl PackageData for PackageBuf<'_> {
    type Err = Error;
    
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        // Have to account for the head portion
        let start = usize::try_from(offset + self.header.total_size()?)?;
        
        let len = self.src.len();
        if start >= len {
            return Ok(0);
        }
        let mut end = start.checked_add(buf.len())
            .ok_or(Error::Overflow)?;
        if end > len {
            end = len;
        }
        buf.copy_from_slice(&self.src[start..end]);
        Ok(end.checked_sub(start).unwrap())
    }
}

