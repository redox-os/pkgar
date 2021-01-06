use alloc::vec;
use alloc::vec::Vec;
use core::convert::TryFrom;

use sodiumoxide::crypto::sign::PublicKey;

use crate::{Entry, Error, HEADER_SIZE, Header};

pub trait PackageSrc {
    type Err: From<Error>;
    
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, Self::Err>;
    
    fn header(&self) -> Header;
    
    /// Users of implementors of `PackageSrc` should use `header` instead of `read_header` for
    /// cheap header access.
    /// Implementors of `PackageSrc` should call this function during initialization and store
    /// the result to pass out with `header`.
    fn read_header(&mut self, public_key: &PublicKey) -> Result<Header, Self::Err> {
        let mut header_data = [0; HEADER_SIZE];
        self.read_at(0, &mut header_data)?;
        let header = Header::new(&header_data, &public_key)?;
        Ok(header.clone())
    }
    
    fn read_entries(&mut self) -> Result<Vec<Entry>, Self::Err> {
        let header = self.header();
        let entries_size = header.entries_size()
            .and_then(|rslt| usize::try_from(rslt)
                .map_err(Error::TryFromInt)
            )?;
        let mut entries_data = vec![0; entries_size];
        self.read_at(HEADER_SIZE as u64, &mut entries_data)?;
        let entries = header.entries(&entries_data)?;
        Ok(entries.to_vec())
    }
    
    /// Read from this src at a given entry's data with a given offset within that entry
    fn read_entry(&mut self, entry: Entry, offset: usize, buf: &mut [u8]) -> Result<usize, Self::Err> {
        if offset as u64 > entry.size {
            return Ok(0);
        }
        
        let mut end = usize::try_from(entry.size - offset as u64)
            .map_err(Error::TryFromInt)?;
        
        if end > buf.len() {
            end = buf.len();
        }
        
        let offset =
            HEADER_SIZE as u64 +
            self.header().entries_size()? +
            entry.offset + offset as u64;
        
        self.read_at(offset as u64, &mut buf[..end])
    }
}

//TODO: Test this impl...
pub struct PackageBuf<'a> {
    src: &'a [u8],
    header: Header,
}

impl<'a> PackageBuf<'a> {
    pub fn new(src: &'a [u8], public_key: &PublicKey) -> Result<PackageBuf<'a>, Error> {
        let zeroes = [0; HEADER_SIZE];
        let mut new = PackageBuf {
            src,
            header: unsafe { *Header::new_unchecked(&zeroes)? },
        };
        new.header = *Header::new(&new.src, &public_key)?;
        Ok(new)
    }
}

impl PackageSrc for PackageBuf<'_> {
    type Err = Error;
    
    fn header(&self) -> Header {
        self.header
    }
    
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        let start = usize::try_from(offset)
            .map_err(Error::TryFromInt)?;
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

