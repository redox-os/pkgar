use alloc::vec::Vec;
use core::convert::{AsRef, TryFrom};

use sodiumoxide::crypto::sign::PublicKey;

use crate::{Entry, Error, HEADER_SIZE, Header};

pub trait PackageSrc {
    type Err: From<Error>;
    
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, Self::Err>;
    
    /// Read from this src at a given entry's data with a given offset within that entry
    fn read_entry(&mut self, entry: Entry, offset: u64, buf: &mut [u8]) -> Result<usize, Self::Err> {
        if offset > entry.size {
            return Ok(0);
        }
        
        let mut end = usize::try_from(entry.size - offset)
            .map_err(Error::TryFromInt)?;
        
        if end > buf.len() {
            end = buf.len();
        }
        
        let header = self.header_unchecked()?;
        
        let offset =
            HEADER_SIZE as u64 +
            header.entries_size()? +
            entry.offset + offset;
        
        self.read_at(offset, &mut buf[..end])
    }
    
    fn header(&mut self, public_key: &PublicKey) -> Result<Header, Self::Err> {
        let mut header_data = [0; HEADER_SIZE];
        self.read_at(0, &mut header_data)?;
        let header = Header::new(&header_data, &public_key)?;
        Ok(header.clone())
    }
    
    fn header_unchecked(&mut self) -> Result<Header, Self::Err> {
        let mut header = [0; HEADER_SIZE];
        self.read_at(0, &mut header)?;
        Ok(unsafe { Header::new_unchecked(&header) }?
            .clone())
    }
    
    fn entries(&mut self, public_key: &PublicKey) -> Result<Vec<Entry>, Self::Err> {
        let header = self.header(public_key)?;
        let entries_size = header.entries_size()
            .and_then(|rslt| usize::try_from(rslt)
                .map_err(Error::TryFromInt)
            )?;
        let mut entries_data = vec![0; entries_size];
        self.read_at(HEADER_SIZE as u64, &mut entries_data)?;
        let entries = header.entries(&entries_data)?;
        Ok(entries.to_vec())
    }
}

impl<T: AsRef<[u8]>> PackageSrc for T {
    type Err = Error;
    
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        let start = usize::try_from(offset)
            .map_err(Error::TryFromInt)?;
        let len = self.as_ref().len();
        if start >= len {
            return Ok(0);
        }
        let mut end = start.checked_add(buf.len())
            .ok_or(Error::Overflow)?;
        if end > len {
            end = len;
        }
        buf.copy_from_slice(&self.as_ref()[start..end]);
        Ok(end.checked_sub(start).unwrap())
    }
}

