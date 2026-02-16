use alloc::vec;
use alloc::vec::Vec;
use bytemuck::Zeroable;
use core::convert::TryFrom;

use dryoc::classic::crypto_sign_ed25519::PublicKey;

use crate::{Entry, Error, Header, HEADER_SIZE};

/// Implements functions aiding reading the pkgar file based on general sources
pub trait PackageSrc {
    type Err: From<Error>;

    /// Read at specific byte offset. mutable because of Seekable.
    /// This is must implemented for reading header and entries.
    /// Users should not use this directly.
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, Self::Err>;

    /// Read data at specific byte offset. mutable because of Seekable.
    /// This is must implemented for reading data, offset is relative to the entry (data_offset + entry.offset).
    fn read_data(&mut self, entry: Entry, offset: u64, buf: &mut [u8]) -> Result<usize, Self::Err>;

    /// Get cached header
    fn header(&self) -> Header;

    /// Init data read. data_offset must be saved by implementors to allow read_data.
    /// This may be implemented for e.g. reading compressed package.
    fn init_data_read(&mut self, data_offset: u64, data_len: u64) -> Result<(), Self::Err>;

    /// Should be called at initialization by implementors to read headers.
    /// Users should use header() instead.
    fn read_header(&mut self, public_key: &PublicKey) -> Result<Header, Self::Err> {
        let mut header_data = [0; HEADER_SIZE];
        self.read_at(0, &mut header_data)?;
        let header = Header::new(&header_data, public_key)?;
        Ok(*header)
    }

    /// Read all entries. This also initialize data reading.
    fn read_entries(&mut self) -> Result<Vec<Entry>, Self::Err> {
        let header = self.header();
        let entries_size = header
            .entries_size()
            .and_then(|rslt| usize::try_from(rslt).map_err(Error::TryFromInt))?;
        let mut entries_data = vec![0; entries_size];
        self.read_at(HEADER_SIZE as u64, &mut entries_data)?;
        let entries = header.entries(&entries_data)?;

        let data_offset = self.header().total_size()?;
        let mut data_size: u64 = 0;
        for entry in entries {
            data_size = data_size.checked_add(entry.size).ok_or(Error::Overflow)?;
        }
        self.init_data_read(data_offset, data_size)?;

        Ok(entries.to_vec())
    }

    /// Helper to get end of buffer relative to entry
    fn calculate_end(entry: Entry, offset: u64, buf: &mut [u8]) -> Result<usize, Self::Err> {
        if offset as u64 > entry.size {
            return Ok(0);
        }
        let mut end = usize::try_from(entry.size - offset as u64).map_err(Error::TryFromInt)?;
        if end > buf.len() {
            end = buf.len();
        }
        Ok(end)
    }

    /// Helper to get range relative to buffer
    fn calculate_range(
        src_len: usize,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<(usize, usize), Self::Err> {
        let start = usize::try_from(offset).map_err(Error::TryFromInt)?;
        if start >= src_len {
            return Ok((0, 0));
        }
        let mut end = start.checked_add(buf.len()).ok_or(Error::Overflow)?;
        if end > src_len {
            end = src_len;
        }

        Ok((start, end))
    }
}

//TODO: Test this impl...
pub struct PackageBuf<'a> {
    src: &'a [u8],
    header: Header,
    data_offset: Option<u64>,
}

impl<'a> PackageBuf<'a> {
    pub fn new(src: &'a [u8], public_key: &PublicKey) -> Result<PackageBuf<'a>, Error> {
        let mut new = PackageBuf {
            src,
            header: Header::zeroed(),
            data_offset: None,
        };
        new.header = *Header::new(new.src, public_key)?;
        Ok(new)
    }
}

impl PackageSrc for PackageBuf<'_> {
    type Err = Error;

    fn header(&self) -> Header {
        self.header
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        let (start, end) = Self::calculate_range(self.src.len(), offset, buf)?;
        buf.copy_from_slice(&self.src[start..end]);
        Ok(buf.len())
    }

    fn init_data_read(&mut self, data_offset: u64, _data_len: u64) -> Result<(), Self::Err> {
        self.data_offset = Some(data_offset);
        match self.header.flags.packaging() {
            crate::Packaging::Uncompressed => Ok(()),
            // TODO: Unable to support LZMA2 due to crate conflict, move to "pkgar" crate maybe
            _ => Err(Error::NotSupported),
        }
    }

    fn read_data(&mut self, entry: Entry, offset: u64, buf: &mut [u8]) -> Result<usize, Self::Err> {
        let data_offset = self.data_offset.ok_or(Error::NotInitialized)?;
        self.read_at(data_offset + entry.offset + offset, buf)
    }
}
