use pkgar_core::{Entry, Header, PackageSrc, PublicKey, Zeroable};
use std::{convert::TryFrom, io::Read};

use crate::Error;

pub struct PackageUrl<'a> {
    client: &'a reqwest::blocking::Client,
    url: String,
    header: Header,
    data_offset: Option<u64>,
}

impl<'a> PackageUrl<'a> {
    pub fn new(
        client: &'a reqwest::blocking::Client,
        url: String,
        public_key: &PublicKey,
    ) -> Result<Self, Error> {
        let mut new = Self {
            client,
            url,
            // Need a blank header to construct the PackageFile, since we need to
            // use a method of PackageSrc in order to get the actual header...
            header: Header::zeroed(),
            data_offset: None,
        };
        new.header = new.read_header(public_key)?;
        Ok(new)
    }
}

impl PackageSrc for PackageUrl<'_> {
    type Err = Error;

    fn header(&self) -> Header {
        self.header
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, Self::Err> {
        if buf.is_empty() {
            return Ok(0);
        }
        let end_offset = offset
            .checked_add(
                u64::try_from(
                    buf.len()
                        .checked_sub(1)
                        .ok_or(pkgar_core::Error::Overflow)?,
                )
                .map_err(pkgar_core::Error::TryFromInt)?,
            )
            .ok_or(pkgar_core::Error::Overflow)?;

        let range = format!("bytes={}-{}", offset, end_offset);
        eprint!("Request {} from {}", range, self.url);
        let mut response = self
            .client
            .get(&self.url)
            .header(reqwest::header::RANGE, range)
            .send()?
            .error_for_status()?;
        eprintln!(" = {:?}", response.status());
        response.read_exact(buf)?;
        Ok(buf.len())
    }

    fn init_data_read(&mut self, data_offset: u64, _data_len: u64) -> Result<(), Self::Err> {
        self.data_offset = Some(data_offset);
        match self.header.flags.packaging() {
            pkgar_core::Packaging::Uncompressed => Ok(()),
            // TODO: LZMA2 support
            _ => Err(Error::Pkgar(Box::new(pkgar::Error::Core(
                pkgar_core::Error::NotInitialized,
            )))),
        }
    }

    fn read_data(&mut self, entry: Entry, offset: u64, buf: &mut [u8]) -> Result<usize, Self::Err> {
        let data_offset = self
            .data_offset
            .ok_or(Error::Pkgar(Box::new(pkgar::Error::Core(
                pkgar_core::Error::NotInitialized,
            ))))?;
        self.read_at(offset + entry.offset + data_offset, buf)
    }
}
