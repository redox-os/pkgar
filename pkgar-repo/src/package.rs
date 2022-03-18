use pkgar_core::{HEADER_SIZE, Header, PackageSrc};
use sodiumoxide::crypto::sign::PublicKey;
use std::{
    convert::TryFrom,
    io::Read
};

use crate::Error;

pub struct PackageUrl<'a> {
    client: &'a reqwest::blocking::Client,
    url: String,
    header: Header,
}

impl<'a> PackageUrl<'a> {
    pub fn new(
        client: &'a reqwest::blocking::Client,
        url: String,
        public_key: &PublicKey
    ) -> Result<Self, Error> {
        let mut new = Self {
            client,
            url,
            // Need a blank header to construct the PackageFile, since we need to
            //   use a method of PackageSrc in order to get the actual header...
            header: unsafe {
                *Header::new_unchecked(&[0; HEADER_SIZE])?
            },
        };
        new.header = new.read_header(public_key)?;
        Ok(new)
    }
}

impl<'a> PackageSrc for PackageUrl<'a> {
    type Err = Error;

    fn header(&self) -> Header {
        self.header
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, Self::Err> {
        if buf.is_empty() {
            return Ok(0);
        }
        let end_offset = offset.checked_add(
            u64::try_from(
                buf.len().checked_sub(1)
                    .ok_or(pkgar_core::Error::Overflow)?
            ).map_err(pkgar_core::Error::TryFromInt)?
        ).ok_or(pkgar_core::Error::Overflow)?;

        let range = format!("bytes={}-{}", offset, end_offset);
        eprint!("Request {} from {}", range, self.url);
        let mut response = self.client.get(&self.url)
            .header(reqwest::header::RANGE, range)
            .send()?
            .error_for_status()?;
        eprintln!(" = {:?}", response.status());
        response.read_exact(buf)?;
        Ok(buf.len())
    }
}
