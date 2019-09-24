use core::convert::TryFrom;
use core::mem;
use sha2::{Sha256, Digest};

use crate::packed::{PackedEntry, PackedHeader};

pub enum Error {
    InvalidData,
    InvalidKey,
    InvalidSha256,
    InvalidSignature,
    Plain(plain::Error),
    Overflow,
}

pub struct Header<'a> {
    header: &'a PackedHeader,
    entries: &'a [PackedEntry],
}

impl<'a> Header<'a> {
    pub unsafe fn new_unsigned(data: &'a [u8]) -> Result<Header<'a>, Error> {
        let header: &PackedHeader = plain::from_bytes(data).map_err(Error::Plain)?;

        let total_size = header.size()
            .and_then(|x| usize::try_from(x).ok())
            .ok_or(Error::Overflow)?;

        let entries_data = data.get(mem::size_of::<PackedHeader>()..total_size)
            .ok_or(Error::Plain(plain::Error::TooShort))?;

        let sha256 = {
            let mut hasher = Sha256::new();
            hasher.input(&entries_data);
            hasher.result()
        };

        if &header.sha256 != sha256.as_slice() {
            return Err(Error::InvalidSha256);
        }

        let entries = plain::slice_from_bytes(entries_data).map_err(Error::Plain)?;

        Ok(Header {
            header,
            entries,
        })
    }

    pub fn new(data: &'a [u8], public_key: &[u8]) -> Result<Header<'a>, Error> {
        let signed = data.get(..mem::size_of::<PackedHeader>())
            .ok_or(Error::Plain(plain::Error::TooShort))?;

        let header: &PackedHeader = plain::from_bytes(signed).map_err(Error::Plain)?;
        if &header.public_key != public_key {
            return Err(Error::InvalidKey);
        }

        let mut verified = [0; mem::size_of::<PackedHeader>()];
        let count = sodalite::sign_attached_open(&mut verified, signed, &header.public_key)
            .map_err(|_err| Error::InvalidSignature)?;

        // Check that verified data matches signed data after skipping the signature
        if &verified[..count] != &signed[64..] {
            return Err(Error::InvalidData);
        }

        unsafe { Header::new_unsigned(data) }
    }
}
