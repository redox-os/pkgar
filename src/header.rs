//! The packed structs represent the on-disk format of pkgar

use core::convert::TryFrom;
use core::mem;
use plain::Plain;
use sha2::{Digest, Sha256};

use crate::{Entry, Error, PublicKey};

#[derive(Clone, Copy)]
#[repr(packed)]
pub struct Header {
    /// NaCl signature of header data
    pub signature: [u8; 64],
    /// NaCl public key used to generate signature
    pub public_key: [u8; 32],
    /// SHA-256 sum of entry data
    pub sha256: [u8; 32],
    /// Count of Entry structs, which immediately follow
    pub count: u64,
}

unsafe impl Plain for Header {}

impl Header {
    /// Parse header from raw header data and verify using public key
    pub fn new<'a>(data: &'a [u8], public_key: &PublicKey) -> Result<&'a Header, Error> {
        let signed = data.get(..mem::size_of::<Header>())
            .ok_or(Error::Plain(plain::Error::TooShort))?;

        let header: &Header = plain::from_bytes(signed).map_err(Error::Plain)?;
        if &header.public_key != &public_key.as_data()[..] {
            return Err(Error::InvalidKey);
        }

        let mut verified = [0; mem::size_of::<Header>()];
        let count = sodalite::sign_attached_open(&mut verified, signed, &header.public_key)
            .map_err(|_err| Error::InvalidSignature)?;

        // Check that verified data matches signed data after skipping the signature
        if &verified[..count] != &signed[64..] {
            return Err(Error::InvalidData);
        }

        Ok(header)
    }

    /// Retrieve the size of the entries
    pub fn entries_size(&self) -> Option<u64> {
        self.count
            .checked_mul(mem::size_of::<Entry>() as u64)
    }

    /// Retrieve the size of the Header and its entries
    pub fn total_size(&self) -> Option<u64> {
        self.entries_size()
            .and_then(|x| x.checked_add(mem::size_of::<Header>() as u64))
    }

    /// Parse entries from raw entries data and verify using sha256
    pub fn entries<'a>(&self, data: &'a [u8]) -> Result<&'a [Entry], Error> {
        let entries_size = self.entries_size()
            .and_then(|x| usize::try_from(x).ok())
            .ok_or(Error::Overflow)?;

        let entries_data = data.get(..entries_size)
            .ok_or(Error::Plain(plain::Error::TooShort))?;

        let sha256 = {
            let mut hasher = Sha256::new();
            hasher.input(&entries_data);
            hasher.result()
        };

        if &self.sha256 != sha256.as_slice() {
            return Err(Error::InvalidSha256);
        }

        plain::slice_from_bytes(entries_data)
            .map_err(Error::Plain)
    }
}
