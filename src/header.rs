//! The packed structs represent the on-disk format of pkgar

use core::convert::TryFrom;
use core::mem;
use plain::Plain;

use crate::{Entry, Error, PublicKey};

#[derive(Clone, Copy)]
#[repr(packed)]
pub struct Header {
    /// NaCl signature of header data
    pub signature: [u8; 64],
    /// NaCl public key used to generate signature
    pub public_key: [u8; 32],
    /// SHA-256 sum of entry data
    pub blake3: [u8; 32],
    /// Count of Entry structs, which immediately follow
    pub count: u64,
}

unsafe impl Plain for Header {}

impl Header {
    /// Parse header from raw header data and verify using public key
    pub fn new<'a>(data: &'a [u8], public_key: &PublicKey) -> Result<&'a Header, Error> {
        // Retrieve signed header data
        let signed = data.get(..mem::size_of::<Header>())
            .ok_or(Error::Plain(plain::Error::TooShort))?;

        // Verify signature and retrieve verified data
        let mut verified = [0; mem::size_of::<Header>()];
        let count = sodalite::sign_attached_open(&mut verified, signed, public_key.as_data())
            .map_err(|_err| Error::InvalidSignature)?;

        // Check that verified data matches signed data after skipping the signature
        if &verified[..count] != &signed[64..] {
            return Err(Error::InvalidData);
        }

        // Create header from signed data and check that public key matches
        let header: &Header = unsafe { Header::new_unchecked(signed)? };
        if &header.public_key != &public_key.as_data()[..] {
            return Err(Error::InvalidKey);
        }

        Ok(header)
    }

    /// Parse header from raw header data without verification
    pub unsafe fn new_unchecked<'a>(data: &'a [u8]) -> Result<&'a Header, Error> {
        plain::from_bytes(data)
            .map_err(Error::Plain)
    }

    /// Retrieve the size of the entries
    pub fn entries_size(&self) -> Result<u64, Error> {
        let entry_size = u64::try_from(mem::size_of::<Entry>())
            .map_err(Error::TryFromInt)?;
        self.count
            .checked_mul(entry_size)
            .ok_or(Error::Overflow)
    }

    /// Retrieve the size of the Header and its entries
    pub fn total_size(&self) -> Result<u64, Error> {
        let header_size = u64::try_from(mem::size_of::<Header>())
            .map_err(Error::TryFromInt)?;
        self.entries_size()?
            .checked_add(header_size)
            .ok_or(Error::Overflow)
    }

    /// Parse entries from raw entries data and verify using blake3
    pub fn entries<'a>(&self, data: &'a [u8]) -> Result<&'a [Entry], Error> {
        let entries_size = usize::try_from(self.entries_size()?)
            .map_err(Error::TryFromInt)?;

        let entries_data = data.get(..entries_size)
            .ok_or(Error::Plain(plain::Error::TooShort))?;

        let hash = blake3::hash(&entries_data);

        if &self.blake3 != hash.as_bytes() {
            return Err(Error::InvalidBlake3);
        }

        unsafe { Self::entries_unchecked(entries_data) }
    }

    /// Parse entries from raw entries data without verification
    pub unsafe fn entries_unchecked<'a>(data: &'a [u8]) -> Result<&'a [Entry], Error> {
        plain::slice_from_bytes(data)
            .map_err(Error::Plain)
    }
}
