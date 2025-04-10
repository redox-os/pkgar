//! The packed structs represent the on-disk format of pkgar

use alloc::vec;
use bytemuck::{Pod, PodCastError, Zeroable};
use core::convert::TryFrom;
use core::mem;

use crate::{dryoc::classic::crypto_sign::crypto_sign_open, Entry, Error, PublicKey};

#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(packed, C)]
pub struct Header {
    /// NaCl signature of header data
    pub signature: [u8; 64],
    /// NaCl public key used to generate signature
    pub public_key: [u8; 32],
    /// Blake3 sum of entry data
    pub blake3: [u8; 32],
    /// Count of Entry structs, which immediately follow
    pub count: u64,
}

impl Header {
    /// Parse header from raw header data and verify using public key
    pub fn new<'a>(data: &'a [u8], public_key: &PublicKey) -> Result<&'a Header, Error> {
        // Retrieve signed header data
        let signed = data
            .get(..mem::size_of::<Header>())
            .ok_or(Error::Cast(PodCastError::SizeMismatch))?;

        // Verify signature
        let mut verified = vec![0; signed.len() - 64];
        crypto_sign_open(&mut verified, signed, public_key)?;

        // Check that verified data matches signed data after skipping the signature
        if verified.as_slice() != &signed[64..] {
            return Err(Error::InvalidData);
        }

        // Create header from signed data and check that public key matches
        let header: &Header = unsafe { Header::new_unchecked(signed)? };
        if header.public_key != public_key.as_ref()[..] {
            return Err(Error::InvalidKey);
        }

        Ok(header)
    }

    /// Parse header from raw header data without verification
    pub unsafe fn new_unchecked(data: &[u8]) -> Result<&Header, Error> {
        Ok(bytemuck::try_from_bytes(data)?)
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    /// Retrieve the size of the entries
    pub fn entries_size(&self) -> Result<u64, Error> {
        let entry_size = u64::try_from(mem::size_of::<Entry>())?;
        self.count.checked_mul(entry_size).ok_or(Error::Overflow)
    }

    /// Retrieve the size of the Header and its entries
    pub fn total_size(&self) -> Result<u64, Error> {
        let header_size = u64::try_from(mem::size_of::<Header>())?;
        self.entries_size()?
            .checked_add(header_size)
            .ok_or(Error::Overflow)
    }

    /// Parse entries from raw entries data and verify using blake3
    pub fn entries<'a>(&self, data: &'a [u8]) -> Result<&'a [Entry], Error> {
        let entries_size = usize::try_from(self.entries_size()?)?;

        let entries_data = data
            .get(..entries_size)
            .ok_or(Error::Cast(PodCastError::SizeMismatch))?;

        let hash = {
            let mut hasher = blake3::Hasher::new();
            hasher.update_with_join::<blake3::join::RayonJoin>(entries_data);
            hasher.finalize()
        };

        if &self.blake3 != hash.as_bytes() {
            return Err(Error::InvalidBlake3);
        }

        unsafe { Self::entries_unchecked(entries_data) }
    }

    /// Parse entries from raw entries data without verification
    pub unsafe fn entries_unchecked(data: &[u8]) -> Result<&[Entry], Error> {
        Ok(bytemuck::try_cast_slice(data)?)
    }
}
/*
impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Header {{\n\tsignature: {:?},\n\tpublic_key: {:?},\n\tblake3: {:?},count: {:?},\n}}",
            &self.signature[..],
            self.public_key,
            self.blake3,
            self.count(),
        )
    }
}*/
