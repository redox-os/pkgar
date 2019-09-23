use core::mem;

use crate::Entry;

#[repr(packed)]
pub struct Header {
    /// NaCl signature of header data
    pub signature: [u8; 64],
    /// NaCl public key used to generate signature
    pub public_key: [u8; 32],
    /// Count of Entry structs, which immediately follow
    pub entries: u64,
}

impl Header {
    /// Retrieve the size of the Header and its entries
    pub fn size(&self) -> u64 {
        (mem::size_of::<Header>() as u64) +
        self.entries * (mem::size_of::<Entry>() as u64)
    }
}
