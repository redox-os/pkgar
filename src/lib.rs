#![cfg_attr(not(feature = "std"), no_std)]

pub use self::entry::Entry;
pub use self::header::Header;

mod entry;
mod header;

pub struct HeaderSlice<'a> {
    /// The .pkgar file data
    pub data: &'a [u8],
}

impl<'a> HeaderSlice<'a> {
    pub fn header(&self) -> Result<&Header, plain::Error> {
        plain::from_bytes(self.data)
    }
}
