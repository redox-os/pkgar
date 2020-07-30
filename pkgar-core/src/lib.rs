#![no_std]
extern crate alloc;

use core::mem;

pub use crate::entry::Entry;
pub use crate::error::Error;
pub use crate::header::Header;
pub use crate::package::PackageSrc;

mod entry;
mod error;
mod header;
mod package;

pub const HEADER_SIZE: usize = mem::size_of::<Header>();
pub const ENTRY_SIZE: usize = mem::size_of::<Entry>();

#[cfg(test)]
mod tests {
    use core::mem;

    use crate::{Entry, ENTRY_SIZE, Header, HEADER_SIZE};

    #[test]
    fn header_size() {
        assert_eq!(mem::size_of::<Header>(), 136);
        assert_eq!(HEADER_SIZE, 136);
    }

    #[test]
    fn entry_size() {
        assert_eq!(mem::size_of::<Entry>(), 308);
        assert_eq!(ENTRY_SIZE, 308);
    }
}

