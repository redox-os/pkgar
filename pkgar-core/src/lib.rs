#![no_std]
extern crate alloc;

use core::mem;

use bitflags::bitflags;

pub use crate::entry::Entry;
pub use crate::error::Error;
pub use crate::header::Header;
pub use crate::package::{PackageBuf, PackageSrc};

mod entry;
mod error;
mod header;
mod package;

pub const HEADER_SIZE: usize = mem::size_of::<Header>();
pub const ENTRY_SIZE: usize = mem::size_of::<Entry>();

bitflags! {
    /// Ensures that all platforms use the same mode defines.
    pub struct Mode: u32 {
        const PERM = 0o007777;
        const KIND = 0o170000;
        const FILE = 0o100000;
        const SYMLINK = 0o120000;
    }
}

impl Mode {
    /// Only any kind bits
    pub fn kind(self) -> Mode {
        self & Mode::KIND
    }

    /// Only any permissions bits
    pub fn perm(self) -> Mode {
        self & Mode::PERM
    }
}

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
