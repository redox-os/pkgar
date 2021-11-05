#![no_std]
extern crate alloc;

// Enable std for tests
#[cfg(test)]
extern crate std;

use core::mem;

use bitflags::bitflags;

pub use crate::entry::Entry;
pub use crate::error::Error;
pub use crate::header::Header;
pub use crate::package::{PackageBuf, PackageData, PackageHead, segment};

mod entry;
mod error;
mod header;
mod package;

#[cfg(test)]
pub mod test;

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

