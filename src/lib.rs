#![cfg_attr(not(feature = "std"), no_std)]

pub use crate::entry::Entry;
pub use crate::error::Error;
pub use crate::header::Header;
//pub use crate::key::{PublicKey, SecretKey};
pub use crate::package::{Package, PackageSrc};

mod entry;
mod error;
mod header;
//mod key;
mod package;

#[cfg(feature = "std")]
pub mod bin;

#[cfg(test)]
mod tests {
    use core::mem;

    use crate::{Entry, Header};

    #[test]
    fn header_size() {
        assert_eq!(mem::size_of::<Header>(), 136);
    }

    #[test]
    fn entry_size() {
        assert_eq!(mem::size_of::<Entry>(), 308);
    }
}
