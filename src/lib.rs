#![cfg_attr(not(feature = "std"), no_std)]

pub use crate::key::{PublicKey, SecretKey};
pub use crate::packed::{PackedHeader, PackedEntry};

mod key;
mod packed;

#[derive(Debug)]
pub enum Error {
    InvalidData,
    InvalidKey,
    InvalidSha256,
    InvalidSignature,
    Plain(plain::Error),
    Overflow,
}
