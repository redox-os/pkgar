#[derive(Debug)]
pub enum Error {
    InvalidData,
    InvalidKey,
    InvalidBlake3,
    InvalidSignature,
    #[cfg(feature = "std")]
    Io(std::io::Error),
    Plain(plain::Error),
    Overflow,
    TryFromInt(core::num::TryFromIntError),
}
