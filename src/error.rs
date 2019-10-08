#[derive(Debug)]
pub enum Error {
    InvalidData,
    InvalidKey,
    InvalidSha256,
    InvalidSignature,
    Plain(plain::Error),
    Overflow,
}
