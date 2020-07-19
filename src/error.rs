#[derive(Debug)]
pub enum Error {
    InvalidData,
    InvalidKey,
    InvalidBlake3,
    InvalidSignature,
    #[cfg(feature = "std")]
    Io(std::io::Error),
    #[cfg(feature = "std")]
    Keys(pkgar_keys::Error),
    Plain(plain::Error),
    Overflow,
    TryFromInt(core::num::TryFromIntError),
    //#[cfg(feature = "rand")]
    //Rand(rand_core::Error),
}

#[cfg(feature = "std")]
impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Error::Io(err)
    }
}

#[cfg(feature = "std")]
impl From<pkgar_keys::Error> for Error {
    fn from(err: pkgar_keys::Error) -> Error {
        Error::Keys(err)
    }
}

impl From<plain::Error> for Error {
    fn from(err: plain::Error) -> Error {
        Error::Plain(err)
    }
}

impl From<core::num::TryFromIntError> for Error {
    fn from(err: core::num::TryFromIntError) -> Error {
        Error::TryFromInt(err)
    }
}

