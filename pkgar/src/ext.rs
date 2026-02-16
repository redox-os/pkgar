//! Extention traits for base types defined in `pkgar-core`.
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

use blake3::{Hash, Hasher};
use pkgar_core::{Entry, PackageSrc, Packaging};

use crate::Error;

/// Handy associated functions for `pkgar_core::Entry` that depend on std
pub trait EntryExt {
    fn check_path(&self) -> Result<&Path, Error>;

    fn verify(&self, blake3: Hash, size: u64) -> Result<(), Error>;
}

impl EntryExt for Entry {
    /// Iterate the components of the path and ensure that there are no
    /// non-normal components.
    fn check_path(&self) -> Result<&Path, Error> {
        let path = Path::new(OsStr::from_bytes(self.path_bytes()));
        for component in path.components() {
            match component {
                Component::Normal(_) => {}
                invalid => {
                    let bad_component: &Path = invalid.as_ref();
                    return Err(Error::InvalidPathComponent {
                        path: path.to_path_buf(),
                        invalid: bad_component.to_path_buf(),
                        entry: Some(Box::new(*self)),
                    });
                }
            }
        }
        Ok(path)
    }

    fn verify(&self, blake3: Hash, size: u64) -> Result<(), Error> {
        if size != self.size() {
            Err(Error::LengthMismatch {
                actual: size,
                expected: self.size(),
            })
        } else if blake3 != self.blake3() {
            Err(pkgar_core::Error::InvalidBlake3.into())
        } else {
            Ok(())
        }
    }
}

pub trait PackageSrcExt
where
    Self: PackageSrc + Sized,
{
    /// Get the path corresponding to this `PackageSrc`. This will likely be
    /// refactored to use something more generic than `Path` in future.
    fn path(&self) -> &Path;

    /// Build a data reader for a given entry on this source.
    fn data_reader(&mut self, entry: Entry) -> EntryReader<'_, Self> {
        EntryReader {
            src: self,
            entry,
            pos: 0,
        }
    }
}

/// A reader that provides acess to one entry's data within a `PackageSrc`.
/// Use `PackageSrcExt::data_reader` for construction
pub struct EntryReader<'a, Src>
where
    Src: PackageSrc,
{
    src: &'a mut Src,
    entry: Entry,
    pos: usize,
}

impl<Src, E> Read for EntryReader<'_, Src>
where
    Src: PackageSrc<Err = E>,
    E: From<pkgar_core::Error> + std::error::Error,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let count = self
            .src
            .read_data(self.entry, self.pos as u64, buf)
            // This is a little painful, since e is pkgar::Error...
            // However, this is likely to be a very rarely triggered error
            // condition.
            .map_err(|err| io::Error::new(io::ErrorKind::Other, format!("{:?}", err)))?;
        self.pos += count;
        Ok(count)
    }
}

/// Copy the contents of `read` into `write` by streaming through buf.
/// The basic function of this function is analogous to io::copy, except it
/// outputs the blake3 hash of the data streamed, and also does not allocate.
pub(crate) fn copy_and_hash<R: Read, W: Write>(
    mut read: R,
    mut write: W,
    buf: &mut [u8],
) -> Result<(u64, Hash), io::Error> {
    let mut hasher = Hasher::new();
    let mut written = 0;
    loop {
        let count = read.read(buf)?;
        if count == 0 {
            break;
        }
        written += count as u64;
        hasher.update_rayon(&buf[..count]);

        write.write_all(&buf[..count])?;
    }
    Ok((written, hasher.finalize()))
}

/// Implements writer based on data flags
/// Note: while it's seekable, user should assume it can never read backward
pub enum DataReader {
    Uncompressed(File),
    LZMA2((lzma_rust2::Lzma2Reader<File>, u64)),
}

impl DataReader {
    pub fn new(header: Packaging, file: File) -> Self {
        match header {
            Packaging::LZMA2 => {
                let decoder = lzma_rust2::Lzma2Reader::new(
                    file,
                    // same dict size with writer
                    lzma_rust2::LzmaOptions::DICT_SIZE_DEFAULT << 3,
                    None,
                );
                Self::LZMA2((decoder, 0))
            }
            _ => Self::Uncompressed(file),
        }
    }

    pub fn finish(self) -> File {
        match self {
            Self::Uncompressed(file) => file,
            Self::LZMA2((xz_decoder, _)) => xz_decoder.into_inner(),
        }
    }

    pub fn skip(&mut self, amount: u64) -> io::Result<u64> {
        io::copy(&mut self.by_ref().take(amount), &mut io::sink())
    }
}

impl Read for DataReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Uncompressed(file) => file.read(buf),
            Self::LZMA2((reader, pos)) => {
                let seek = reader.read(buf)?;
                *pos += seek as u64;
                Ok(seek)
            }
        }
    }
}

impl Seek for DataReader {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        match self {
            Self::Uncompressed(file) => file.seek(pos),
            Self::LZMA2((_, seek)) => {
                let seek = *seek;
                let rel = match pos {
                    io::SeekFrom::Current(x) if x >= 0 => self.skip(x as u64),
                    io::SeekFrom::Start(x) if x >= seek => self.skip(x as u64 - seek),
                    _ => Err(io::Error::from(io::ErrorKind::NotSeekable)),
                }?;
                Ok(seek + rel)
            }
        }
    }
}

/// Implements writer based on data flags
pub enum DataWriter {
    Uncompressed(File),
    LZMA2(lzma_rust2::Lzma2Writer<File>),
}

impl Write for DataWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Uncompressed(file) => file.write(buf),
            Self::LZMA2(xz_encoder) => xz_encoder.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Uncompressed(file) => file.flush(),
            Self::LZMA2(xz_encoder) => xz_encoder.flush(),
        }
    }
}

impl DataWriter {
    pub fn new(header: Packaging, file: File) -> Self {
        match header {
            Packaging::LZMA2 => Self::LZMA2(lzma_rust2::Lzma2Writer::new(
                file,
                lzma_rust2::Lzma2Options::with_preset(5),
            )),
            _ => Self::Uncompressed(file),
        }
    }

    pub fn finish(self) -> std::io::Result<File> {
        match self {
            Self::Uncompressed(file) => Ok(file),
            Self::LZMA2(xz_encoder) => xz_encoder.finish(),
        }
    }
}
