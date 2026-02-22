//! Extention traits for base types defined in `pkgar-core`.
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read, Seek, Take, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

use blake3::{Hash, Hasher};
use pkgar_core::{Entry, Header, PackageSrc, Packaging};

use crate::{wrap_io_err, Error};

/// Handy associated functions for `pkgar_core::Entry` that depend on std
pub trait EntryExt {
    fn check_path(&self) -> Result<&Path, Error>;

    fn verify<R>(&self, blake3: Hash, size: u64, reader: &DataReader<R>) -> Result<(), Error>
    where
        R: Sized;
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

    /// Verify is extracted blake3 or compressed size is correct
    fn verify<R>(&self, blake3: Hash, size: u64, reader: &DataReader<R>) -> Result<(), Error> {
        if size != reader.unpacked_size {
            Err(Error::LengthMismatch {
                actual: size,
                expected: reader.unpacked_size,
            })
        } else if self.size() != reader.data_size {
            Err(Error::LengthMismatch {
                actual: self.size(),
                expected: reader.data_size,
            })
        } else if blake3 != self.blake3() {
            Err(pkgar_core::Error::InvalidBlake3.into())
        } else {
            Ok(())
        }
    }
}

pub trait PackageSrcExt<R>
where
    Self: PackageSrc + Sized,
    R: Read + Seek,
{
    /// Get the path corresponding to this `PackageSrc`. This will likely be
    /// refactored to use something more generic than `Path` in future.
    fn path(&self) -> &Path;

    /// Take the underlying reader out into the data reader
    fn take_reader(&mut self) -> Result<R, Error>;

    /// Put the underlying reader back in from the data reader
    fn restore_reader(&mut self, reader: R) -> Result<(), Error>;

    /// Build a reader for a given entry on this source.
    /// Must call reader.finish() before getting another reader.
    fn data_reader(&mut self, entry: Entry) -> Result<DataReader<R>, Error> {
        let mut reader = self.take_reader()?;
        let offset = self.header().total_size()? as u64 + entry.offset;
        reader
            .seek(io::SeekFrom::Start(offset))
            .map_err(wrap_io_err!("Seeking for data reader"))?;
        DataReader::new(&self.header(), reader, entry.size)
            .map_err(wrap_io_err!("Seeking for data reader"))
    }
}

/// Copy the contents of `read` into `write` by streaming through buf.
/// The basic function of this function is analogous to io::copy, except it
/// outputs the blake3 hash of the data streamed, and also does not allocate.
pub(crate) fn copy_and_hash<R: Read, W: Write>(
    read: &mut R,
    write: &mut W,
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

/// Implements reader based on data flags
pub struct DataReader<R> {
    pub data_size: u64,
    pub unpacked_size: u64,
    pub inner: DataReaderKind<R>,
}

pub enum DataReaderKind<R> {
    Uncompressed(Take<R>),
    LZMA2(lzma_rust2::Lzma2Reader<Take<R>>),
}

impl<R: Read + Seek> DataReader<R> {
    pub fn new(header: &Header, mut file: R, len: u64) -> std::io::Result<Self> {
        let mut unpacked_size = len;
        let inner = match header.flags.packaging() {
            Packaging::LZMA2 => {
                let mut ulen_buf = [0u8; size_of::<u64>()];
                file.read_exact(&mut ulen_buf)?;
                unpacked_size = u64::from_le_bytes(ulen_buf);
                let decoder = lzma_rust2::Lzma2Reader::new(
                    file.take(len),
                    // same dict size with writer
                    lzma_rust2::LzmaOptions::DICT_SIZE_DEFAULT << 3,
                    None,
                );
                DataReaderKind::LZMA2(decoder)
            }
            _ => DataReaderKind::Uncompressed(file.take(len)),
        };
        Ok(Self {
            inner,
            unpacked_size,
            data_size: len,
        })
    }

    pub fn new_with_seek(header: &Header, mut pkg_file: R, entry: &Entry) -> std::io::Result<Self> {
        let head_size = header.total_size().unwrap() as u64;
        pkg_file.seek(io::SeekFrom::Start(head_size + entry.offset))?;
        Self::new(&header, pkg_file, entry.size)
    }

    pub fn finish(self, source: &mut impl PackageSrcExt<R>) -> Result<(), Error> {
        source.restore_reader(self.into_inner())
    }

    pub fn into_inner(self) -> R {
        match self.inner {
            DataReaderKind::Uncompressed(file) => file.into_inner(),
            DataReaderKind::LZMA2(xz_decoder) => xz_decoder.into_inner().into_inner(),
        }
    }
}

impl<R: Read> Read for DataReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.inner {
            DataReaderKind::Uncompressed(file) => file.read(buf),
            DataReaderKind::LZMA2(reader) => reader.read(buf),
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
    pub fn new(header: Packaging, mut file: File, len: u64) -> std::io::Result<Self> {
        let writer = match header {
            Packaging::LZMA2 => {
                file.write(&len.to_le_bytes())?;
                Self::LZMA2(lzma_rust2::Lzma2Writer::new(
                    file,
                    lzma_rust2::Lzma2Options::with_preset(5),
                ))
            }
            _ => Self::Uncompressed(file),
        };
        Ok(writer)
    }

    pub fn finish(self) -> std::io::Result<File> {
        match self {
            Self::Uncompressed(file) => Ok(file),
            Self::LZMA2(xz_encoder) => xz_encoder.finish(),
        }
    }
}
