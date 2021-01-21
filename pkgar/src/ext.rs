//! Extention traits for base types defined in `pkgar-core`.
use std::io::{self, Read, Write};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

use error_chain::bail;
use blake3::{Hash, Hasher};
use pkgar_core::{Entry, Mode, PackageData};

use crate::{Error, ErrorKind, ResultExt};

/// Handy associated functions for `pkgar_core::Entry` that depend on std
pub trait EntryExt {
    fn new(
        blake3: Hash,
        offset: u64,
        size: u64,
        mode: Mode,
        path: &Path
    ) -> Result<Entry, Error>;

    fn check_path(&self) -> Result<&Path, Error>;
    
    fn verify(&self, blake3: Hash, size: u64) -> Result<(), Error>;
}

impl EntryExt for Entry {
    fn new(
        blake3: Hash,
        offset: u64,
        size: u64,
        mode: Mode,
        path: &Path
    ) -> Result<Entry, Error> {
        let mut path_buf = [0; 256];
        let path_bytes = path.as_os_str().as_bytes();

        if path_bytes.len() >= path_buf.len() {
            bail!(ErrorKind::PathTooLong(path.to_path_buf()));
        }
        path_buf[..path_bytes.len()].copy_from_slice(path_bytes);

        Ok(Entry {
            blake3: blake3.into(),
            offset,
            size,
            mode: mode.bits(),
            path: path_buf,
        })
    }

    /// Iterate the components of the path and ensure that there are no
    /// non-normal components.
    fn check_path(&self) -> Result<&Path, Error> {
        let path = Path::new(OsStr::from_bytes(self.path_bytes()));
        check_path(&path)?;
        Ok(&path)
    }

    /// Compare the given blake3 and size against this Entry's blake3 and size
    /// and return Err if they do not match
    fn verify(&self, blake3: Hash, size: u64) -> Result<(), Error> {
        if size != self.size() {
            Err(Error::from_kind(ErrorKind::LengthMismatch(size, self.size())))
        } else if blake3 != self.blake3() {
            Err(pkgar_core::Error::InvalidBlake3.into())
        } else {
            Ok(())
        }.chain_err(|| *self )
    }
}

pub trait PackageDataExt
    where Self: PackageData + Sized,
{
    /// Get the path corresponding to this `PackageSrc`. This will likely be
    /// refactored to use something more generic than `Path` in future.
    fn path(&self) -> &Path;

    /// Build a reader for a given entry on this source.
    fn entry_reader(&mut self, entry: Entry) -> EntryReader<'_, Self> {
        EntryReader {
            src: self,
            entry,
            pos: 0,
        }
    }
}

/// A reader that provides acess to one entry's data within a `PackageSrc`.
/// Use `PackageSrcExt::entry_reader` for construction
pub struct EntryReader<'a, Src>
    where Src: PackageData
{
    src: &'a mut Src,
    entry: Entry,
    pos: usize,
}

impl<Src, E> Read for EntryReader<'_, Src>
    where
        Src: PackageData<Err = E>,
        E: From<pkgar_core::Error> + std::error::Error,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let count = self.src.read_entry(self.entry, self.pos, buf)
            // This is a little painful, since e is pkgar::Error...
            // However, this is likely to be a very rarely triggered error
            // condition.
            .map_err(|err|
                io::Error::new(io::ErrorKind::Other, err.to_string())
            )?;
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
    buf: &mut [u8]
) -> Result<(u64, Hash), io::Error> {
    let mut hasher = Hasher::new();
    let mut written = 0;
    loop {
        let count = read.read(buf)?;
        if count == 0 {
            break;
        }
        written += count as u64;
        hasher.update_with_join::<blake3::join::RayonJoin>(&buf[..count]);

        write.write_all(&buf[..count])?;
    }
    Ok((written, hasher.finalize()))
}

/// Iterate the components of a path and ensure that none are non-normal
/// (the path is relative rather than absolute, and has no `./` or `../`
/// elements.
pub(crate) fn check_path(path: &Path) -> Result<(), Error> {
    for component in path.components() {
        match component {
            Component::Normal(_) => {},
            invalid => {
                let bad_component: &Path = invalid.as_ref();
                bail!(ErrorKind::InvalidPathComponent(bad_component.to_path_buf()));
            },
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use std::io::Cursor;
    use std::path::Path;

    use pkgar_core::{Entry, Mode};

    use crate::{Error, READ_WRITE_HASH_BUF_SIZE};
    use crate::ext::{check_path, copy_and_hash, EntryExt};

    #[test]
    fn entry_constructor() -> Result<(), Error> {
        const ENTRY_DATA: &str = "some file contents";

        let hash = blake3::hash(ENTRY_DATA.as_bytes());

        let entry = Entry::new(hash, 0, ENTRY_DATA.len() as u64, Mode::PERM, Path::new("/some/filepath"))?;

        entry.verify(hash, ENTRY_DATA.len() as u64)
    }
    
    #[test]
    fn path_check() {
        assert!(check_path(Path::new("/absolute/paths")).is_err());
        assert!(check_path(Path::new("trying_to_break_something/../../../..")).is_err());
        assert!(check_path(Path::new("./test.sh")).is_err());
        
        check_path(Path::new("normal/relative/path"))
            .expect("Normal paths should pass");
    }
    
    #[test]
    fn copy_check() -> Result<(), Error> {
        //TODO: Copy a buffer that requires multiple iterations of copy/hash
        const SOME_DATA: &str = "here's a buffer to copy and hash";
        
        let mut dest = Cursor::new(Vec::new());
        let mut buf = vec![0; READ_WRITE_HASH_BUF_SIZE];
        let (size, hash) = copy_and_hash(SOME_DATA.as_bytes(), &mut dest, &mut buf)?;
        
        assert_eq!(size, SOME_DATA.len() as u64);
        assert_eq!(hash, blake3::hash(SOME_DATA.as_bytes()));
        assert_eq!(dest.into_inner(), SOME_DATA.as_bytes());
        Ok(())
    }
}

