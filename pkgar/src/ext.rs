//! Extention traits for base types defined in `pkgar-core`.
use std::io::{self, Read, Write};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

use blake3::{Hash, Hasher};
use pkgar_core::{Entry, PackageSrc};

use crate::ErrorKind;

/// Handy associated functions for `pkgar_core::Entry` that depend on std
pub trait EntryExt {
    fn check_path(&self) -> Result<&Path, ErrorKind>;
}

impl EntryExt for Entry {
    /// Iterate the components of the path and ensure that there are no
    /// non-normal components.
    fn check_path(&self) -> Result<&Path, ErrorKind> {
        let path = Path::new(OsStr::from_bytes(self.path()));
        for component in path.components() {
            match component {
                Component::Normal(_) => {},
                invalid => {
                    let bad_component: &Path = invalid.as_ref();
                    return Err(ErrorKind::InvalidPath {
                        entry: path.to_path_buf(),
                        component: bad_component.to_path_buf(),
                    });
                },
            }
        }
        Ok(&path)
    }
}

pub trait PackageSrcExt
    where Self: PackageSrc + Sized,
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
//TODO: Fix the types for this
pub struct EntryReader<'a, Src>
    where Src: PackageSrc
{
    src: &'a mut Src,
    entry: Entry,
    pos: usize,
}

impl<Src, E> Read for EntryReader<'_, Src>
    where
        Src: PackageSrc<Err = E>,
        E: From<pkgar_core::Error> + std::error::Error + Send + Sync + 'static,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let count = self.src.read_entry(self.entry, self.pos, buf)
            // This is a little painful, since e is pkgar::Error...
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e) )?;
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

