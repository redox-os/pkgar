//! Extention traits for base types defined in `pkgar-core`.
use std::io::{self, Read, Write};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

use blake3::{Hash, Hasher};
use pkgar_core::{Entry, PackageSrc};

use crate::Error;

pub trait EntryExt {
    fn check_path(&self) -> Result<&Path, Error>;
}

impl EntryExt for Entry {
    /// Iterate the components of the path and ensure that there are no
    /// non-normal components.
    fn check_path(&self) -> Result<&Path, Error> {
        let path = Path::new(OsStr::from_bytes(self.path()));
        for component in path.components() {
            match component {
                Component::Normal(_) => {},
                invalid => {
                    let bad_component: &Path = invalid.as_ref();
                    return Err(Error::InvalidPath {
                        entry: path.to_path_buf(),
                        component: bad_component.to_path_buf(),
                    });
                },
            }
        }
        Ok(&path)
    }
}

//TODO: Fix the types for this
pub trait PackageSrcExt<Src>
where Src: PackageSrc<Err = Error>,
{
    fn entry_reader(&mut self, entry: Entry) -> EntryReader<'_, Src>;
}

impl<Src> PackageSrcExt<Src> for Src
where Src: PackageSrc<Err = Error>,
{
    fn entry_reader(&mut self, entry: Entry) -> EntryReader<'_, Src> {
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
where Src: PackageSrc<Err = Error>,
{
    src: &'a mut Src,
    entry: Entry,
    pos: usize,
}

impl<Src> Read for EntryReader<'_, Src>
where Src: PackageSrc<Err = Error>,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let count = self.src.read_entry(self.entry, self.pos, buf)
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

