//! Extention traits for base types defined in `pkgar-core`.
use std::io::Write;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

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

pub(crate) trait PackageSrcExt {
    fn copy_entry_and_hash<W: Write>(
        &mut self,
        entry: Entry,
        write: W,
        buf: &mut [u8],
    ) -> Result<(u64, Hash), Error>;
}

impl<T: PackageSrc<Err = Error>> PackageSrcExt for T {
    fn copy_entry_and_hash<W: Write>(
        &mut self,
        entry: Entry,
        mut write: W,
        buf: &mut [u8]
    ) -> Result<(u64, Hash), Error> {
        let mut hasher = Hasher::new();
        let mut total = 0;
        loop {
            let count = self.read_entry(entry, total, buf)?;
            if count == 0 {
                break;
            }
            total += count as u64;
            write.write_all(&buf[..count])
                .map_err(|e| Error::Io {
                    reason: "Copy entry".to_string(),
                    file: PathBuf::new(),
                    source: e,
                })?;
            hasher.update_with_join::<blake3::join::RayonJoin>(&buf[..count]);
        }
        Ok((total, hasher.finalize()))
    }
}

