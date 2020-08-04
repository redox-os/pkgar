//! Extention traits for base types defined in `pkgar-core`.
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

use pkgar_core::Entry;

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

