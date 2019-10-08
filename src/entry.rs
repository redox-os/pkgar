//! The packed structs represent the on-disk format of pkgar

use plain::Plain;

#[derive(Clone, Copy)]
#[repr(packed)]
pub struct Entry {
    /// SHA-256 sum of the file data
    pub sha256: [u8; 32],
    /// Offset of file data in the data portion
    pub offset: u64,
    /// Size in bytes of the file data in the data portion
    pub size: u64,
    /// Unix permissions (user, group, other with read, write, execute)
    pub mode: u32,
    /// NUL-terminated relative path from extract directory
    pub path: [u8; 256],
}

impl Entry {
    /// Retrieve the path, ending at the first NUL
    pub fn path(&self) -> &[u8] {
        let mut i = 0;
        while i < self.path.len() {
            if self.path[i] == 0 {
                break;
            }
            i += 1;
        }
        &self.path[..i]
    }
}

unsafe impl Plain for Entry {}

#[cfg(test)]
mod tests {
    use core::mem;

    use super::{Entry, Header};

    #[test]
    fn header_size() {
        assert_eq!(mem::size_of::<Header>(), 136);
    }

    #[test]
    fn entry_size() {
        assert_eq!(mem::size_of::<Entry>(), 308);
    }
}