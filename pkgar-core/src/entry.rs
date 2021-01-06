//! The packed structs represent the on-disk format of pkgar
use blake3::Hash;
use plain::Plain;

use crate::{Error, Mode};

#[derive(Clone, Copy, Debug)]
#[repr(packed)]
pub struct Entry {
    /// Blake3 sum of the file data
    pub blake3: [u8; 32],
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
    pub fn blake3(&self) -> Hash {
        Hash::from(self.blake3)
    }
    
    pub fn offset(&self) -> u64 {
        self.offset
    }
    
    pub fn size(&self) -> u64 {
        self.size
    }
    
    pub fn mode(&self) -> Result<Mode, Error> {
        Mode::from_bits(self.mode)
            .ok_or(Error::InvalidMode(self.mode))
    }
    
    /// Retrieve the path, ending at the first NUL
    pub fn path_bytes(&self) -> &[u8] {
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

