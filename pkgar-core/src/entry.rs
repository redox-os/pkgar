//! The packed structs represent the on-disk format of pkgar
use plain::Plain;

#[derive(Clone, Copy)]
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
    
    /*
    pub fn read_at(&self, package: &mut Package, offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        if offset >= self.size {
            return Ok(0);
        }
        let mut end = offset.checked_add(buf.len() as u64)
            .ok_or(Error::Overflow)?;
        
        if end > self.size {
            end = self.size;
        }
        let buf_len = usize::try_from(end.checked_sub(offset).unwrap())
            .map_err(Error::TryFromInt)?;
        
        package.src.read_at(
            // Offset to first entry data
            package.header.total_size()?
                // Add offset to provided entry data
                .checked_add(self.offset)
                .ok_or(Error::Overflow)?
                
                // Offset into entry data
                .checked_add(offset)
                .ok_or(Error::Overflow)?,
            &mut buf[..buf_len])
    }*/
}

unsafe impl Plain for Entry {}

