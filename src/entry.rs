#[repr(packed)]
pub struct Entry {
    /// SHA-256 sum of the file data
    pub sha256: [u8; 32],
    /// Offset of file data in the data portion
    pub offset: u64,
    /// Size in bytes of the file data in the data portion
    pub size: u64,
    /// Unix permissions (user, group, other with read, write, execute)
    pub mode: u16,
    /// NUL-terminated relative path from extract directory
    pub path: [u8; 256],
}
