#[repr(packed)]
pub struct Entry {
    pub sha256: [u8; 32],
    pub offset: u64,
    pub size: u64,
    pub mode: u16,
    pub path: [u8; 256],
}
