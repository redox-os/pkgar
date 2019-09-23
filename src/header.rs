#[repr(packed)]
pub struct Header {
    pub signature: [u8; 64],
    pub public_key: [u8; 32],
    pub entries: u64,
}
