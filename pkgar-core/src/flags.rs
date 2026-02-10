#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum DataVersion {
    V0 = 0,
    Reserved(u8),
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum Architecture {
    /// Architecture-independent
    Independent = 0,
    /// x86_64, base arch (x86_64-v1)
    X86_64 = 1,
    /// 32 bit x86, base arch (i586)
    X86 = 2,
    /// Aarch64, base arch (Armv8-A)
    AArch64 = 3,
    /// Riscv64, base arch (extension GC)
    RiscV64 = 4,
    Reserved(u8),
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum Packaging {
    Uncompressed = 0,
    LZMA = 1,
    Reserved(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C, packed)]
pub struct HeaderFlags(pub u32);

impl HeaderFlags {
    pub fn new(version: DataVersion, arch: Architecture, pkg: Packaging) -> Self {
        let mut bits = 0u32;
        bits |= (Self::val_version(version) as u32) << 0;
        bits |= (Self::val_arch(arch) as u32) << 8;
        bits |= (Self::val_pkg(pkg) as u32) << 16;
        Self(bits)
    }

    pub fn version(&self) -> DataVersion {
        match (self.0 >> 0) as u8 {
            0 => DataVersion::V0,
            v => DataVersion::Reserved(v),
        }
    }

    pub fn architecture(&self) -> Architecture {
        match (self.0 >> 8) as u8 {
            0 => Architecture::Independent,
            1 => Architecture::X86_64,
            2 => Architecture::X86,
            3 => Architecture::AArch64,
            4 => Architecture::RiscV64,
            v => Architecture::Reserved(v),
        }
    }

    pub fn packaging(&self) -> Packaging {
        match (self.0 >> 16) as u8 {
            0 => Packaging::Uncompressed,
            1 => Packaging::LZMA,
            v => Packaging::Reserved(v),
        }
    }

    fn val_version(v: DataVersion) -> u8 {
        match v {
            DataVersion::V0 => 0,
            DataVersion::Reserved(n) => n,
        }
    }
    fn val_arch(a: Architecture) -> u8 {
        match a {
            Architecture::Independent => 0,
            Architecture::X86_64 => 1,
            Architecture::X86 => 2,
            Architecture::AArch64 => 3,
            Architecture::RiscV64 => 4,
            Architecture::Reserved(n) => n,
        }
    }
    fn val_pkg(p: Packaging) -> u8 {
        match p {
            Packaging::Uncompressed => 0,
            Packaging::LZMA => 1,
            Packaging::Reserved(n) => n,
        }
    }
}

impl Default for HeaderFlags {
    fn default() -> Self {
        Self(0)
    }
}

impl From<u32> for HeaderFlags {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl Into<u32> for HeaderFlags {
    fn into(self) -> u32 {
        self.0
    }
}
