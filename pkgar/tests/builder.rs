use std::io;

use pkgar::{Error, PackageBuilder};
use pkgar_core::{
    ENTRY_SIZE, HEADER_SIZE,
    Mode,
    PackageBuf, PackageHead,
};
use pkgar_keys::SecretKeyFile;

const SOME_FILE_PATH: &str = "some/file";
const SOME_FILE_PERMS: Mode = Mode::from_bits_truncate(0o640);
const SOME_FILE_MODE: Mode = Mode::from_bits_truncate(SOME_FILE_PERMS.bits() | Mode::FILE.bits());
const SOME_FILE_CONTENTS: &str = "some file contents";

#[test]
fn builder_file_writer() -> Result<(), Error> {
    let (pkey, skey) = SecretKeyFile::new();
    
    let mut archive_dest = io::Cursor::new(Vec::new());
    
    let mut builder = PackageBuilder::new(skey);
    builder.file_reader(SOME_FILE_CONTENTS.as_bytes(), SOME_FILE_PATH, SOME_FILE_MODE)?;
    builder.write_archive(&mut archive_dest)?;
    
    let archive = archive_dest.into_inner();
    
    assert_eq!(SOME_FILE_CONTENTS.as_bytes(), &archive[HEADER_SIZE + ENTRY_SIZE..]);
    
    // Use PackageSrc
    let src = PackageBuf::new(&archive, &pkey.pkey)?;
    let entry = src.entries()
        .next()
        .unwrap();
    
    eprintln!("Entry Mode:     {:o}", entry.mode()?);
    eprintln!("SOME_FILE_MODE: {:o}", SOME_FILE_MODE);
    
    assert_eq!(entry.blake3(), blake3::hash(SOME_FILE_CONTENTS.as_bytes()));
    assert_eq!(entry.size(), SOME_FILE_CONTENTS.len() as u64);
    assert_eq!(entry.offset(), 0);
    assert_eq!(entry.mode()?, SOME_FILE_MODE);
    assert_eq!(entry.path_bytes(), SOME_FILE_PATH.as_bytes());
    Ok(())
}

const SOME_SYMLINK_MODE: Mode = Mode::from_bits_truncate(SOME_FILE_PERMS.bits() | Mode::SYMLINK.bits());
const SOME_SYMLINK_DEST: &str = "/some/symlink/destination";

#[test]
fn builder_symlink() -> Result<(), Error> {
    let (pkey, skey) = SecretKeyFile::new();
    
    let mut archive_dest = io::Cursor::new(Vec::new());
    
    let mut builder = PackageBuilder::new(skey);
    builder.symlink(SOME_SYMLINK_DEST, SOME_FILE_PATH, SOME_SYMLINK_MODE)?;
    builder.write_archive(&mut archive_dest)?;
    
    let archive = archive_dest.into_inner();
    
    assert_eq!(SOME_SYMLINK_DEST.as_bytes(), &archive[HEADER_SIZE + ENTRY_SIZE..]);
    
    let src = PackageBuf::new(&archive, &pkey.pkey)?;
    let entry = src.entries()
        .next()
        .unwrap();
    
    assert_eq!(entry.blake3(), blake3::hash(SOME_SYMLINK_DEST.as_bytes()));
    assert_eq!(entry.size(), SOME_SYMLINK_DEST.len() as u64);
    assert_eq!(entry.offset(), 0);
    assert_eq!(entry.mode()?, SOME_SYMLINK_MODE);
    assert_eq!(entry.path_bytes(), SOME_FILE_PATH.as_bytes());
    Ok(())
}

const AN_ABSOLUTE_PATH: &str = "/some/absolute/path";

#[test]
fn builder_absolute_path() {
    let (_, skey) = SecretKeyFile::new();
    
    let mut builder = PackageBuilder::new(skey);
    assert!(builder.file_reader(
            SOME_FILE_CONTENTS.as_bytes(),
            AN_ABSOLUTE_PATH,
            SOME_FILE_MODE
        ).is_err()
    );
}

