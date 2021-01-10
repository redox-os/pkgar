use std::convert::TryInto;
use std::io;

use pkgar::{Error, PackageBuilder};
use pkgar_core::{ENTRY_SIZE, HEADER_SIZE, Mode, PackageBuf, PackageSrc};
use pkgar_keys::SecretKeyFile;

fn eprint_grp(label: &str, group: &[u8]) {
    eprintln!("{:>16}: {:02x?}", label, group);
}

fn eprint_u64(label: &str, group: &[u8]) {
    let grp_array = group.try_into()
        .expect("Wrong number of bytes to eprint_u64");
    eprintln!("{:>16}: {} ({:02x?})", label, u64::from_le_bytes(grp_array), group);
}

fn eprint_mode(label: &str, group: &[u8]) {
    let grp_array = group.try_into()
        .expect("Wrong number of bytes to eprint_mode");
    eprintln!("{:>16}: {:o} ({:02x?})", label, u32::from_le_bytes(grp_array), group);
}

// Separate header and entry bytes for the first entry and write the groups
// to stderr.
// This is HIDEOUS
fn format_print_archive(archive: &[u8]) {
    const OFFSETS: [usize; 9] = [64, 32, 32, 8, 32, 8, 8, 4, 256];
    
    let field = |indx: usize| {
        let base = OFFSETS.iter()
            .take(indx)
            .fold(0, |acc, i| acc + i);
        &archive[base..base + OFFSETS[indx]]
    };
    
    eprintln!("Header");
    eprint_grp("Signature", field(0));
    eprint_grp("Public Key", field(1));
    eprint_grp("Entries Hash", field(2));
    eprint_u64("Count", field(3));
    
    eprintln!("Entry[0]");
    eprint_grp("Data Hash", field(4));
    eprint_u64("Offset", field(5));
    eprint_u64("Size", field(6));
    eprint_mode("Mode", field(7));
    eprint_grp("Path", field(8));
    
    eprintln!("Data\n{:02x?}", &archive[HEADER_SIZE + ENTRY_SIZE..]);
}

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
    
    // Check raw archive
    let archive = archive_dest.into_inner();
    format_print_archive(&archive);
    
    assert_eq!(SOME_FILE_CONTENTS.as_bytes(), &archive[HEADER_SIZE + ENTRY_SIZE..]);
    
    // Use PackageSrc
    let mut src = PackageBuf::new(&archive, &pkey.pkey)?;
    let entry = src.read_entries()?[0];
    
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
    format_print_archive(&archive);
    
    assert_eq!(SOME_SYMLINK_DEST.as_bytes(), &archive[HEADER_SIZE + ENTRY_SIZE..]);
    
    let mut src = PackageBuf::new(&archive, &pkey.pkey)?;
    let entry = src.read_entries()?[0];
    
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

