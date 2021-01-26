//! Format-print a pkgar archive; Useful for debugging
// Also implemented completely independently of the rest of the library,
// not sure that was a smart move...
use std::convert::TryInto;

use crate::core::{ENTRY_SIZE, HEADER_SIZE};

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

/// Separate header and entry bytes and write the groups to stderr in a
/// semi-readable format.
///
/// Entry count is required as in debugging situations it's unclear if the
/// header's count field is correct.
// This is HIDEOUS
#[allow(dead_code)]
pub fn format_print_archive(archive: &[u8], entry_count: usize) {
    const HEAD_OFFSETS: [usize; 4] = [64, 32, 32, 8];
    const ENTRY_OFFSETS: [usize; 5] = [32, 8, 8, 4, 256];
    
    let head_field = |offset_indx: usize| {
        let base = HEAD_OFFSETS.iter()
            .take(offset_indx)
            .fold(0, |acc, i| acc + i);
        &archive[base..base + HEAD_OFFSETS[offset_indx]]
    };

    let field = |entry_indx: usize, offset_indx: usize| {
        let base = HEADER_SIZE // Head
            + (ENTRY_SIZE * entry_indx) // Prior entries
            + ENTRY_OFFSETS.iter() // offset of the requested field
                .take(offset_indx)
                .fold(0, |acc, i| acc + i );
        &archive[base..base + ENTRY_OFFSETS[offset_indx]]
    };
    
    eprintln!("Header");
    eprint_grp("Signature", head_field(0));
    eprint_grp("Public Key", head_field(1));
    eprint_grp("Entries Hash", head_field(2));
    eprint_u64("Count", head_field(3));
    
    for e_indx in 0..entry_count {
        eprintln!("Entry[{}]", e_indx);
        eprint_grp("Data Hash", field(e_indx, 0));
        eprint_u64("Offset", field(e_indx, 1));
        eprint_u64("Size", field(e_indx, 2));
        eprint_mode("Mode", field(e_indx, 3));
        eprint_grp("Path", field(e_indx, 4));
    }
    
    eprintln!("Data\n{:02x?}", &archive[HEADER_SIZE + ENTRY_SIZE..]);
}

