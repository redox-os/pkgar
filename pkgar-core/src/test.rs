use std::mem;
use std::vec::Vec;
use std::vec;

use sodiumoxide::crypto::sign;

use crate::{Entry, ENTRY_SIZE, Header, HEADER_SIZE};

const ZEROS_PACKAGE_LEN: usize = HEADER_SIZE + (ENTRY_SIZE * 2) + 1000;
pub const ZEROS_PACKAGE: [u8; ZEROS_PACKAGE_LEN] = [0; ZEROS_PACKAGE_LEN];

pub const PACKAGE_ENTRY1: &[u8] = b"some random string file contents\n";
pub const PACKAGE_ENTRY1_PATH: &[u8] = b"var/db/fun";

pub const PACKAGE_ENTRY2: &[u8] = b"{\"__comment\":\"Some json data\", \"my_float\":92.17364}";
pub const PACKAGE_ENTRY2_PATH: &[u8] = b"lib/extra/randomjson.json";

// returns (head, data)
pub fn package(pkey: sign::PublicKey, skey: sign::SecretKey) -> (Vec<u8>, Vec<u8>) {
    let mut header = Header {
        signature: [0; 64],
        public_key: pkey.0,
        blake3: [0; 32],
        count: 2,
    };
    
    let mut entries = Vec::with_capacity(2);
    entries.push(Entry {
        blake3: blake3::hash(PACKAGE_ENTRY1).into(),
        offset: 0,
        size: PACKAGE_ENTRY1.len() as u64,
        mode: 0o640,
        path: [0; 256],
    });
    entries[0].path[..PACKAGE_ENTRY1_PATH.len()].copy_from_slice(PACKAGE_ENTRY1_PATH);
    
    entries.push(Entry {
        blake3: blake3::hash(PACKAGE_ENTRY2).into(),
        offset: PACKAGE_ENTRY1.len() as u64,
        size: PACKAGE_ENTRY2.len() as u64,
        mode: 0o644,
        path: [0; 256],
    });
    entries[1].path[..PACKAGE_ENTRY2_PATH.len()].copy_from_slice(PACKAGE_ENTRY2_PATH);
    
    let mut entries_bytes = vec![];
    for entry in entries.iter() {
        entries_bytes.extend_from_slice(unsafe { plain::as_bytes(entry) });
    }
    
    header.blake3 = blake3::hash(&entries_bytes).into();
    
    let header_bytes = unsafe { plain::as_bytes(&header) };
    header.signature = sign::sign_detached(&header_bytes[64..], &skey)
        .to_bytes();
    
    let mut head = vec![];
    head.extend_from_slice(unsafe { plain::as_bytes(&header) });
    head.extend_from_slice(&entries_bytes);
    
    let mut data = vec![];
    data.extend_from_slice(PACKAGE_ENTRY1);
    data.extend_from_slice(PACKAGE_ENTRY2);
    
    (head, data)
}

#[test]
fn header_size() {
    assert_eq!(mem::size_of::<Header>(), 136);
    assert_eq!(HEADER_SIZE, 136);
}

#[test]
fn entry_size() {
    assert_eq!(mem::size_of::<Entry>(), 308);
    assert_eq!(ENTRY_SIZE, 308);
}

