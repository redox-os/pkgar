#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate pkgar;

fuzz_target!(|data: &[u8]| {
    let public_key = pkgar::PublicKey::from_data([0; 32]);
    let _result = pkgar::Header::new(data, &public_key);
});
