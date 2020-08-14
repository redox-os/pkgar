mod error;

use std::fs::File;
use std::io::{self, Read, stdin, stdout, Write};
use std::ops::Deref;
use std::path::{Path, PathBuf};

use hex::FromHex;
use lazy_static::lazy_static;
use seckey::SecKey;
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::{
    pwhash,
    secretbox,
    sign,
};
use termion::input::TermRead;

pub use error::Error;

lazy_static! {
    static ref HOMEDIR: PathBuf = {
         dirs::home_dir()
            .unwrap_or("./".into())
    };
    pub static ref DEFAULT_PUBKEY: PathBuf = {
        Path::join(&HOMEDIR, ".pkgar/keys/id_ed25519.toml")
    };
    pub static ref DEFAULT_SECKEY: PathBuf = {
        Path::join(&HOMEDIR, ".pkgar/keys/id_ed25519.pub.toml")
    };
}

mod ser {
    use hex::FromHex;
    use serde::{Deserialize, Deserializer};
    use serde::de::Error;
    use sodiumoxide::crypto::{pwhash, secretbox, sign};
    
    //TODO: Macro?
    pub(crate) fn to_salt<'d, D: Deserializer<'d>>(deser: D) -> Result<pwhash::Salt, D::Error> {
        String::deserialize(deser)
            .and_then(|s| <[u8; 32]>::from_hex(s)
                .map(|val| pwhash::Salt(val) )
                .map_err(|err| Error::custom(err.to_string()) ) )
    }
    
    pub(crate) fn to_nonce<'d, D: Deserializer<'d>>(deser: D) -> Result<secretbox::Nonce, D::Error> {
        String::deserialize(deser)
            .and_then(|s| <[u8; 24]>::from_hex(s)
                .map(|val| secretbox::Nonce(val) )
                .map_err(|err| Error::custom(err.to_string()) ) )
    }
    
    pub(crate) fn to_pubkey<'d, D: Deserializer<'d>>(deser: D) -> Result<sign::PublicKey, D::Error> {
        String::deserialize(deser)
            .and_then(|s| <[u8; 32]>::from_hex(s)
                .map(|val| sign::PublicKey(val) )
                .map_err(|err| Error::custom(err.to_string()) ) )
    }

}

/// Standard pkgar public key format definition. Use serde to serialize/deserialize
/// files into this struct (helper methods available).
#[derive(Deserialize, Serialize)]
pub struct PublicKeyFile {
    #[serde(serialize_with = "hex::serialize", deserialize_with = "ser::to_pubkey")]
    pub pkey: sign::PublicKey,
}

impl PublicKeyFile {
    /// Helper function to deserialize.
    pub fn open(file: &Path) -> Result<PublicKeyFile, Error> {
        let mut s = String::new();
        File::open(file)?
            .read_to_string(&mut s)?;
        
        Ok(toml::from_str(&s)?)
    }
    
    /// Helper function to serialize and save.
    pub fn save(&self, file: &Path) -> Result<(), Error> {
        File::create(file)?
            .write_all(toml::to_string(self)?.as_bytes())?;
        Ok(())
    }
}

enum SKey {
    Cipher([u8; 80]),
    Plain(sign::SecretKey),
}

impl SKey {
    fn encrypt(&mut self, passwd: SecKey<str>, salt: pwhash::Salt, nonce: secretbox::Nonce) {
        if let SKey::Plain(skey) = self {
            if let Some(passwd_key) = gen_key(passwd, salt) {
                let mut buf = [0; 80];
                buf.copy_from_slice(&secretbox::seal(skey.as_ref(), &nonce, &passwd_key));
                *self = SKey::Cipher(buf);
            }
        }
    }
    
    fn decrypt(&mut self, passwd: SecKey<str>, salt: pwhash::Salt, nonce: secretbox::Nonce) -> Result<(), Error> {
        if let SKey::Cipher(ciphertext) = self {
            if let Some(passwd_key) = gen_key(passwd, salt) {
                let skey_plain = secretbox::open(ciphertext.as_ref(), &nonce, &passwd_key)
                    .map_err(|_| Error::PassphraseIncorrect )?;
                
                *self = SKey::Plain(sign::SecretKey::from_slice(&skey_plain)
                    .ok_or(Error::KeyInvalid)?);
            } else {
                *self = SKey::Plain(sign::SecretKey::from_slice(&ciphertext[..64])
                    .ok_or(Error::KeyInvalid)?);
            }
        }
        Ok(())
    }
    
    /// Returns `None` if encrypted
    fn skey(&self) -> Option<sign::SecretKey> {
        match &self {
            SKey::Plain(skey) => Some(skey.clone()),
            SKey::Cipher(_) => None,
        }
    }
}

impl AsRef<[u8]> for SKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            SKey::Cipher(buf) => buf.as_ref(),
            SKey::Plain(skey) => skey.as_ref(),
        }
    }
}

impl FromHex for SKey {
    type Error = hex::FromHexError;
    
    fn from_hex<T: AsRef<[u8]>>(buf: T) -> Result<SKey, hex::FromHexError> {
        let bytes = hex::decode(buf)?;
        
        // Public key is only 64 bytes...
        if bytes.len() == 64 {
            Ok(SKey::Plain(sign::SecretKey::from_slice(&bytes)
                                .expect("Somehow not the right number of bytes")))
        } else {
            let mut buf = [0; 80];
            buf.copy_from_slice(&bytes);
            Ok(SKey::Cipher(buf))
        }
    }
}

/// Standard pkgar private key format definition. Use serde.
/// Internally, this struct stores the encrypted state of the private key as an enum.
/// Manipulate the state using the `encrypt()`, `decrypt()` and `is_encrypted()`.
#[derive(Deserialize, Serialize)]
pub struct SecretKeyFile {
    #[serde(serialize_with = "hex::serialize", deserialize_with = "ser::to_salt")]
    salt: pwhash::Salt,
    #[serde(serialize_with = "hex::serialize", deserialize_with = "ser::to_nonce")]
    nonce: secretbox::Nonce,
    #[serde(with = "hex")]
    skey: SKey,
}

impl SecretKeyFile {
    /// Generate a keypair with all the nessesary info to save both
    /// keys. You must call `save()` on each object to persist to disk.
    pub fn new() -> (PublicKeyFile, SecretKeyFile) {
        let (pkey, skey) = sign::gen_keypair();
        
        let pkey_file = PublicKeyFile { pkey };
        let skey_file = SecretKeyFile {
            salt: pwhash::gen_salt(),
            nonce: secretbox::gen_nonce(),
            skey: SKey::Plain(skey),
        };
        
        (pkey_file, skey_file)
    }
    
    /// Parse a SecretKeyFile from `file`.
    pub fn open(file: &Path) -> Result<SecretKeyFile, Error> {
        let mut s = String::new();
        File::open(file)?
            .read_to_string(&mut s)?;
        
        Ok(toml::from_str(&s)?)
    }
    
    /// Save the secret key to `file`.
    /// Make sure to call `encrypt()` in order to encrypt
    /// the private key, otherwise it will be stored as plain text.
    pub fn save(&self, file: &Path) -> Result<(), Error> {
        File::create(file)?
            .write_all(toml::to_string(&self)?.as_bytes())?;
        Ok(())
    }
    
    /// Ensure that the internal state of this struct is encrypted.
    /// Note that if passwd is empty, this function is a no-op.
    pub fn encrypt(&mut self, passwd: SecKey<str>) {
        self.skey.encrypt(passwd, self.salt, self.nonce)
    }
    
    /// Ensure that the internal state of this struct is decrypted.
    /// If the internal state is already decrypted, this function is a no-op.
    pub fn decrypt(&mut self, passwd: SecKey<str>) -> Result<(), Error> {
        self.skey.decrypt(passwd, self.salt, self.nonce)
    }
    
    /// Status of the internal state.
    pub fn is_encrypted(&self) -> bool {
        match self.skey {
            SKey::Cipher(_) => true,
            SKey::Plain(_) => false,
        }
    }
    
    /// Returns `None` if the secret key is encrypted.
    pub fn key(&mut self) -> Option<sign::SecretKey> {
        match &self.skey {
            SKey::Plain(skey) => Some(skey.clone()),
            SKey::Cipher(_) => None,
        }
    }
    
    /// Returns `None` if the secret key is encrypted.
    pub fn public_key_file(&self) -> Option<PublicKeyFile> {
        Some(PublicKeyFile {
            pkey: self.skey.skey()?.public_key(),
        })
    }
}

/// Get a key for symmetric key encryption from a password.
fn gen_key(passwd: SecKey<str>, salt: pwhash::Salt) -> Option<secretbox::Key> {
    if passwd.read().deref() == "" {
        None
    } else {
        let mut key = secretbox::Key([0; secretbox::KEYBYTES]);
        let secretbox::Key(ref mut binary_key) = key;
        
        pwhash::derive_key(binary_key, passwd.read().as_bytes(), &salt,
                           pwhash::OPSLIMIT_INTERACTIVE,
                           pwhash::MEMLIMIT_INTERACTIVE)
            .expect("Failed to get key from password");
        Some(key)
    }
}

/// Prompt the user for a password on stdin.
fn get_passwd(prompt: &str) -> Result<SecKey<str>, Error> {
    let stdout = stdout();
    let mut stdout = stdout.lock();
    let stdin = stdin();
    let mut stdin = stdin.lock();
    
    stdout.write_all(prompt.as_bytes())?;
    stdout.flush()?;
    
    let mut passwd = stdin.read_passwd(&mut stdout)?
        .ok_or(Error::Io(io::Error::new(io::ErrorKind::UnexpectedEof, "Invalid Password Input")))?;
    
    let passwd = SecKey::from_str(&mut passwd)
        .ok_or(Error::MAlloc)?;
    
    println!();
    
    Ok(passwd)
}

/// Prompt for a password and confirm it.
fn get_new_passwd() -> Result<SecKey<str>, Error> {
    let passwd = get_passwd("Please enter a new passphrase (leave empty to store the key in plaintext): ")?;
    let confirm = get_passwd("Please re-enter the passphrase: ")?;
    
    if passwd.read().deref() != confirm.read().deref() {
        Err(Error::PassphraseMismatch)
    } else {
        Ok(passwd)
    }
}

/// Generate a new keypair. The new keys will be saved to `file`. The user
/// will be prompted on stdin for a password, empty passwords will cause the
/// secret key to be stored in plain text. Note that parent
/// directories will not be created.
pub fn gen_keypair(pkey_path: &Path, skey_path: &Path) -> Result<(PublicKeyFile, SecretKeyFile), Error> {
    let passwd = get_new_passwd()?;

    let (pkey_file, mut skey_file) = SecretKeyFile::new();
    
    skey_file.encrypt(passwd);
    skey_file.save(skey_path)?;
    
    pkey_file.save(pkey_path)?;
    
    println!("Generated {} and {}", pkey_path.display(), skey_path.display());
    Ok((pkey_file, skey_file))
}

/// Get a SecretKeyFile from a path. If the file is encrypted, prompt for a password on stdin.
pub fn get_skey(skey_path: &Path) -> Result<SecretKeyFile, Error> {
    let mut key_file = SecretKeyFile::open(skey_path)?;
    
    if key_file.is_encrypted() {
        let passwd = get_passwd(&format!("Passphrase for {}: ", skey_path.display()))?;
        key_file.decrypt(passwd)?;
    }
    
    Ok(key_file)
}

/// Open, decrypt, re-encrypt with a different passphrase from stdin, and save the newly encrypted
/// secret key at `skey_path`.
pub fn re_encrypt(skey_path: &Path) -> Result<(), Error> {
    let mut skey_file = SecretKeyFile::open(skey_path)?;
    
    if skey_file.is_encrypted() {
        let passwd = get_passwd(&format!("Old passphrase for {}: ", skey_path.display()))?;
        skey_file.decrypt(passwd)?;
    }
    
    let passwd = get_new_passwd()?;
    skey_file.encrypt(passwd);
    
    skey_file.save(skey_path)
}

