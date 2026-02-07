mod error;

use std::fs::{self, File, OpenOptions};
use std::io::{self, stdin, stdout, Write};
use std::ops::Deref;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use hex::FromHex;
use lazy_static::lazy_static;
use pkgar_core::{
    dryoc::{
        classic::{
            crypto_pwhash::{crypto_pwhash, PasswordHashAlgorithm},
            crypto_secretbox::{crypto_secretbox_easy, crypto_secretbox_open_easy, Key, Nonce},
            crypto_sign::{crypto_sign_keypair, crypto_sign_seed_keypair},
        },
        constants::{CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE, CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE},
        types::NewByteArray,
    },
    PublicKey, SecretKey,
};
use seckey::SecBytes;
use serde::{Deserialize, Serialize};
use termion::input::TermRead;

type Salt = [u8; 32];

pub use crate::error::Error;

lazy_static! {
    static ref HOMEDIR: PathBuf = {
         dirs::home_dir()
            .unwrap_or("./".into())
    };

    /// The default location for pkgar to look for the user's public key.
    ///
    /// Defaults to `$HOME/.pkgar/keys/id_ed25519.pub.toml`. If `$HOME` is
    /// unset, `./.pkgar/keys/id_ed25519.pub.toml`.
    pub static ref DEFAULT_PUBKEY: PathBuf = {
        Path::join(&HOMEDIR, ".pkgar/keys/id_ed25519.pub.toml")
    };

    /// The default location for pkgar to look for the user's secret key.
    ///
    /// Defaults to `$HOME/.pkgar/keys/id_ed25519.toml`. If `$HOME` is unset,
    /// `./.pkgar/keys/id_ed25519.toml`.
    pub static ref DEFAULT_SECKEY: PathBuf = {
        Path::join(&HOMEDIR, ".pkgar/keys/id_ed25519.toml")
    };
}

mod ser {
    use hex::FromHex;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer};

    use crate::{Nonce, PublicKey, Salt};

    //TODO: Macro?
    pub(crate) fn to_salt<'d, D: Deserializer<'d>>(deser: D) -> Result<Salt, D::Error> {
        String::deserialize(deser)
            .and_then(|s| <[u8; 32]>::from_hex(s).map_err(|err| Error::custom(err.to_string())))
    }

    pub(crate) fn to_nonce<'d, D: Deserializer<'d>>(deser: D) -> Result<Nonce, D::Error> {
        String::deserialize(deser)
            .and_then(|s| <[u8; 24]>::from_hex(s).map_err(|err| Error::custom(err.to_string())))
    }

    pub(crate) fn to_pubkey<'d, D: Deserializer<'d>>(deser: D) -> Result<PublicKey, D::Error> {
        String::deserialize(deser)
            .and_then(|s| <[u8; 32]>::from_hex(s).map_err(|err| Error::custom(err.to_string())))
    }
}

/// Standard pkgar public key format definition. Use serde to serialize/deserialize
/// files into this struct (helper methods available).
#[derive(Clone, Deserialize, Serialize)]
pub struct PublicKeyFile {
    #[serde(serialize_with = "hex::serialize", deserialize_with = "ser::to_pubkey")]
    pub pkey: PublicKey,
}

impl PublicKeyFile {
    /// Parse a `PublicKeyFile` from `file` (in toml format).
    pub fn open(file: impl AsRef<Path>) -> Result<PublicKeyFile, Error> {
        let content = fs::read_to_string(file)?;
        toml::from_str(&content).map_err(Error::Deser)
    }

    /// Write `self` serialized as toml to `w`.
    pub fn write(&self, mut w: impl Write) -> Result<(), Error> {
        w.write_all(toml::to_string(self)?.as_bytes())
            .map_err(Error::Io)
    }

    /// Shortcut to write the public key to `file`
    pub fn save(&self, file: impl AsRef<Path>) -> Result<(), Error> {
        self.write(File::create(file)?)
    }
}

impl std::fmt::Debug for PublicKeyFile {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("PublicKeyFile")
            .field("pkey", &hex::encode(self.pkey))
            .finish()
    }
}

enum SKey {
    Cipher([u8; 80]),
    Plain(SecretKey),
}

impl SKey {
    fn encrypt(&mut self, passwd: Passwd, salt: Salt, nonce: Nonce) -> Result<(), Error> {
        if let SKey::Plain(skey) = self {
            if let Some(passwd_key) = passwd.gen_key(salt) {
                let mut buf = [0; 80];
                crypto_secretbox_easy(&mut buf, skey.as_ref(), &nonce, &passwd_key)
                    .map_err(pkgar_core::Error::Dryoc)?;
                *self = SKey::Cipher(buf);
            }
        }
        Ok(())
    }

    fn decrypt(&mut self, passwd: Passwd, salt: Salt, nonce: Nonce) -> Result<(), Error> {
        if let SKey::Cipher(ciphertext) = self {
            let mut buf = [0; 64];
            if let Some(passwd_key) = passwd.gen_key(salt) {
                crypto_secretbox_open_easy(&mut buf, ciphertext.as_ref(), &nonce, &passwd_key)
                    .map_err(pkgar_core::Error::Dryoc)?;
            } else {
                let skey_plain = &ciphertext[..64];
                if skey_plain.len() != buf.len() {
                    return Err(Error::KeyInvalid {
                        expected: buf.len(),
                        actual: skey_plain.len(),
                    });
                }
                buf.copy_from_slice(skey_plain);
            }
            *self = SKey::Plain(buf);
        }
        Ok(())
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
            let mut buf = [0; 64];
            buf.copy_from_slice(&bytes);
            Ok(SKey::Plain(buf))
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
    salt: Salt,
    #[serde(serialize_with = "hex::serialize", deserialize_with = "ser::to_nonce")]
    nonce: Nonce,
    #[serde(with = "hex")]
    skey: SKey,
}

impl SecretKeyFile {
    /// Generate a keypair with all the nessesary info to save both keys. You
    /// must call `save()` on each object to persist them to disk.
    pub fn new() -> (PublicKeyFile, SecretKeyFile) {
        let (pkey, skey) = crypto_sign_keypair();

        let pkey_file = PublicKeyFile { pkey };
        let skey_file = SecretKeyFile {
            salt: Salt::gen(),
            nonce: Nonce::gen(),
            skey: SKey::Plain(skey),
        };

        (pkey_file, skey_file)
    }

    /// Parse a `SecretKeyFile` from `file` (in toml format).
    pub fn open(file: impl AsRef<Path>) -> Result<SecretKeyFile, Error> {
        let content = fs::read_to_string(file)?;
        toml::from_str(&content).map_err(Error::Deser)
    }

    /// Write `self` serialized as toml to `w`.
    pub fn write(&self, mut w: impl Write) -> Result<(), Error> {
        w.write_all(toml::to_string(&self)?.as_bytes())?;
        Ok(())
    }

    /// Shortcut to write the secret key to `file`.
    ///
    /// Make sure to call `encrypt()` in order to encrypt
    /// the private key, otherwise it will be stored as plain text.
    pub fn save(&self, file: impl AsRef<Path>) -> Result<(), Error> {
        self.write(
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(file)?,
        )
    }

    /// Ensure that the internal state of this struct is encrypted.
    /// Note that if passwd is empty, this function is a no-op.
    pub fn encrypt(&mut self, passwd: Passwd) -> Result<(), Error> {
        self.skey.encrypt(passwd, self.salt, self.nonce)
    }

    /// Ensure that the internal state of this struct is decrypted.
    /// If the internal state is already decrypted, this function is a no-op.
    pub fn decrypt(&mut self, passwd: Passwd) -> Result<(), Error> {
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
    pub fn secret_key(&self) -> Option<SecretKey> {
        match &self.skey {
            SKey::Plain(skey) => Some(*skey),
            SKey::Cipher(_) => None,
        }
    }

    /// Returns `None` if the secret key is encrypted.
    pub fn public_key(&self) -> Option<PublicKey> {
        let skey = self.secret_key()?;
        let mut seed = [0; 32];
        seed.copy_from_slice(&skey[..32]);
        let (pkey, new_skey) = crypto_sign_seed_keypair(&seed);
        assert_eq!(skey, new_skey);
        Some(pkey)
    }

    /// Returns `None` if the secret key is encrypted.
    pub fn public_key_file(&self) -> Option<PublicKeyFile> {
        Some(PublicKeyFile {
            pkey: self.public_key()?,
        })
    }
}

/// Secure in-memory representation of a password.
pub struct Passwd {
    bytes: SecBytes,
}

impl Passwd {
    /// Create a new `Passwd` and zero the old string.
    pub fn new(passwd: &mut String) -> Passwd {
        let pwd = Passwd {
            bytes: SecBytes::with(passwd.len(), |buf| buf.copy_from_slice(passwd.as_bytes())),
        };
        unsafe {
            seckey::zero(passwd.as_bytes_mut());
        }
        pwd
    }

    /// Prompt the user for a `Passwd` on stdin.
    pub fn prompt(prompt: impl AsRef<str>) -> Result<Passwd, Error> {
        let stdout = stdout();
        let mut stdout = stdout.lock();
        let stdin = stdin();
        let mut stdin = stdin.lock();

        stdout.write_all(prompt.as_ref().as_bytes())?;
        stdout.flush()?;

        let mut passwd = stdin
            .read_passwd(&mut stdout)?
            .ok_or(Error::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Invalid Password Input",
            )))?;
        println!();

        Ok(Passwd::new(&mut passwd))
    }

    /// Prompt for a password on stdin and confirm it. For configurable
    /// prompts, use [`Passwd::prompt`](struct.Passwd.html#method.prompt).
    pub fn prompt_new() -> Result<Passwd, Error> {
        let passwd = Passwd::prompt(
            "Please enter a new passphrase (leave empty to store the key in plaintext): ",
        )?;
        let confirm = Passwd::prompt("Please re-enter the passphrase: ")?;

        if passwd != confirm {
            return Err(Error::PassphraseMismatch);
        }
        Ok(passwd)
    }

    /// Get a key for symmetric key encryption from a password.
    fn gen_key(&self, salt: Salt) -> Option<Key> {
        if self.bytes.read().len() > 0 {
            let mut key = [0; 32];
            crypto_pwhash(
                &mut key,
                &self.bytes.read(),
                &salt,
                CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
                CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
                PasswordHashAlgorithm::Argon2id13,
            )
            .expect("Failed to get key from password");
            Some(key)
        } else {
            None
        }
    }
}

impl PartialEq for Passwd {
    fn eq(&self, other: &Passwd) -> bool {
        self.bytes.read().deref() == other.bytes.read().deref()
    }
}
impl Eq for Passwd {}

/// Generate a new keypair. The new keys will be saved to `file`. The user
/// will be prompted on stdin for a password, empty passwords will cause the
/// secret key to be stored in plain text. Note that parent
/// directories will not be created.
pub fn gen_keypair(
    pkey_path: &Path,
    skey_path: &Path,
) -> Result<(PublicKeyFile, SecretKeyFile), Error> {
    let passwd = Passwd::prompt_new()?;

    let (pkey_file, mut skey_file) = SecretKeyFile::new();

    skey_file.encrypt(passwd)?;
    skey_file.save(skey_path)?;

    pkey_file.save(pkey_path)?;

    println!(
        "Generated {} and {}",
        pkey_path.display(),
        skey_path.display()
    );
    Ok((pkey_file, skey_file))
}

fn prompt_skey(skey_path: &Path, prompt: impl AsRef<str>) -> Result<SecretKeyFile, Error> {
    let mut key_file = SecretKeyFile::open(skey_path)?;

    if key_file.is_encrypted() {
        let passwd = Passwd::prompt(format!("{} {}: ", prompt.as_ref(), skey_path.display()))?;
        key_file.decrypt(passwd)?;
    }
    Ok(key_file)
}

/// Get a SecretKeyFile from a path. If the file is encrypted, prompt for a password on stdin.
pub fn get_skey(skey_path: &Path) -> Result<SecretKeyFile, Error> {
    prompt_skey(skey_path, "Passphrase for")
}

/// Open, decrypt, re-encrypt with a different passphrase from stdin, and save the newly encrypted
/// secret key at `skey_path`.
pub fn re_encrypt(skey_path: &Path) -> Result<(), Error> {
    let mut skey_file = prompt_skey(skey_path, "Old passphrase for")?;

    let passwd = Passwd::prompt_new()?;
    skey_file.encrypt(passwd)?;

    skey_file.save(skey_path)
}
