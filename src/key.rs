use rand_core::{CryptoRng, Error, RngCore};

pub struct PublicKey([u8; 32]);

impl PublicKey {
    pub fn from_data(data: [u8; 32]) -> Self {
        Self(data)
    }

    pub fn as_data(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn into_data(self) -> [u8; 32] {
        self.0
    }
}

pub struct SecretKey([u8; 64]);

impl SecretKey {
    pub fn new<R: CryptoRng + RngCore>(rng: &mut R) -> Result<Self, Error> {
        let mut seed = [0; 32];
        rng.try_fill_bytes(&mut seed)?;

        let mut public_key = [0; 32];
        let mut secret_key = [0; 64];
        sodalite::sign_keypair_seed(&mut public_key, &mut secret_key, &seed);

        assert_eq!(public_key, secret_key[32..]);

        Ok(Self::from_data(secret_key))
    }

    pub fn from_data(data: [u8; 64]) -> Self {
        Self(data)
    }

    pub fn as_data(&self) -> &[u8; 64] {
        &self.0
    }

    pub fn into_data(self) -> [u8; 64] {
        self.0
    }

    pub fn public_key(&self) -> PublicKey {
        let mut public_key = [0; 32];
        public_key.copy_from_slice(&self.0[32..]);
        PublicKey::from_data(public_key)
    }
}
