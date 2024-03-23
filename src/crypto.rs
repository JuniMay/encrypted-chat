use anyhow::Result;
use openssl::{
    bn::BigNumContext,
    derive::Deriver,
    ec::{EcGroup, EcKey, EcPoint},
    nid::Nid,
    pkey::{PKey, Private, Public},
    rsa::Rsa,
    symm,
};

pub struct AesCrypto {
    key: Vec<u8>,
    cipher: symm::Cipher,
}

impl AesCrypto {
    pub fn new(key: Vec<u8>) -> Self {
        let cipher = symm::Cipher::aes_256_cbc();
        Self { key, cipher }
    }

    pub fn encrypt(&self, data: String) -> Result<Vec<u8>> {
        let encrypted = symm::encrypt(self.cipher, &self.key, None, data.as_bytes())?;
        Ok(encrypted)
    }

    pub fn decrypt(&self, data: Vec<u8>) -> Result<String> {
        let decrypted = symm::decrypt(self.cipher, &self.key, None, &data)?;
        Ok(String::from_utf8(decrypted)?)
    }
}

pub struct DesCrypto {
    key: Vec<u8>,
    cipher: symm::Cipher,
}

impl DesCrypto {
    pub fn new(key: Vec<u8>) -> Self {
        let cipher = symm::Cipher::des_ede3_cbc();
        Self { key, cipher }
    }

    pub fn encrypt(&self, data: String) -> Result<Vec<u8>> {
        let encrypted = symm::encrypt(self.cipher, &self.key, None, data.as_bytes())?;
        Ok(encrypted)
    }

    pub fn decrypt(&self, data: Vec<u8>) -> Result<String> {
        let decrypted = symm::decrypt(self.cipher, &self.key, None, &data)?;
        Ok(String::from_utf8(decrypted)?)
    }
}

/// RSA encryption and decryption
pub struct RsaCrypto {
    /// The RSA key pair
    rsa: Rsa<Private>,
    /// The peer's public key
    peer: Option<Rsa<Public>>,
}

impl RsaCrypto {
    /// Create a new RSA key pair
    pub fn new() -> Result<Self> {
        let rsa = Rsa::generate(2048)?;
        Ok(Self { rsa, peer: None })
    }

    /// Set the peer's public key
    pub fn set_peer_public_key(&mut self, public_key: Vec<u8>) -> Result<()> {
        let rsa = Rsa::public_key_from_pem(&public_key)?;
        self.peer = Some(rsa);
        Ok(())
    }

    /// Get the public key in PEM format
    pub fn public_key(&self) -> Result<Vec<u8>> {
        Ok(self.rsa.public_key_to_pem()?)
    }

    /// encrypt with the peer's public key
    pub fn encrypt(&self, data: String) -> Result<Vec<u8>> {
        if self.peer.is_none() {
            anyhow::bail!("Peer's public key is not set");
        }

        let peer = self.peer.as_ref().unwrap();
        let mut buffer = vec![0; peer.size() as usize];
        let size =
            peer.public_encrypt(data.as_bytes(), &mut buffer, openssl::rsa::Padding::PKCS1)?;
        buffer.truncate(size);
        Ok(buffer)
    }

    /// decrypt with the private key
    pub fn decrypt(&self, data: Vec<u8>) -> Result<String> {
        let mut buffer = vec![0; self.rsa.size() as usize];
        let size = self
            .rsa
            .private_decrypt(&data, &mut buffer, openssl::rsa::Padding::PKCS1)?;
        buffer.truncate(size);
        Ok(String::from_utf8(buffer)?)
    }
}

struct Ecdh {
    group: EcGroup,
    key: PKey<Private>,
}

impl Ecdh {
    fn new(curve: Nid) -> Result<Self> {
        let group = EcGroup::from_curve_name(curve)?;
        let key = EcKey::generate(&group)?;
        let key = PKey::from_ec_key(key)?;
        Ok(Self { group, key })
    }

    fn public_bytes(&self) -> Result<Vec<u8>> {
        let ec_key = self.key.ec_key()?;
        let point = ec_key.public_key();
        let mut ctx = BigNumContext::new()?;
        let bytes = point.to_bytes(
            &self.group,
            openssl::ec::PointConversionForm::COMPRESSED,
            &mut ctx,
        )?;
        Ok(bytes)
    }

    fn derive_shared_secret(&self, peer_public_bytes: &[u8]) -> Result<Vec<u8>> {
        let mut ctx = BigNumContext::new()?;
        let peer_point = EcPoint::from_bytes(&self.group, peer_public_bytes, &mut ctx)?;
        let peer_key = EcKey::from_public_key(&self.group, &peer_point)?;
        let peer_pkey = PKey::from_ec_key(peer_key)?;

        let mut deriver = Deriver::new(&self.key)?;
        deriver.set_peer(&peer_pkey)?;

        let secret = deriver.derive_to_vec()?;
        Ok(secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_crypto() {
        let alice = RsaCrypto::new().unwrap();
        let mut bob = RsaCrypto::new().unwrap();

        let msg = "Hello, world!".to_string();

        let alice_public_key = alice.public_key().unwrap();
        bob.set_peer_public_key(alice_public_key).unwrap();

        let encrypted = bob.encrypt(msg.clone()).unwrap();
        let decrypted = alice.decrypt(encrypted).unwrap();

        assert_eq!(msg, decrypted);
    }

    #[test]
    fn test_aes_crypto() {
        // 256-bit key, 32 bytes
        let key = b"0123456789abcdef0123456789abcdef".to_vec();
        let crypto = AesCrypto::new(key);

        let msg = "Hello, world!".to_string();

        let encrypted = crypto.encrypt(msg.clone()).unwrap();
        let decrypted = crypto.decrypt(encrypted).unwrap();

        assert_eq!(msg, decrypted);
    }

    #[test]
    fn test_des_crypto() {
        // 192-bit key, 24 bytes
        let key = b"0123456789abcdef01234567".to_vec();
        let crypto = DesCrypto::new(key);

        let msg = "Hello, world!".to_string();

        let encrypted = crypto.encrypt(msg.clone()).unwrap();
        let decrypted = crypto.decrypt(encrypted).unwrap();

        assert_eq!(msg, decrypted);
    }

    #[test]
    fn test_ecdh() {
        let alice = Ecdh::new(Nid::SECP384R1).unwrap();
        let bob = Ecdh::new(Nid::SECP384R1).unwrap();

        let alice_public_bytes = alice.public_bytes().unwrap();
        let bob_public_bytes = bob.public_bytes().unwrap();

        let alice_shared_secret = alice.derive_shared_secret(&bob_public_bytes).unwrap();
        let bob_shared_secret = bob.derive_shared_secret(&alice_public_bytes).unwrap();

        assert_eq!(alice_shared_secret, bob_shared_secret);
    }
}
