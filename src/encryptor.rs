use async_trait::async_trait;
use thiserror::Error;

/// Errors returned by [`KeyEncryptor`] implementations.
#[derive(Debug, Error)]
pub enum EncryptorError {
    /// The ciphertext was produced with a key version this encryptor cannot decrypt.
    #[error("wrong key version: {0}")]
    WrongKeyVersion(u8),
    /// The encryption operation failed.
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),
    /// The decryption operation failed.
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),
    /// A nonce is required for decryption but was not present in the payload.
    #[error("missing nonce")]
    MissingNonce,
    /// An AWS KMS API error occurred.
    #[cfg(feature = "aws-kms")]
    #[error("KMS error: {0}")]
    Kms(Box<dyn std::error::Error + Send + Sync + 'static>),
}

/// An encrypted payload produced by a [`KeyEncryptor`].
#[derive(Clone)]
pub struct Encrypted {
    /// The encrypted key bytes (ciphertext).
    pub ciphertext: Vec<u8>,
    /// The nonce/IV used during encryption (`None` for KMS/no-op, which manage their own IV).
    pub nonce: Option<[u8; 12]>,
    /// The version of the data-encryption key used (0 = plaintext/no-op).
    pub key_version: u8,
}

/// Encrypts and decrypts key material before it is persisted to storage.
///
/// Use [`NoOpEncryptor`](crate::no_op_encryptor::NoOpEncryptor) when at-rest encryption is
/// not required. For local AES-256-GCM-SIV use `LocalEncryptor`. For AWS KMS use `KmsEncryptor`.
#[async_trait]
pub trait KeyEncryptor: Send + Sync + 'static {
    /// Encrypt `plaintext` and return the ciphertext bundle.
    async fn encrypt(&self, plaintext: &[u8]) -> Result<Encrypted, EncryptorError>;
    /// Decrypt an [`Encrypted`] bundle back to plaintext.
    async fn decrypt(&self, encrypted: &Encrypted) -> Result<Vec<u8>, EncryptorError>;
}
