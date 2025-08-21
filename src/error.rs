use thiserror::Error;

#[derive(Error, Debug)]
pub enum KaijuError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("QUIC error: {0}")]
    Quinn(#[from] quinn::ConnectionError),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),
    
    #[error("Cryptographic error: {0}")]
    Crypto(String),
    
    #[error("Invalid message format")]
    InvalidMessage,
    
    #[error("Authentication failed")]
    AuthenticationFailed,
    
    #[error("Message expired")]
    MessageExpired,
    
    #[error("Replay detected")]
    ReplayDetected,
    
    #[error("HMAC verification failed")]
    HmacVerificationFailed,
    
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
    
    #[error("Decryption failed")]
    DecryptionFailed,
    
    #[error("Device not trusted")]
    DeviceNotTrusted,
    
    #[error("Invalid device ID")]
    InvalidDeviceId,
    
    #[error("Connection timeout")]
    Timeout,
    
    #[error("Maximum message size exceeded")]
    MessageTooLarge,
    
    #[error("Transport error: {0}")]
    Transport(String),
    
    #[error("Write error: {0}")]
    Write(#[from] quinn::WriteError),
    
    #[error("Read error: {0}")]
    Read(#[from] quinn::ReadError),
    
    #[error("Read exact error: {0}")]
    ReadExact(#[from] quinn::ReadExactError),
    
    #[error("Stream finish error: {0}")]
    Finish(#[from] quinn::ClosedStream),
}

pub type Result<T> = std::result::Result<T, KaijuError>;