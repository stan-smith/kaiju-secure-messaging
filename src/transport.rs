use crate::error::{KaijuError, Result};
use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig};
use std::sync::Arc;
use std::time::Duration;
use std::net::SocketAddr;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

pub const ALPN_PROTOCOL: &[u8] = b"kaiju-secure-messaging";

pub struct QuicTransport;

impl QuicTransport {
    pub fn generate_self_signed_cert() -> Result<(Vec<CertificateDer<'static>>, PrivatePkcs8KeyDer<'static>)> {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .map_err(|e| KaijuError::Transport(format!("Certificate generation failed: {}", e)))?;
        
        let cert_der = CertificateDer::from(cert.cert);
        let key_der = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
        
        Ok((vec![cert_der], key_der))
    }
    
    pub fn create_server_config() -> Result<ServerConfig> {
        // Install the crypto provider at the start
        let _ = rustls::crypto::ring::default_provider().install_default();
        
        let (cert_chain, key) = Self::generate_self_signed_cert()?;
        
        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key.into())
            .map_err(|e| KaijuError::Transport(format!("Server config failed: {}", e)))?;
        
        server_crypto.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];
        
        let mut server_config = ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
                .map_err(|e| KaijuError::Transport(format!("QUIC server config failed: {}", e)))?
        ));
        
        let mut transport_config = TransportConfig::default();
        transport_config
            .max_concurrent_bidi_streams(100_u8.into())
            .max_concurrent_uni_streams(100_u8.into())
            .max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap()))
            .keep_alive_interval(Some(Duration::from_secs(10)));
        
        server_config.transport_config(Arc::new(transport_config));
        
        Ok(server_config)
    }
    
    pub fn create_client_config() -> Result<ClientConfig> {
        // Install the crypto provider at the start
        let _ = rustls::crypto::ring::default_provider().install_default();
        
        let mut crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();
        
        // Set ALPN protocol to match server
        crypto.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];
        
        let mut client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .map_err(|e| KaijuError::Transport(format!("QUIC client config failed: {}", e)))?
        ));
        
        let mut transport_config = TransportConfig::default();
        transport_config
            .max_concurrent_bidi_streams(100_u8.into())
            .max_concurrent_uni_streams(100_u8.into())
            .max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap()))
            .keep_alive_interval(Some(Duration::from_secs(10)));
        
        client_config.transport_config(Arc::new(transport_config));
        
        Ok(client_config)
    }
    
    pub async fn create_server_endpoint(addr: SocketAddr) -> Result<Endpoint> {
        let server_config = Self::create_server_config()?;
        let endpoint = Endpoint::server(server_config, addr)
            .map_err(|e| KaijuError::Transport(format!("Failed to create server endpoint: {}", e)))?;
        
        Ok(endpoint)
    }
    
    pub fn create_client_endpoint() -> Result<Endpoint> {
        let client_config = Self::create_client_config()?;
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| KaijuError::Transport(format!("Failed to create client endpoint: {}", e)))?;
        
        endpoint.set_default_client_config(client_config);
        
        Ok(endpoint)
    }
}

#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}