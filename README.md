# Rustls KMS Provider (WIP)
A Rust library that enables TLS client authentication via rustls using private keys stored in Google Cloud KMS (Key Management Service).

[![Build Status](https://github.com/vaporif/rustls-gcp-kms/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/vaporif/rustls-gcp-kms/actions/workflows/ci.yaml?query=branch%3Amain)

Installation

Add the library to your Cargo.toml:

```toml
[dependencies]
rustls-kms = "0.1.0"
```

# Code of conduct

This project adopts the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct).
Please email rustls-mod@googlegroups.com to report any instance of misconduct, or if you
have any comments or questions on the Code of Conduct.

# Example

```rust
use rustls_kms::{KmsConfig, provider};
use reqwest::Certificate;
use std::sync::Arc;
use google_cloud_kms::client::{Client, ClientConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure KMS
    let kms_config = KmsConfig::new(
        "my-project-id",
        "global",
        "my-keyring",
        "my-signing-key",
        "1"
    );

    let client_config = ClientConfig::default()
       .with_auth()
       .await?;

    let client = Client::new(client_config)
        .await
        .unwrap();

    // Create the crypto provider with KMS
    let crypto_provider = provider(client, kms_config).await?;

    // Load your client certificate
    let cert_pem = std::fs::read("path/to/client.crt")?;
    let cert = Certificate::from_pem(&cert_pem)?;

    // Create a dummy private key (not actually used)
    let dummy_key = rustls::pki_types::PrivateKeyDer::from(vec![0u8; 32]);

    // Configure reqwest with KMS-backed TLS
    let client = reqwest::Client::builder()
        .use_preconfigured_tls(
            rustls::ClientConfig::builder()
                .with_provider(Arc::new(crypto_provider))
                .with_client_auth_cert(
                    vec![cert.clone().into()],
                    dummy_key
                )?
        )
        .build()?;

    // Make a request with client certificate authentication
    let response = client.get("https://api.example.com/secure-endpoint")
        .send()
        .await?;

    println!("Response: {}", response.status());

    Ok(())
}
