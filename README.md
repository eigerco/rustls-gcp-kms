# Rustls KMS Provider
A Rust library that enables TLS client authentication via rustls using private keys stored in Google Cloud KMS (Key Management Service).

[![Build Status](https://github.com/eigerco/rustls-gcp-kms/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/eigerco/rustls-gcp-kms/actions/workflows/ci.yaml?query=branch%3Amain)


## Installation

Add the library to your Cargo.toml:

```toml
[dependencies]
rustls-gcp-kms = { git = "https://github.com/eigerco/rustls-gcp-kms.git" }

```

## Features
- serde: adds Serialize/Deserialize for `KmsConfig`


## Example

```rust
use std::sync::Arc;
use google_cloud_kms::client::{Client, ClientConfig};
use rustls::pki_types::CertificateDer;
use rustls::RootCertStore;
use rustls_gcp_kms::{dummy_key, provider, KmsConfig};

async fn send_request() -> Result<(), Box<dyn std::error::Error>> {
    // Configure KMS
    let kms_config = KmsConfig::new(
        "my-project-id",
        "global",
        "my-keyring",
        "my-signing-key",
        "1",
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
    let cert = std::fs::read("path/to/client.crt")?;
    let cert = CertificateDer::from_slice(&cert).into_owned();

    let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(crypto_provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(RootCertStore::empty())
        .with_client_auth_cert(vec![cert], dummy_key());

    // Configure reqwest with KMS-backed TLS
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .use_preconfigured_tls(client_config)
        .build()?;

    // Make a request with client certificate authentication
    let response = client
        .get("https://api.example.com/secure-endpoint")
        .send()
        .await?;

    println!("Response: {}", response.status());

    Ok(())
}
```

## Code of conduct

This project adopts the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct).
Please email rustls-mod@googlegroups.com to report any instance of misconduct, or if you
have any comments or questions on the Code of Conduct.
