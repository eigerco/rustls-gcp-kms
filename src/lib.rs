#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(clippy::cargo)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::implicit_return)]
#![allow(clippy::missing_docs_in_private_items)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::wildcard_enum_match_arm)]
#![allow(clippy::shadow_reuse)]
#![allow(clippy::question_mark_used)]
#![allow(clippy::trivially_copy_pass_by_ref)]
#![allow(clippy::pattern_type_mismatch)]
#![allow(clippy::single_call_fn)]
#![allow(clippy::str_to_string)]
#![allow(clippy::missing_inline_in_public_items)]
#![allow(clippy::multiple_crate_versions)]

//! Rustls KMS Provider
//!
//! A library that enables TLS client authentication using private keys stored in Google Cloud KMS.
//! This allows secure key management where the private key never leaves the secure KMS environment.
//!
//! Use [`provider`](`client:google_cloud_kms::client::Client`, `kms_config: KmsConfig`) to create a new provider with the specified KMS configuration.

use core::fmt::Debug;
use std::sync::Arc;

use futures::executor::block_on;
use google_cloud_kms::client::{google_cloud_auth, Client};
use google_cloud_kms::grpc::kms::v1::crypto_key::CryptoKeyPurpose;
use google_cloud_kms::grpc::kms::v1::crypto_key_version::CryptoKeyVersionAlgorithm;
use google_cloud_kms::grpc::kms::v1::{
    digest, AsymmetricSignRequest, Digest, GetCryptoKeyRequest, GetCryptoKeyVersionRequest,
    GetPublicKeyRequest,
};
use rustls::crypto::{CryptoProvider, KeyProvider};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{PrivateKeyDer, SubjectPublicKeyInfoDer};
use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};
use thiserror::Error;

/// KMS Signer implementation that delegates TLS signing operations to Google Cloud KMS
#[derive(Debug, Clone)]
struct KmsSigner {
    /// Google Cloud KMS client
    client: Arc<Client>,
    /// Key version name in GCP resource format
    cryptokey_version_name: String,
    /// Supported signature scheme
    scheme: SignatureScheme,
    /// Supported signature algorithm
    algorithm: SignatureAlgorithm,
    /// Public key corresponding to the private key in KMS
    public_key: SubjectPublicKeyInfoDer<'static>,
    /// Whether this key meets FIPS requirements
    fips: bool,
}

impl KmsSigner {
    async fn connect(client: Client, kms_cfg: KmsConfig) -> Result<Self, KmsError> {
        let crypto_key = client
            .get_crypto_key(
                GetCryptoKeyRequest {
                    name: kms_cfg.crypto_key_name,
                },
                None,
            )
            .await
            .map_err(KmsError::GetCryptoKey)?;

        let purpose = crypto_key.purpose();

        if purpose != CryptoKeyPurpose::AsymmetricSign {
            return Err(KmsError::UnexpectedKeyPurpose(purpose));
        }

        let crypto_key_version = client
            .get_crypto_key_version(
                GetCryptoKeyVersionRequest {
                    name: kms_cfg.crypto_key_version_name.clone(),
                },
                None,
            )
            .await
            .map_err(KmsError::GetCryptoKeyVersion)?;

        let public_key_pem = client
            .get_public_key(
                GetPublicKeyRequest {
                    name: kms_cfg.crypto_key_version_name.clone(),
                    public_key_format: 0,
                },
                None,
            )
            .await
            .map_err(KmsError::GetPublicKey)?
            .pem;

        let public_key = SubjectPublicKeyInfoDer::from_pem_slice(public_key_pem.as_bytes())?;
        let kms_algorithm = crypto_key_version.algorithm();

        let scheme_opt = map_to_rustls_scheme(&kms_algorithm);
        let algorithm_opt = map_to_rustls_algorithm(&kms_algorithm);

        let (Some(scheme), Some(algorithm)) = (scheme_opt, algorithm_opt) else {
            return Err(KmsError::UnsupportedScheme(
                kms_algorithm.as_str_name().to_owned(),
            ));
        };

        let fips = is_fips_approved(&kms_algorithm);
        let client = Arc::new(client);

        Ok(Self {
            client,
            cryptokey_version_name: kms_cfg.crypto_key_version_name,
            scheme,
            algorithm,
            public_key,
            fips,
        })
    }
}

impl Signer for KmsSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let digest = match self.scheme {
            SignatureScheme::RSA_PKCS1_SHA256
            | SignatureScheme::RSA_PSS_SHA256
            | SignatureScheme::ECDSA_NISTP256_SHA256 => {
                use sha2::Digest as _;
                let hash = sha2::Sha256::digest(message);
                Digest {
                    digest: Some(digest::Digest::Sha256(hash.to_vec())),
                }
            }
            SignatureScheme::ECDSA_NISTP384_SHA384 => {
                use sha2::Digest as _;
                let hash = sha2::Sha384::digest(message);
                Digest {
                    digest: Some(digest::Digest::Sha384(hash.to_vec())),
                }
            }
            SignatureScheme::RSA_PKCS1_SHA512 | SignatureScheme::RSA_PSS_SHA512 => {
                use sha2::Digest as _;
                let hash = sha2::Sha512::digest(message);
                Digest {
                    digest: Some(digest::Digest::Sha512(hash.to_vec())),
                }
            }
            scheme => {
                return Err(rustls::Error::General(format!(
                    "Unsupported signature scheme {}",
                    scheme.as_str().unwrap_or_default()
                )));
            }
        };

        let req = AsymmetricSignRequest {
            name: self.cryptokey_version_name.clone(),
            data: message.to_vec(),
            digest: Some(digest),
            ..Default::default()
        };

        let sign_response = self.client.asymmetric_sign(req, None);
        let sign_response = block_on(sign_response).map_err(|err| {
            rustls::Error::General(format!("KMS signing operation failed due to err: {err}"))
        })?;

        Ok(sign_response.signature)
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

impl SigningKey for KmsSigner {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&self.scheme) {
            return Some(Box::new(self.clone()));
        }

        None
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(self.public_key.clone())
    }
}

impl KeyProvider for KmsSigner {
    fn fips(&self) -> bool {
        self.fips
    }

    fn load_private_key(
        &self,
        // NOTE: this will be dummy cert due to use of kms
        _key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, rustls::Error> {
        Ok(Arc::new(self.clone()))
    }
}

/// Errors that may occur when working with Google Cloud KMS for TLS authentication.
///
/// These errors cover the different stages of connecting to KMS, retrieving key information,
/// and using the key for TLS authentication.
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum KmsError {
    /// Authentication error when connecting to Google Cloud
    #[error("connect failed with error: {0}")]
    Connect(#[from] google_cloud_auth::error::Error),
    /// Error establishing a connection to the KMS service
    #[error("kms connect failed with error: {0}")]
    KmsConnect(google_cloud_gax::conn::Error),
    /// Error retrieving crypto key information from KMS
    #[error("kms get crypto key failed with error: {0}")]
    GetCryptoKey(google_cloud_gax::grpc::Status),
    /// Error retrieving crypto key version information from KMS
    #[error("kms get crypto key version failed with error: {0}")]
    GetCryptoKeyVersion(google_cloud_gax::grpc::Status),
    /// Error retrieving the public key from KMS
    #[error("could not get public key due to error: {0:?}")]
    GetPublicKey(google_cloud_gax::grpc::Status),
    /// Error parsing the PEM-encoded public key
    #[error("could not parse pem value due to error: {0}")]
    PemParse(#[from] rustls::pki_types::pem::Error),
    /// The key in KMS is not configured for asymmetric signing
    #[error("key purpose is not asymmetric sign, purpose is: {0:?}")]
    UnexpectedKeyPurpose(CryptoKeyPurpose),
    /// The key algorithm is not supported by rustls
    #[error("usupported scheme of kms {0}")]
    UnsupportedScheme(String),
}

/// Configuration for connecting to Google Cloud KMS and identifying a specific key.
///
/// This struct encapsulates all the information needed to locate a specific key version
/// in Google Cloud KMS.
/// It follows Google's resource naming hierarchy:
/// `projects/{project_id}/locations/{location}/keyRings/{keyring}/cryptoKeys/{key}/cryptoKeyVersions/{version}`
///
/// # Examples
///
/// ```
/// use rustls_gcp_kms::KmsConfig;
///
/// // Create a configuration for a key in the "global" location
/// let config = KmsConfig::new(
///     "my-project-id",
///     "global",
///     "my-keyring",
///     "my-signing-key",
///     "1"  // Version number
/// );
///
/// // Create a configuration for a key in a specific region
/// let regional_config = KmsConfig::new(
///     "my-project-id",
///     "us-central1",
///     "production-keyring",
///     "api-signing-key",
///     "3"  // Version number
/// );
/// ```
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KmsConfig {
    /// Google Cloud project ID
    pub project_id: String,
    /// Location where the key is stored (e.g., "global", "us-central1")
    pub location: String,
    /// Name of the key ring containing the key
    pub keyring: String,
    /// Name of the crypto key
    pub cryptokey: String,
    /// Version of the crypto key to use
    pub cryptokey_version: String,
    crypto_key_name: String,
    crypto_key_version_name: String,
}

impl KmsConfig {
    /// Creates a new KMS configuration with the specified parameters.
    ///
    /// # Arguments
    ///
    /// * `project_id` - Google Cloud project ID
    /// * `locationd` - Location where the key is stored (e.g., "global", "us-central1")
    /// * `keyring` - Name of the key ring containing the key
    /// * `cryptokey` - Name of the crypto key
    /// * `cryptokey_version` - Version of the crypto key to use
    ///
    /// # Returns
    ///
    /// A new `KmsConfig` instance.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustls_gcp_kms::KmsConfig;
    ///
    /// let config = KmsConfig::new(
    ///     "my-project-id",
    ///     "global",
    ///     "my-keyring",
    ///     "my-signing-key",
    ///     "1"
    /// );
    /// ```
    pub fn new<P, L, KR, CK, CV>(
        project_id: P,
        location_id: L,
        keyring_id: KR,
        cryptokey_id: CK,
        cryptokey_version: CV,
    ) -> Self
    where
        P: Into<String>,
        L: Into<String>,
        KR: Into<String>,
        CK: Into<String>,
        CV: Into<String>,
    {
        let project_id = project_id.into();
        let location = location_id.into();
        let keyring = keyring_id.into();
        let cryptokey = cryptokey_id.into();
        let cryptokey_version = cryptokey_version.into();
        let crypto_key_name = format!(
            "projects/{project_id}/locations/{location}/keyRings/{keyring}/cryptoKeys/{cryptokey}"
        );
        let crypto_key_version_name =
            format!("{crypto_key_name}/cryptoKeyVersions/{cryptokey_version}");

        Self {
            project_id,
            location,
            keyring,
            cryptokey,
            cryptokey_version,
            crypto_key_name,
            crypto_key_version_name,
        }
    }
}

impl KmsConfig {
    /// Validates that all required KMS configuration fields have been set.
    ///
    /// This function checks that none of the essential KMS configuration fields
    /// are empty, which would cause authentication failures when interacting
    /// with the Google Cloud KMS service.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if all required fields are non-empty
    /// - `Err(String)` containing a comma-separated list of validation errors
    ///   if any required fields are empty
    pub fn validate(&self) -> Result<(), String> {
        let mut errors = Vec::new();

        if self.project_id.is_empty() {
            errors.push("project_id should be set");
        }

        if self.location.is_empty() {
            errors.push("location should be set");
        }

        if self.keyring.is_empty() {
            errors.push("keyring should be set");
        }

        if self.cryptokey.is_empty() {
            errors.push("cryptokey should be set");
        }

        if self.cryptokey_version.is_empty() {
            errors.push("cryptokey_version should be set");
        }

        if errors.is_empty() {
            return Ok(());
        }

        Err(errors.join(","))
    }
}

/// Creates a `CryptoProvider` that uses Google Cloud KMS for TLS client authentication.
///
/// This function connects to Google Cloud KMS, retrieves information about the specified key,
/// and creates a rustls `CryptoProvider` that will use the KMS key for TLS client authentication.
/// The private key never leaves the secure KMS environment.
///
/// # Arguments
///
/// * `kms_config` - Configuration for connecting to Google Cloud KMS and identifying the key
///
/// # Returns
///
/// * `Result<CryptoProvider, KmsError>` - A rustls `CryptoProvider` configured to use KMS for signing,
///   or an error if initialization fails
///
/// # Examples
///
/// ```rust
///  use std::sync::Arc;
///  use google_cloud_kms::client::{Client, ClientConfig};
///  use rustls::pki_types::CertificateDer;
///  use rustls::RootCertStore;
///  use rustls_gcp_kms::{dummy_key, provider, KmsConfig};
///
///  async fn send_request() -> Result<(), Box<dyn std::error::Error>> {
///      // Configure KMS
///      let kms_config = KmsConfig::new(
///          "my-project-id",
///          "global",
///          "my-keyring",
///          "my-signing-key",
///          "1",
///      );
///
///      let client_config = ClientConfig::default()
///          .with_auth()
///          .await?;
///
///      let client = Client::new(client_config)
///          .await
///          .unwrap();
///
///      // Create the crypto provider with KMS
///      let crypto_provider = provider(client, kms_config).await?;
///
///      // Load your client certificate
///      let cert = std::fs::read("path/to/client.crt")?;
///      let cert = CertificateDer::from_slice(&cert).into_owned();
///
///      let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(crypto_provider))
///          .with_safe_default_protocol_versions()
///          .unwrap()
///          .with_root_certificates(RootCertStore::empty())
///          .with_client_auth_cert(vec![cert], dummy_key());
///
///      // Configure reqwest with KMS-backed TLS
///      let client = reqwest::Client::builder()
///          .use_rustls_tls()
///          .use_preconfigured_tls(client_config)
///          .build()?;
///
///      // Make a request with client certificate authentication
///      let response = client
///          .get("https://api.example.com/secure-endpoint")
///          .send()
///          .await?;
///
///      println!("Response: {}", response.status());
///
///      Ok(())
///  }
/// ```
pub async fn provider(client: Client, kms_config: KmsConfig) -> Result<CryptoProvider, KmsError> {
    let kms_signer = KmsSigner::connect(client, kms_config).await?;
    let kms_signer = Box::new(kms_signer);

    // Safety: This is a deliberate memory leak, as we need the key provider to have static lifetime
    // The provider will be valid for the lifetime of the application
    let key_provider: &'static dyn KeyProvider = Box::leak(kms_signer);

    let ring_provider = rustls::crypto::ring::default_provider();

    let provider = CryptoProvider {
        cipher_suites: ring_provider.cipher_suites,
        kx_groups: ring_provider.kx_groups,
        signature_verification_algorithms: ring_provider.signature_verification_algorithms,
        secure_random: ring_provider.secure_random,
        key_provider,
    };

    Ok(provider)
}

/// Maps a Google Cloud KMS algorithm to a rustls signature scheme
#[inline]
fn map_to_rustls_scheme(algorithm: &CryptoKeyVersionAlgorithm) -> Option<SignatureScheme> {
    match algorithm {
        CryptoKeyVersionAlgorithm::RsaSignPkcs12048Sha256
        | CryptoKeyVersionAlgorithm::RsaSignPkcs13072Sha256
        | CryptoKeyVersionAlgorithm::RsaSignPkcs14096Sha256 => {
            Some(SignatureScheme::RSA_PKCS1_SHA256)
        }
        CryptoKeyVersionAlgorithm::RsaSignPkcs14096Sha512 => {
            Some(SignatureScheme::RSA_PKCS1_SHA512)
        }
        CryptoKeyVersionAlgorithm::RsaSignPss2048Sha256
        | CryptoKeyVersionAlgorithm::RsaSignPss3072Sha256
        | CryptoKeyVersionAlgorithm::RsaSignPss4096Sha256 => Some(SignatureScheme::RSA_PSS_SHA256),
        CryptoKeyVersionAlgorithm::RsaSignPss4096Sha512 => Some(SignatureScheme::RSA_PSS_SHA512),
        CryptoKeyVersionAlgorithm::EcSignP256Sha256 => Some(SignatureScheme::ECDSA_NISTP256_SHA256),
        CryptoKeyVersionAlgorithm::EcSignP384Sha384 => Some(SignatureScheme::ECDSA_NISTP384_SHA384),
        CryptoKeyVersionAlgorithm::EcSignEd25519 => Some(SignatureScheme::ED25519),
        _ => None,
    }
}

/// Maps a Google Cloud KMS algorithm to a rustls signature algorithm
#[inline]
fn map_to_rustls_algorithm(algorithm: &CryptoKeyVersionAlgorithm) -> Option<SignatureAlgorithm> {
    match algorithm {
        CryptoKeyVersionAlgorithm::RsaSignPkcs12048Sha256
        | CryptoKeyVersionAlgorithm::RsaSignPkcs13072Sha256
        | CryptoKeyVersionAlgorithm::RsaSignPkcs14096Sha256
        | CryptoKeyVersionAlgorithm::RsaSignPkcs14096Sha512
        | CryptoKeyVersionAlgorithm::RsaSignPss2048Sha256
        | CryptoKeyVersionAlgorithm::RsaSignPss3072Sha256
        | CryptoKeyVersionAlgorithm::RsaSignPss4096Sha256
        | CryptoKeyVersionAlgorithm::RsaSignPss4096Sha512
        | CryptoKeyVersionAlgorithm::RsaSignRawPkcs12048
        | CryptoKeyVersionAlgorithm::RsaSignRawPkcs13072
        | CryptoKeyVersionAlgorithm::RsaSignRawPkcs14096 => Some(SignatureAlgorithm::RSA),
        CryptoKeyVersionAlgorithm::EcSignP256Sha256
        | CryptoKeyVersionAlgorithm::EcSignP384Sha384
        | CryptoKeyVersionAlgorithm::EcSignSecp256k1Sha256 => Some(SignatureAlgorithm::ECDSA),
        CryptoKeyVersionAlgorithm::EcSignEd25519 => Some(SignatureAlgorithm::ED25519),
        _ => None,
    }
}

/// Determines if a Google Cloud KMS algorithm is FIPS 140-2/140-3 approved
#[inline]
fn is_fips_approved(algorithm: &CryptoKeyVersionAlgorithm) -> bool {
    matches!(
        algorithm,
        CryptoKeyVersionAlgorithm::RsaSignPkcs12048Sha256
            | CryptoKeyVersionAlgorithm::RsaSignPkcs13072Sha256
            | CryptoKeyVersionAlgorithm::RsaSignPkcs14096Sha256
            | CryptoKeyVersionAlgorithm::RsaSignPkcs14096Sha512
            | CryptoKeyVersionAlgorithm::EcSignP256Sha256
            | CryptoKeyVersionAlgorithm::EcSignP384Sha384
    )
}

/// Creates a dummy private key for use in TLS configurations where a private key is required,
/// but the actual signing operations will be delegated to KMS.
///
/// This function returns a PKCS#8 formatted private key container with empty data.
/// The key data is not a valid cryptographic key and should never be used for actual
/// cryptographic operations.
///
/// # Returns
///
/// A `PrivateKeyDer<'static>` containing a dummy PKCS#8 key with a static lifetime.
#[must_use]
pub fn dummy_key() -> PrivateKeyDer<'static> {
    let bytes = vec![0_u8; 32];
    PrivateKeyDer::Pkcs8(bytes.into())
}
