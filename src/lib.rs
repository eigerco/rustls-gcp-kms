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

use core::fmt::Debug;
use std::sync::Arc;

use futures::executor::block_on;
use google_cloud_kms::client::{Client, ClientConfig};
use google_cloud_kms::grpc::kms::v1::crypto_key::CryptoKeyPurpose;
use google_cloud_kms::grpc::kms::v1::crypto_key_version::CryptoKeyVersionAlgorithm;
use google_cloud_kms::grpc::kms::v1::{
    AsymmetricSignRequest, Digest, GetCryptoKeyRequest, GetCryptoKeyVersionRequest,
    GetPublicKeyRequest, digest,
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
    key_version_name: String,
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
                    name: kms_cfg.crypto_key_name(),
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
                    name: kms_cfg.crypto_key_version(),
                },
                None,
            )
            .await
            .map_err(KmsError::GetCryptoKeyVersion)?;

        let public_key_pem = client
            .get_public_key(
                GetPublicKeyRequest {
                    name: kms_cfg.crypto_key_version(),
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
            key_version_name: kms_cfg.crypto_key_version(),
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
                use sha2::{Digest as _, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(message);
                let hash = hasher.finalize();

                Digest {
                    digest: Some(digest::Digest::Sha256(hash.to_vec())),
                }
            }
            SignatureScheme::ECDSA_NISTP384_SHA384 => {
                use sha2::{Digest as _, Sha384};
                let mut hasher = Sha384::new();
                hasher.update(message);
                let hash = hasher.finalize();

                Digest {
                    digest: Some(digest::Digest::Sha384(hash.to_vec())),
                }
            }
            SignatureScheme::RSA_PKCS1_SHA512 | SignatureScheme::RSA_PSS_SHA512 => {
                use sha2::{Digest as _, Sha512};
                let mut hasher = Sha512::new();
                hasher.update(message);
                let hash = hasher.finalize();

                Digest {
                    digest: Some(digest::Digest::Sha512(hash.to_vec())),
                }
            }
            _ => {
                return Err(rustls::Error::General(
                    "Unsupported signature scheme".into(),
                ));
            }
        };

        let req = AsymmetricSignRequest {
            name: self.key_version_name.clone(),
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
/// in Google Cloud KMS. It follows Google's resource naming hierarchy:
/// `projects/{project_id}/locations/{location}/keyRings/{keyring}/cryptoKeys/{key}/cryptoKeyVersions/{version}`
///
/// # Examples
///
/// ```
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
#[non_exhaustive]
#[derive(Debug)]
pub struct KmsConfig {
    /// Google Cloud project ID
    pub project_id: String,
    /// Location where the key is stored (e.g., "global", "us-central1")
    pub location_id: String,
    /// Name of the key ring containing the key
    pub keyring_id: String,
    /// Name of the crypto key
    pub cryptokey_id: String,
    /// Version of the crypto key to use
    pub cryptokey_version: String,
}

impl KmsConfig {
    /// Creates a new KMS configuration with the specified parameters.
    ///
    /// # Arguments
    ///
    /// * `project_id` - Google Cloud project ID
    /// * `location_id` - Location where the key is stored (e.g., "global", "us-central1")
    /// * `keyring_id` - Name of the key ring containing the key
    /// * `cryptokey_id` - Name of the crypto key
    /// * `cryptokey_version` - Version of the crypto key to use
    ///
    /// # Returns
    ///
    /// A new `KmsConfig` instance.
    ///
    /// # Examples
    ///
    /// ```
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
        Self {
            project_id: project_id.into(),
            location_id: location_id.into(),
            keyring_id: keyring_id.into(),
            cryptokey_id: cryptokey_id.into(),
            cryptokey_version: cryptokey_version.into(),
        }
    }

    fn crypto_key_name(&self) -> String {
        let project_id = &self.project_id;
        let location_id = &self.location_id;
        let keyring_id = &self.keyring_id;
        let crypto_key_id = &self.cryptokey_id;

        format!(
            "projects/{project_id}/locations/{location_id}/keyRings/{keyring_id}/cryptoKeys/{crypto_key_id}"
        )
    }

    fn crypto_key_version(&self) -> String {
        let crypto_key_name = self.crypto_key_name();
        let cryptokey_version = &self.cryptokey_version;

        format!("{crypto_key_name}/cryptoKeyVersions/{cryptokey_version}")
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
/// use rustls_kms::{KmsConfig, provider};
/// use reqwest::Certificate;
/// use std::sync::Arc;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     // Configure KMS
///     let kms_config = KmsConfig::new(
///         "my-project-id",
///         "global",
///         "my-keyring",
///         "my-signing-key",
///         "1"
///     );
///
///     let client_config = ClientConfig::default()
///        .with_auth()
///        .await?;
///
///     let client = Client::new(client_config)
///         .await
///         .unwrap();
///
///     // Create the crypto provider with KMS
///     let crypto_provider = provider(client, kms_config).await?;
///
///     // Load your client certificate
///     let cert_pem = std::fs::read("path/to/client.crt")?;
///     let cert = Certificate::from_pem(&cert_pem)?;
///
///     // Create a dummy private key (not actually used)
///     let dummy_key = rustls::pki_types::PrivateKeyDer::from(vec![0u8; 32]);
///
///     // Configure reqwest with KMS-backed TLS
///     let client = reqwest::Client::builder()
///         .use_preconfigured_tls(
///             rustls::ClientConfig::builder()
///                 .with_provider(Arc::new(crypto_provider))
///                 .with_client_auth_cert(
///                     vec![cert.clone().into()],
///                     dummy_key
///                 )?
///         )
///         .build()?;
///
///     // Make a request with client certificate authentication
///     let response = client.get("https://api.example.com/secure-endpoint")
///         .send()
///         .await?;
///
///     println!("Response: {}", response.status());
///
///     Ok(())
/// }
/// ```
pub async fn provider(client: Client,kms_config: KmsConfig) -> Result<CryptoProvider, KmsError> {
    let kms_signer = KmsSigner::connect(client, kms_config).await?;
    let kms_signer = Box::new(kms_signer);

    // Safety: This is a deliberate memory leak, as we need the key provider to have static lifetime
    // The provider will be valid for the lifetime of the application
    let key_provider: &'static dyn KeyProvider = Box::leak(kms_signer);

    let ring_provider = rustls::crypto::ring::default_provider();

    let provider = CryptoProvider {
        cipher_suites: ring_provider.cipher_suites.clone(),
        kx_groups: ring_provider.kx_groups.clone(),
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
