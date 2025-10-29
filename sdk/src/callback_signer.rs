// Copyright 2024 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

#![deny(missing_docs)]

//! The `callback_signer` module provides a way to obtain a [`Signer`] or [`AsyncSigner`]
//! using a callback and public signing certificates.

use async_trait::async_trait;

use crate::{crypto::raw_signature::SigningAlg, AsyncSigner, Error, Result, Signer};

/// Defines a callback function interface for standard signing a [`CallbackSigner`].
///
/// The callback should return a signature for the given data.
/// The callback should return an error if the data cannot be signed.
pub type CallbackFunc =
    dyn Fn(*const (), &[u8]) -> std::result::Result<Vec<u8>, Error> + Send + Sync;

/// Defines a signer that uses a callback to sign data.
///
/// The private key should only be known by the callback.
pub struct CallbackSigner {
    /// An opaque context for the signer, used to store any necessary state.
    pub context: *const (),

    /// The callback to use to sign data.
    pub signing_callback: Box<CallbackFunc>,

    /// The signing algorithm to use.
    pub alg: SigningAlg,

    /// The public certificates to use in PEM format.
    pub certs: Vec<u8>,

    /// A max size to reserve for the signature.
    pub reserve_size: usize,

    /// The optional URL of a Time Stamping Authority.
    pub tsa_url: Option<String>,

    /// The callback to use to timestamp data.
    pub tsa_callback: Option<Box<CallbackFunc>>,
    
    /// The callback to use to sign COSE data.
    pub direct_cose_handling: bool,
}

unsafe impl Send for CallbackSigner {}
unsafe impl Sync for CallbackSigner {}

impl CallbackSigner {
    /// Create a new callback signer.
    pub fn new<F, T>(callback: F, alg: SigningAlg, certs: T) -> Self
    where
        F: Fn(*const (), &[u8]) -> std::result::Result<Vec<u8>, Error> + Send + Sync + 'static,
        T: Into<Vec<u8>>,
    {
        let certs = certs.into();
        let reserve_size = 10000 + certs.len();

        Self::with_reserved_size(callback, alg, certs, reserve_size)
    }
    
    /// Create a new callback signer.
    pub fn with_reserved_size<F, T>(callback: F, alg: SigningAlg, certs: T, reserve_size: usize) -> Self
    where
        F: Fn(*const (), &[u8]) -> std::result::Result<Vec<u8>, Error> + Send + Sync + 'static,
        T: Into<Vec<u8>>,
    {
        let certs = certs.into();
        Self {
            context: std::ptr::null(),
            signing_callback: Box::new(callback),
            alg,
            certs,
            reserve_size,
            ..Default::default()
        }
    }

    /// Set a time stamping authority URL to call when signing.
    pub fn set_tsa_url<S: Into<String>>(mut self, url: S) -> Self {
        self.tsa_url = Some(url.into());
        self
    }
    
    /// Sets the optional callback for performing C2PA Timestamping.
    /// 
    /// The TSA URL will be used if this is not set.
    pub fn set_tsa_callback<F>(mut self, tsa_callback: F) -> Self
    where
        F: Fn(*const (), &[u8]) -> std::result::Result<Vec<u8>, Error> + Send + Sync + 'static,
    {
        self.tsa_callback = Some(Box::new(tsa_callback));
        self
    }

    /// Set a context value for the signer.
    ///
    /// This can be used to store any necessary state for the callback.
    /// Safety: The context must be valid for the lifetime of the signer.
    /// There is no Rust memory management for the context since it may also come from FFI.
    pub fn set_context(mut self, context: *const ()) -> Self {
        self.context = context;
        self
    }
    
    /// Sets whether the signer will handle COSE structures directly.
    pub fn set_direct_cose_handling(mut self, direct: bool) -> Self {
        self.direct_cose_handling = direct;
        self
    }

    /// Sign data using an Ed25519 private key.
    /// This static function is provided for testing with [`CallbackSigner`].
    /// For a released product the private key should be stored securely.
    /// The signing should be done in a secure environment.
    /// The private key should not be exposed to the client.
    /// Example: (only for testing)
    /// ```
    /// use c2pa::{CallbackSigner, SigningAlg};
    ///
    /// const CERTS: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pub");
    /// const PRIVATE_KEY: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pem");
    ///
    /// let ed_signer =
    ///     |_context: *const _, data: &[u8]| CallbackSigner::ed25519_sign(data, PRIVATE_KEY);
    /// let signer = CallbackSigner::new(ed_signer, SigningAlg::Ed25519, CERTS);
    /// ```
    pub fn ed25519_sign(data: &[u8], private_key: &[u8]) -> Result<Vec<u8>> {
        use ed25519_dalek::{Signature, Signer, SigningKey};
        use pem::parse;

        // Parse the PEM data to get the private key
        let pem = parse(private_key).map_err(|e| Error::OtherError(Box::new(e)))?;

        // For Ed25519, the key is 32 bytes long, so we skip the first 16 bytes of the PEM data
        let key_bytes = pem.contents().get(16..).ok_or(Error::InvalidSigningKey)?;
        let signing_key =
            SigningKey::try_from(key_bytes).map_err(|e| Error::OtherError(Box::new(e)))?;

        // Sign the data
        let signature: Signature = signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }
}

// This default is only intended for struct completion, do not use on its own.
impl Default for CallbackSigner {
    fn default() -> Self {
        Self {
            context: std::ptr::null(),
            signing_callback: Box::new(|_, _| Err(Error::UnsupportedType)),
            alg: SigningAlg::Es256,
            certs: Vec::new(),
            reserve_size: 10000,
            tsa_url: None,
            tsa_callback: None,
            direct_cose_handling: false,
        }
    }
}

impl Signer for CallbackSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        (self.signing_callback)(self.context, data)
    }

    fn alg(&self) -> SigningAlg {
        self.alg
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        let pems = pem::parse_many(&self.certs).map_err(|e| Error::OtherError(Box::new(e)))?;
        Ok(pems.into_iter().map(|p| p.into_contents()).collect())
    }

    fn reserve_size(&self) -> usize {
        self.reserve_size
    }
    
    fn timestamp(&self, data: &[u8]) -> Option<Result<Vec<u8>>> {
        if let Some(callback) = &self.tsa_callback {
            let result = (callback)(self.context, data);
            match &result {
                Ok(timestamp_response) =>
                {
                    if timestamp_response.is_empty()
                    {
                        None
                    } else
                    {
                        Some(result)
                    }
                }
                _ => Some(result)
            }
            
        } else {
            None
        }
    }

    fn time_authority_url(&self) -> Option<String> {
        self.tsa_url.clone()
    }
    
    fn direct_cose_handling(&self) -> bool {
        self.direct_cose_handling
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl AsyncSigner for CallbackSigner {
    async fn sign(&self, data: Vec<u8>) -> Result<Vec<u8>> {
        (self.signing_callback)(self.context, &data)
    }

    fn alg(&self) -> SigningAlg {
        self.alg
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        let pems = pem::parse_many(&self.certs).map_err(|e| Error::OtherError(Box::new(e)))?;
        Ok(pems.into_iter().map(|p| p.into_contents()).collect())
    }

    fn reserve_size(&self) -> usize {
        self.reserve_size
    }
    
    async fn timestamp(&self, data: &[u8]) -> Option<Result<Vec<u8>>> {
        if let Some(callback) = &self.tsa_callback {
            Some((callback)(self.context, data))
        } else {
            None
        }
    }

    fn time_authority_url(&self) -> Option<String> {
        self.tsa_url.clone()
    }

    #[cfg(target_arch = "wasm32")]
    async fn send_timestamp_request(&self, _message: &[u8]) -> Option<Result<Vec<u8>>> {
        None
    }
    
    fn direct_cose_handling(&self) -> bool {
        self.direct_cose_handling
    }
}
