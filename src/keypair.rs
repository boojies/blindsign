//! Generate and manage the ECC keys
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use rand::OsRng;
use Error::{WiredRistrettoPointMalformed, WiredScalarMalformed};

/// An elliptic curve cryptography keypair. The private key (Xs) is used by the
/// signer for creating the blind signature on the blinded hash(msg||R), and the
/// public key (Qs) is usable by anyone for verifying the authenticity of the
/// unblinded signature on the unblinded hash(msg||R).
#[derive(Copy, Clone, Debug)]
pub struct BlindKeypair {
    private: Scalar,
    public: RistrettoPoint,
}

impl BlindKeypair {
    /// Generates an ECC keypair for use with the blind signature protocol.
    /// The private key is a random scalar, and the public key is an elliptic
    /// curve point equal to this scalar multiplied by the Ristretto generator
    /// point. This is based on the wikipedia description of ECDSA key
    /// generation seeing as the whitepaper doesn't specify key generation.
    ///
    /// # Returns
    ///
    /// * Ok(BlindKeypair) on success.
    ///
    /// * Err(::Error) on error, which can only be the failure to initiate the
    /// internal RNG.
    ///
    /// # Mathematics
    ///
    /// * Xs = a randomly generated scalar
    /// * Qs = Xs * P
    /// * P = The ECC generator point
    pub fn generate() -> ::Result<Self> {
        let mut rng = OsRng::new()?;
        let private = Scalar::random(&mut rng);
        let public = private * RISTRETTO_BASEPOINT_POINT;
        Ok(BlindKeypair { private, public })
    }

    /// Creates a new BlindKeypair object from the provided private and public
    /// key components (in wired form).
    ///
    /// # Returns
    ///
    /// * Ok(BlindKeypair) on success.
    ///
    /// * Err(::Error) on failure, which can indicate either that the private
    /// or public key inputs were malformed.
    pub fn from_wired(private: [u8; 32], public: [u8; 32]) -> ::Result<Self> {
        Ok(BlindKeypair {
            private: Scalar::from_canonical_bytes(private).ok_or(WiredScalarMalformed)?,
            public: CompressedRistretto(public)
                .decompress()
                .ok_or(WiredRistrettoPointMalformed)?,
        })
    }

    /// Returns the private key in Scalar form
    pub fn private(&self) -> Scalar {
        self.private
    }

    /// Returns the public key in RistrettoPoint form
    pub fn public(&self) -> RistrettoPoint {
        self.public
    }

    /// Returns the public key in wired form
    pub fn public_wired(&self) -> [u8; 32] {
        self.public.compress().to_bytes()
    }

    /// Returns the private key in wired form
    pub fn private_wired(&self) -> [u8; 32] {
        self.private.to_bytes()
    }
}
