//! Signer side of the protocol
//!
//! # Note
//! This **does not** include **any** networking code to actually accept the
//! request for protocol initiation. Also, the request for protocol initiation
//! is neither defined nor implemented by this crate.

use rand::{
    OsRng,
};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    scalar::Scalar,
};
use ::Error::{
    WiredScalarMalformed,
};



/// For managing the signer side response to incoming requests for blind
/// signatures. How the actual requests come in is orthogonal to this crate.
pub struct BlindSession {
    k: Scalar
}


impl BlindSession {
    /// Initiate a new signer side session to create a blind signature for
    /// a requester.
    ///
    /// # Returns
    ///
    /// * Ok( ([u8; 32], BlindSession) ) on success, with the [u8; 32] being the
    /// value R' for sending to the requester, and the BlindSession struct
    /// supporting the sign_ep() method for completing the protocol (upon the
    /// receipt of the E' response from the requester).
    ///
    /// * Err(::Error) variant on failure, which is only due to the
    /// failure to initiate the internal random number generator.
    ///
    /// # Mathematics
    ///
    /// * R' = kP
    /// * k = A randomly generated scalar by the signer
    /// * P = An ECC Generator Point
    pub fn new() -> ::Result<([u8; 32], Self)> {
        let mut rng = OsRng::new()?;
        let k       = Scalar::random(&mut rng);
        let rp      = (k * RISTRETTO_BASEPOINT_POINT).compress().to_bytes();
        Ok( (rp, Self { k }) )
    }

    /// Consumes the session and returns the generated blind signature.
    ///
    /// # Arguments
    ///
    /// * 'ep' - A reference to a 32 byte scalar represented as a [u8; 32]. This
    /// scalar is received from the requester in some manner.
    ///
    /// * 'xs' - The private key componenet of the associated BlindKeypair
    /// component, in internal Scalar form. This is used for creating signatures
    /// which can be authenticated with the associated public key.
    ///
    /// # Returns
    ///
    /// * Ok([u8; 32]) on success, representing the completed blind signature
    /// value S'.
    ///
    /// * Err(errors::BlindErrors) variant on error. Only errors if the
    /// requester provided a malformed scalar value ep.
    ///
    /// # Mathematics
    ///
    /// * S' = Xs*e' + k
    /// * e' = requester calculated e' value, received by signer
    /// * k  = randomly generated number by the signer
    pub fn sign_ep(self, ep: &[u8; 32], xs: Scalar) -> ::Result<[u8; 32]> {
        Ok( (xs * Scalar::from_canonical_bytes(*ep)
                        .ok_or(WiredScalarMalformed)? + self.k).to_bytes() )
    }
}
