//! Manage the blindly signed message
use curve25519_dalek::scalar::{
    Scalar
};
use curve25519_dalek::{
    ristretto::{
        RistrettoPoint,
        CompressedRistretto
    },
    constants::RISTRETTO_BASEPOINT_POINT
};
use ::Error::{
    WiredScalarMalformed,
    WiredRistrettoPointMalformed
};


/// The resultant blindly signed message of protocol completion. The signature
/// member S can be authenticated on members e and R, when provided with the
/// public key associated with the private key that ostensibly created the blind
/// signature S' on e' in the session initiated with R'. The actual message is
/// not included with this structure, but rather e = H(msg||R), upon which the
/// unblinded signature S is made.
#[derive(Copy, Clone, Debug)]
pub struct BlindSignedMsg {
    // The H(msg || R) value.
    e: Scalar,
    // The unblinded signature
    s: Scalar,
    // The unblinded R value
    r: RistrettoPoint,
}

/// The BlindSignedMsg in wired form capable of being sent over the network.
/// The wired form consists of e || S || R, with each component consisting of
/// 32 bytes.
pub struct WiredBlindSignedMsg(pub [u8; 96]);

impl From<BlindSignedMsg> for WiredBlindSignedMsg {
    fn from(bsm: BlindSignedMsg) -> Self {
        let mut arr = [0; 96];
        arr[0..32].copy_from_slice(bsm.e.as_bytes());
        arr[32..64].copy_from_slice(bsm.s.as_bytes());
        arr[64..96].copy_from_slice(bsm.r.compress().as_bytes());
        WiredBlindSignedMsg(arr)
    }
}

impl WiredBlindSignedMsg {
    /// Converts WiredBlindSignedMsg into a BlindSignedMsg.
    ///
    /// # Returns
    ///
    /// * Ok(BlindSignedMsg) on success
    /// * Err(::Error) on failure, which could be due to any component of the
    /// internal [u8; 96] being malformed.
    pub fn to_internal_format(&self) -> ::Result<BlindSignedMsg> {
        let mut e_arr = [0; 32];
        let mut s_arr = [0; 32];
        let mut r_arr = [0; 32];
        e_arr.copy_from_slice(&self.0[0..32]);
        s_arr.copy_from_slice(&self.0[32..64]);
        r_arr.copy_from_slice(&self.0[64..96]);
        Ok( BlindSignedMsg {
            e: Scalar::from_canonical_bytes(e_arr).ok_or(WiredScalarMalformed)?,
            s: Scalar::from_canonical_bytes(s_arr).ok_or(WiredScalarMalformed)?,
            r: CompressedRistretto(r_arr).decompress().ok_or(WiredRistrettoPointMalformed)?,
        } )
    }

    /// Returns a reference to the internal [u8; 96]
    pub fn as_bytes(&self) -> &[u8; 96] {
        &self.0
    }

   /// Returns a copy of the internal [u8; 96]
    pub fn to_bytes(&self) -> [u8; 96] {
        self.0
    }
}

impl BlindSignedMsg {
    /// Creates a new BlindSignedMsg object, which consists of values e, S, and
    /// R.
    ///
    /// # Arguments
    ///
    /// * 'e' - H(msg||R), the unblinded variant of e'.
    /// * 's' - The unblinded signature (S' unblinded)
    /// * 'r' - The unblinded R' value received from the signer in step one
    /// of the protocol
    pub fn new(e: Scalar, s: Scalar, r: RistrettoPoint) -> Self {
        Self{ e, s, r }
    }

    /// Authenticates that the signature value S on e is valid with R and the
    /// provided public key (ie: that S' was created on e' with the private key
    /// associated with the provided public key, in the session that was
    /// initiated with the R' value).
    ///
    /// # Arguments
    ///
    /// 'pub_key' - The public key with which this BlindSignedMsg was ostensibly
    /// signed.
    ///
    /// # Returns
    ///
    /// * True to indicate that the values S is authentic on e and R with the
    /// provided pub_key, or in other words that the signature is valid.
    ///
    /// * False to indicate that the value S on e and R isn't authentic, or in
    /// other words that the signature is invalid.
    ///
    /// # Mathematics
    ///
    /// * SP == e*Qs + R
    /// * S = Unblinded signature value
    /// * P = ECC generator point
    /// * Qs = Public key of the signer
    /// * e = H(msg || R)
    /// * R = Unblinded version of the R' value from the signer
    ///
    /// # Note
    ///
    /// (SP == e*Qs + R) is **not** done in constant time, however neither half
    /// of this equation contains any secret information so this should be fine.
    pub fn authenticate(&self, pub_key: RistrettoPoint) -> bool {
        self.s * RISTRETTO_BASEPOINT_POINT == self.e * pub_key + self.r
    }
}
