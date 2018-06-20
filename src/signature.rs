//! Manage the blindly signed message
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use Error::{WiredRistrettoPointMalformed, WiredScalarMalformed};
use subtle::ConstantTimeEq;
use typenum::U64;
use digest::Digest;
use request;

/// The data required for authenticating the unblinded signature,
///
/// * 'e' is H(R || msg), the unblinded version of e' upon which the blind
/// signature S' is created.
///
/// * 'S' is the unblinded version of blind signature S'. S' is a blind
/// signature on the blind messag||R hash value e', S is the unblinded
// signature on the unblinded R||message hash value e.
///
/// * 'R' is the unblinded version of protocol initiation value R', which is
/// the original Ristretto Point sent to the requester in response to
/// protocol initiation.
///
/// All of these components are required to authenticate a blind signature
/// created by the signer. The value S can be authenticated against the
/// coupled R and e value when provided with the public ECC key that is
/// associated with the private ECC key the blind signature S' was ostensibly
/// created with on e'.
///
/// The actual message content is not included in this structure, though the
/// input message can be validated against the signed e value of this struct as
/// e = H(R || msg).
#[derive(Copy, Clone, Debug)]
pub struct UnblindedSigData {
    // The H(R || msg) value, which is the unblinded version of e',
    // which is the value that is blindly signed producing S' from which
    // S on E is derived.
    e: Scalar,
    // The unblinded signature S, valid on E, derived from S' valid on e'.
    s: Scalar,
    // The unblinded R value
    r: RistrettoPoint,
}

impl UnblindedSigData {
    /// Creates a new UnblindedSigData object, which consists of values e, S, and
    /// R.
    ///
    /// # Arguments
    ///
    /// * 'e' - H(msg||R), the unblinded variant of e'.
    /// * 's' - The unblinded signature (S' unblinded)
    /// * 'r' - The unblinded R' value received from the signer in step one
    /// of the protocol
    pub fn new(e: Scalar, s: Scalar, r: RistrettoPoint) -> Self {
        Self { e, s, r }
    }

    /// Authenticates that the signature value S on e is valid with R and the
    /// provided public key (ie: that S' was created on e' with the private key
    /// associated with the provided public key, in the session that was
    /// initiated with the R' value).
    ///
    /// # Arguments
    ///
    /// 'pub_key' - The public key associated with the private key that
    /// ostensibly created the signature value S' on e', to authenticate that
    /// S is authentic on e (given R).
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
    /// # Notes
    ///
    /// * (SP == e*Qs + R) is **not** done in constant time, however neither half
    /// of this equation contains any secret information so this should be fine.
    ///
    /// * This method only verifies that the signature S on e is valid given
    /// R and pub_key, it does **not** verify that e is correlated to any given
    /// msg value.
    pub fn authenticate(&self, pub_key: RistrettoPoint) -> bool {
        self.s * RISTRETTO_BASEPOINT_POINT == self.e * pub_key + self.r
    }

    /// The same as authenticate but with a constant time comparison.
    pub fn const_authenticate(&self, pub_key: RistrettoPoint) -> bool {
        (self.s * RISTRETTO_BASEPOINT_POINT)
            .ct_eq( &(self.e * pub_key + self.r) )
            .unwrap_u8() == 1
    }

    /// The same as authenticate, but rather than using the internal e value
    /// compute the e value e = H(R||Msg) from the provided msg value. This
    /// function is useful if the actual value of the signed message is
    /// important.
    ///
    /// # Note
    ///
    /// The internal e value is not used at all, and is not guaranteed to match
    /// H(R||msg) for the provided msg.
    pub fn msg_authenticate<H, M>(&self, pub_key: RistrettoPoint, msg: M) -> bool
    where
        H: Digest<OutputSize = U64> + Default,
        M: AsRef<[u8]>,
    {
        let e = request::generate_e::<H>(self.r, msg.as_ref());
        self.s * RISTRETTO_BASEPOINT_POINT == e * pub_key + self.r
    }

    /// The same as const_authenticate, but rather than using the internal e value
    /// compute the e value e = H(R||Msg) from the provided msg value. This
    /// function is useful if the actual value of the signed message is
    /// important.
    ///
    /// # Note
    ///
    /// The internal e value is not used at all, and is not guaranteed to match
    /// H(R||msg) for the provided msg.
    pub fn msg_const_authenticate<H, M>(&self, pub_key: RistrettoPoint, msg: M) -> bool
    where
        H: Digest<OutputSize = U64> + Default,
        M: AsRef<[u8]>,
    {
        let e = request::generate_e::<H>(self.r, msg.as_ref());
        (self.s * RISTRETTO_BASEPOINT_POINT)
            .ct_eq( &(e * pub_key + self.r) )
            .unwrap_u8() == 1
    }
}



/// The UnblindedSigData in wired form capable of being sent over the network.
/// The wired form consists of e || S || R, with each component consisting of
/// 32 bytes.
pub struct WiredUnblindedSigData(pub [u8; 96]);

impl From<UnblindedSigData> for WiredUnblindedSigData {
    fn from(usd: UnblindedSigData) -> Self {
        let mut arr = [0; 96];
        arr[0..32].copy_from_slice(usd.e.as_bytes());
        arr[32..64].copy_from_slice(usd.s.as_bytes());
        arr[64..96].copy_from_slice(usd.r.compress().as_bytes());
        WiredUnblindedSigData(arr)
    }
}

impl WiredUnblindedSigData {
    /// Converts WiredUnblindedSigData into UnblindedSigData.
    ///
    /// # Returns
    ///
    /// * Ok(UnblindedSigData) on success
    ///
    /// * Err(::Error) on failure, which could be due to any component of the
    /// internal [u8; 96] being malformed.
    pub fn to_internal_format(&self) -> ::Result<UnblindedSigData> {
        let mut e_arr = [0; 32];
        let mut s_arr = [0; 32];
        let mut r_arr = [0; 32];
        e_arr.copy_from_slice(&self.0[0..32]);
        s_arr.copy_from_slice(&self.0[32..64]);
        r_arr.copy_from_slice(&self.0[64..96]);
        Ok(UnblindedSigData {
            e: Scalar::from_canonical_bytes(e_arr).ok_or(WiredScalarMalformed)?,
            s: Scalar::from_canonical_bytes(s_arr).ok_or(WiredScalarMalformed)?,
            r: CompressedRistretto(r_arr)
                .decompress()
                .ok_or(WiredRistrettoPointMalformed)?,
        })
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
