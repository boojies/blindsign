//! An implementation of ECC based blind signatures.
//!
//! # Based On Paper
//!
//! Mathematical syntax from this documentation is taken from the paper
//! [Blind Signature Scheme Based on Elliptic Curve Cryptography](pdfs.semanticscholar.org/e58a/1713858a9e18abfc05de244e.pdf).
//!
//! # Note
//!
//! This is a sans-IO implementation, meaning that no network IO for requesting
//! or granting the initiation of the protocol is provided by this crate.

// Regular imported crates
extern crate curve25519_dalek;
extern crate digest;
extern crate failure;
extern crate rand;
extern crate typenum;
extern crate subtle;

// Imported crates with used macros
#[macro_use]
extern crate failure_derive;

// The public interface
pub mod keypair;
pub mod request;
pub mod session;
pub mod signature;

/// The Result type used
pub type Result<T> = ::std::result::Result<T, Error>;

/// The Error types
#[derive(Fail, Debug)]
pub enum Error {
    #[fail(display = "failed to initialize the RNG")]
    RngInitFailed,
    #[fail(display = "failed to convert wired scalar to scalar")]
    WiredScalarMalformed,
    #[fail(display = "failed to convert wired ristretto point to ristretto point")]
    WiredRistrettoPointMalformed,
}

impl From<rand::Error> for Error {
    fn from(_: rand::Error) -> Self {
        Error::RngInitFailed
    }
}
