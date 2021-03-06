blindsign
=====

A rust library for computing and verifying blind signatures as part of the multi
step blind signature scheme described in the paper [Blind Signature Scheme Based on Elliptic Curve Cryptography](http://pdfs.semanticscholar.org/e58a/1713858a9e18abfc05de244e.pdf).

### About

Blind signatures allow for a requester to have a message signed without the
signer knowing the content of the message. Additionally, although the signer
and anyone with the signer's public key can authenticate the signature on the
message, the signer cannot link the unblinded signature on the unblinded message
to the blind signature on the blinded message.

The unlinkability of blind signatures to unblinded signatures, coupled with the
ability to authenticate unblinded signatures on unblinded messages, makes blind
signature schemes the go to algorithms for things such as anonymous E-cash,
anonymous membership set constrained voting, and revocable anonymity.

### Documentation

[blindsign documentation](https://docs.rs/blindsign) gives detailed instructions
on how to make use of the various components provided by this library.

### Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
blindsign = "0.0.4"
```

And this to your crate root:

```rust
extern crate blindsign;
```

A complete sequence of using the protocol, with both client and server side
steps represented linearly.

```rust
use sha3::Sha3_512;

use blindsign::{
    keypair::BlindKeypair,
    signature::{UnblindedSigData, WiredUnblindedSigData},
    request::BlindRequest,
    session::BlindSession,
    Error, Result,
};

// Generates a new keypair. The private key is used for creating blind
// signatures on the blinded message, and the public key is used for
// authenticating the unblinded signature on the unblinded message.
let keypair = BlindKeypair::generate().unwrap();

// Initiates a new blind session (bs) on the signer side, the first step of
// which is generating of the value R' (rp).
let (rp, bs) = BlindSession::new().unwrap();

// Initiates a new blind request on the requester side, which is input R' and
// generates e' (ep).
let (ep, br) = BlindRequest::new::<Sha3_512>(&rp).unwrap();

// Signs the e' value, which is essentially the blinded message hash. Produces
// S' (sp), which is the blind signature.
let sp = bs.sign_ep(&ep, keypair.private()).unwrap();

// Forms a new unblinded signed message object on the requester side, when
// provided with the blind signature previously generated by the signer
// side.
let unblinded_signed_msg = br.gen_signed_msg(&sp).unwrap();

// A demonstration of converting the unblinded signed message between
// internal representation and wired format for transmission over the
// network.
let wired = WiredUnblindedSigData::from(unblinded_signed_msg);
let sig = wired.to_internal_format().unwrap();

// A demonstration of authenticating the blind signature
assert!(sig.authenticate(keypair.public()));
```

### License

* This implementation is licensed under MIT
