// Regular imported crates
extern crate curve25519_dalek;
extern crate sha3;
extern crate rand;
extern crate ecc_blind;

#[cfg(test)]
mod integration_test {
    use sha3::Sha3_512;

    use ecc_blind::{
        Error,
        Result,
        keypair::{
            BlindKeypair
        },
        message::{
            BlindSignedMsg,
            WiredBlindSignedMsg,
        },
        request::{
            BlindRequest
        },
        session::{
            BlindSession,
        },
    };

    use rand::OsRng;

    #[test]
    fn session_with_random_msg() {
        let keypair = BlindKeypair::generate().unwrap();
        let (rp, bs) = BlindSession::new().unwrap();
        let (ep, br) = BlindRequest::new::<Sha3_512>(&rp).unwrap();
        let sp = bs.sign_ep(&ep, keypair.private()).unwrap();
        let blind_signed_msg = br.gen_signed_msg(&sp).unwrap();
        let wired = WiredBlindSignedMsg::from(blind_signed_msg);
        println!("\nS: {:?},\nE: {:?}, \nR: {:?}", &wired.0[0..32], &wired.0[32..64], &wired.0[64..96]);
        let sig = wired.to_internal_format().unwrap();
        assert!(sig.authenticate(keypair.public()));
    }

    #[test]
    fn session_with_specific_msg() {
        let keypair = BlindKeypair::generate().unwrap();
        let (rp, bs) = BlindSession::new().unwrap();
        let (ep, br) = BlindRequest::new_specific_msg::<Sha3_512, &str>(&rp, "specific").unwrap();
        let sp = bs.sign_ep(&ep, keypair.private()).unwrap();
        let blind_signed_msg = br.gen_signed_msg(&sp).unwrap();
        let wired = WiredBlindSignedMsg::from(blind_signed_msg);
        println!("\nS: {:?},\nE: {:?}, \nR: {:?}", &wired.0[0..32], &wired.0[32..64], &wired.0[64..96]);
        let sig = wired.to_internal_format().unwrap();
        assert!(sig.authenticate(keypair.public()));
    }
}
