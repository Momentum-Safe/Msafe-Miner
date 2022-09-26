extern crate ed25519_dalek;
extern crate rand;

use ed25519_dalek::Digest;
use ed25519_dalek::Keypair;
use ed25519_dalek::PublicKey;
use sha3::digest::Output;
use sha3::Sha3_256;
use std::thread;

use rand::{SeedableRng};
use rand::rngs::StdRng;

fn address(public_key_bytes: &[u8]) -> Output<Sha3_256> {
    let hasher = &mut Sha3_256::new();
    hasher.update(public_key_bytes);
    hasher.update(b"\x00");
    hasher.finalize_reset()
}

fn address_pubkey(addr: Output<Sha3_256>, nonce: u8) -> bool {
    let high16 = &mut addr.as_slice();
    let h = &high16[0..16];
    let mut low16 = [0; 16];
    low16[0] = nonce;
    let l = &low16[..];
    let ret = [&h[..], &l[..]].concat();
    PublicKey::from_bytes(&ret).is_ok()
}

fn calculate() {
    let mut csprng = StdRng::from_entropy();
    let mut max_nonce = 0u8;
    loop {
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let public_key_bytes: &[u8] = keypair.public.as_bytes();
        let addr = address(public_key_bytes);
        let mut nonce = 0u8;
        loop {
            let pubkey_valid = address_pubkey(addr, nonce);
            if nonce > 200 || !pubkey_valid {
                break;
            }
            nonce = nonce + 1;
        }
        if nonce > max_nonce {
            max_nonce = nonce;
            println!(
                "prikey: {:02x?} max_nonce: {}",
                keypair.secret.as_bytes(),
                nonce
            );
        }
        if nonce > 100 {
            break;
        }
    }
}

fn main() {
    let mut handles = vec![];
     for i in 0..4 {
        println!("thread:{}", i);
        let handle = thread::spawn(||{
            calculate();
         });
         handles.push(handle);
     }

     for handle in handles {
        handle.join().unwrap();
     }
}
