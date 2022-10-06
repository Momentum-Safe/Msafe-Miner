extern crate ed25519_dalek;
extern crate rand;

use ed25519_dalek::Digest;
use ed25519_dalek::Keypair;
use ed25519_dalek::SecretKey;
use ed25519_dalek::PublicKey;
use sha3::digest::Output;
use sha3::Sha3_256;
use std::thread;

use curve25519_dalek::edwards::CompressedEdwardsY;

use hex_literal::hex;
use rand::rngs::StdRng;
use rand::SeedableRng;

fn address(public_key_bytes: &[u8]) -> Output<Sha3_256> {
    let hasher = &mut Sha3_256::new();
    hasher.update(public_key_bytes);
    hasher.update(b"\x00");
    hasher.finalize_reset()
}

fn address_pubkey(addr: Output<Sha3_256>, nonce: u32) -> bool {
    let h = addr.as_slice();
    let n128:u128 = nonce.into();
    let l = n128.to_le_bytes();
    let ret = [&h[..16], &l[..]].concat();
    //PublicKey::from_bytes(&ret).is_ok()
    native_public_key_validate(<[u8; 32]>::try_from(ret).unwrap())
}



fn calculate2() {
    let mut csprng = StdRng::from_entropy();
    let mut max_max_gap = 0u32;
    //let bytes = hex!("fad2b32339a0fd4b7b49762913ebc372edb3c0e1837767c6ca23314b1b927059");
    //let sk: SecretKey = SecretKey::from_bytes(bytes.as_slice()).unwrap();
    //let pk: PublicKey = (&sk).into();
    //let keypair: Keypair = Keypair { secret: (sk), public: (pk) };
    loop {
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let public_key_bytes: &[u8] = keypair.public.as_bytes();
        let addr = address(public_key_bytes);
        let mut nonce = 0u32;
        let mut gap_start = 0u32;
        let mut max_gap = 0u32;
        let mut mode = 0; // 1 in gap 0: in valid
        let mut valid_count = 0u32;
        loop {
            let pubkey_valid = address_pubkey(addr, nonce);
            if pubkey_valid {
                valid_count = valid_count + 1;
            }
            if mode == 0 && pubkey_valid == false {
                mode = 1;
                gap_start = nonce;
            } else if mode == 1 && pubkey_valid {
                mode = 0;
                let gap = nonce - gap_start;
                if gap > max_gap || valid_count % 100000 == 0 {
                    if gap > max_gap {
                        max_gap = gap;
                    }
                    println!("gap(cur/max):{}/{} nonce(valid/all):{}/{}", gap, max_gap, valid_count, nonce)
                }
            }
            nonce = nonce + 1;
            if max_gap > 25 {
                break;
            }
        }
        if max_gap > max_max_gap {
            max_max_gap = max_gap;
            println!(
                "prikey: {:02x?} max_nonce: {}",
                keypair.secret.as_bytes(),
                max_gap
            );
        }
    }
}

fn calculate() {
    let mut csprng = StdRng::from_entropy();
    let mut max_nonce = 0u32;
    loop {
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let public_key_bytes: &[u8] = keypair.public.as_bytes();
        let addr = address(public_key_bytes);
        let mut nonce = 0u32;
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

fn native_public_key_validate(key_bytes_slice: [u8; 32]) -> bool {
    let point = CompressedEdwardsY(key_bytes_slice).decompress();
    if point.is_some() {
        return !point.unwrap().is_small_order();
    };
    false
}

fn main() {
    let pk_bytes = hex!("0200000000000000000000000000000000000000000000000000000000000000");
    let is_pk = PublicKey::from_bytes(&pk_bytes[..]).is_ok();
    let is_pk_valid = native_public_key_validate(pk_bytes);
    println!("test:{} {}", is_pk, is_pk_valid);

    let mut handles = vec![];
    for i in 0..1 {
        println!("thread:{}", i);
        let handle = thread::spawn(|| {
            calculate2();
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}
