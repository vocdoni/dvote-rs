// extern crate stderrlog;
extern crate eth_checksum;
extern crate num_bigint;
use sha3::{Digest, Keccak256};
extern crate secp256k1;
// extern crate za_prover;

use poseidon_rs::Poseidon;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use bip39::{Language, Mnemonic, MnemonicType, Seed};
// use ethkey::prelude::Address;
pub use ethsign::{PublicKey, SecretKey};

use num_bigint::BigInt;
// use secp256k1::{Message, Secp256k1, Signature};
use tiny_hderive::bip32::ExtendedPrivKey;

// use za_prover::groth16;
// use za_prover::groth16::helper;

const DEFAULT_HD_PATH: &str = "m/44'/60'/0'/0/0";
const ETHEREUM_SIGNATURE_PREFIX: &str = "\x19Ethereum Signed Message:\n";

///////////////////////////////////////////////////////////////////////////////
// EXPORTED FUNCTIONS FUNCTIONS
///////////////////////////////////////////////////////////////////////////////

#[no_mangle]
pub extern "C" fn digest_string_claim(str_claim_ptr: *const c_char) -> *mut c_char {
    let str_claim = unsafe { CStr::from_ptr(str_claim_ptr) }
        .to_str()
        .expect("Invalid str_claim string");

    let hex_result = digest_string_claim_inner(str_claim);

    CString::new(hex_result).unwrap().into_raw()

    // NOTE: Caller must free() the resulting pointer
}

#[no_mangle]
pub extern "C" fn digest_hex_claim(hex_claim_ptr: *const c_char) -> *mut c_char {
    let hex_claim = unsafe { CStr::from_ptr(hex_claim_ptr) }
        .to_str()
        .expect("Invalid hex_claim string");

    let hex_result = digest_hex_claim_inner(hex_claim);

    CString::new(hex_result).unwrap().into_raw()

    // NOTE: Caller must free() the resulting pointer
}

#[no_mangle]
pub extern "C" fn generate_mnemonic(size: i32) -> *mut c_char {
    let hex_result = generate_mnemonic_inner(size);

    CString::new(hex_result).unwrap().into_raw()

    // NOTE: Caller must free() the resulting pointer
}

#[no_mangle]
pub extern "C" fn compute_private_key(
    mnemonic_ptr: *const c_char,
    hd_path_ptr: *const c_char,
) -> *mut c_char {
    let mnemonic = unsafe { CStr::from_ptr(mnemonic_ptr) }
        .to_str()
        .expect("Invalid mnemonic string");
    let hd_path = unsafe { CStr::from_ptr(hd_path_ptr) }
        .to_str()
        .expect("Invalid hd_path string");

    let hex_result = compute_private_key_inner(mnemonic, hd_path);

    CString::new(hex_result).unwrap().into_raw()

    // NOTE: Caller must free() the resulting pointer
}

#[no_mangle]
pub extern "C" fn compute_public_key(hex_private_key_ptr: *const c_char) -> *mut c_char {
    let hex_private_key = unsafe { CStr::from_ptr(hex_private_key_ptr) }
        .to_str()
        .expect("Invalid hex_private_key string");

    let hex_result = compute_public_key_inner(hex_private_key);

    CString::new(hex_result).unwrap().into_raw()

    // NOTE: Caller must free() the resulting pointer
}

#[no_mangle]
pub extern "C" fn compute_address(hex_private_key_ptr: *const c_char) -> *mut c_char {
    let hex_private_key = unsafe { CStr::from_ptr(hex_private_key_ptr) }
        .to_str()
        .expect("Invalid hex_private_key string");

    let hex_result = compute_address_inner(hex_private_key);

    CString::new(hex_result).unwrap().into_raw()

    // NOTE: Caller must free() the resulting pointer
}

#[no_mangle]
pub extern "C" fn sign_message(
    message_ptr: *const c_char,
    hex_private_key_ptr: *const c_char,
) -> *mut c_char {
    let message = unsafe { CStr::from_ptr(message_ptr) }
        .to_str()
        .expect("Invalid message string");
    let hex_private_key = unsafe { CStr::from_ptr(hex_private_key_ptr) }
        .to_str()
        .expect("Invalid hex_private_key string");

    let hex_result = sign_message_inner(message, hex_private_key);

    CString::new(hex_result).unwrap().into_raw()

    // NOTE: Caller must free() the resulting pointer
}

// #[no_mangle]
// pub extern "C" fn generate_zk_proof(
//     proving_key_path: *const c_char,
//     inputs: *const c_char,
// ) -> *mut c_char {
//     let proving_key_path = unsafe { CStr::from_ptr(proving_key_path) };
//     let proving_key_path = proving_key_path
//         .to_str()
//         .expect("Could not parse proving_key_path");

//     let inputs = unsafe { CStr::from_ptr(inputs) };
//     let inputs = inputs.to_str().expect("Could not parse the inputs");

//     match groth16::flatten_json("main", &inputs)
//         .and_then(|inputs| helper::prove(&proving_key_path, inputs))
//     {
//         Ok(proof) => CString::new(proof).unwrap().into_raw(),
//         Err(err) => CString::new(format!("ERROR: {:?}", err))
//             .unwrap()
//             .into_raw(),
//     }
//     // NOTE: Caller must free() the resulting pointer
// }

///////////////////////////////////////////////////////////////////////////////
// INTERNAL HANDLERS
///////////////////////////////////////////////////////////////////////////////

fn digest_string_claim_inner(claim: &str) -> String {
    // Convert into a byte array
    let claim_bytes = claim.as_bytes().to_vec();

    // Hash
    let poseidon = Poseidon::new();
    let hash = match poseidon.hash_bytes(claim_bytes) {
        Ok(v) => v,
        Err(reason) => {
            return format!("ERROR: {}", reason);
        }
    };

    let claim_bytes = pad_bigint_le(&hash);
    base64::encode(claim_bytes)
}

fn digest_hex_claim_inner(hex_claim: &str) -> String {
    // Decode hex into a byte array
    let hex_claim_clean: &str = if hex_claim.starts_with("0x") {
        &hex_claim[2..] // skip 0x
    } else {
        hex_claim
    };
    let claim_bytes = match hex::decode(hex_claim_clean) {
        Ok(v) => v,
        Err(err) => {
            return format!(
                "ERROR: The given claim ({}) is not a valid hex string - {}",
                hex_claim, err
            );
        }
    };

    // Hash
    let poseidon = Poseidon::new();
    let hash = match poseidon.hash_bytes(claim_bytes) {
        Ok(v) => v,
        Err(reason) => {
            return format!("ERROR: {}", reason);
        }
    };
    let claim_bytes = pad_bigint_le(&hash);
    base64::encode(claim_bytes)
}

fn generate_mnemonic_inner(size: i32) -> String {
    let mnemonic = match size {
        128 => Mnemonic::new(MnemonicType::Words12, Language::English),
        160 => Mnemonic::new(MnemonicType::Words15, Language::English),
        192 => Mnemonic::new(MnemonicType::Words18, Language::English),
        224 => Mnemonic::new(MnemonicType::Words21, Language::English),
        256 => Mnemonic::new(MnemonicType::Words24, Language::English),
        _ => return "ERROR: Invalid size".to_string(),
    };

    mnemonic.phrase().to_string()
}

fn compute_private_key_inner(phrase: &str, hd_path: &str) -> String {
    let hd_path = if hd_path == "" {
        DEFAULT_HD_PATH
    } else {
        hd_path
    };

    let mnemonic = Mnemonic::from_phrase(phrase, Language::English);

    match mnemonic {
        Err(_) => return "ERROR: Invalid mnemonic".to_string(),
        _ => {}
    }
    let mnemonic = mnemonic.unwrap();

    // get the HD wallet seed
    let seed = Seed::new(&mnemonic, "");
    let seed_bytes: &[u8] = seed.as_bytes();

    let secret_key_bytes = match ExtendedPrivKey::derive(seed_bytes, hd_path) {
        Ok(result) => result,
        Err(_) => return "ERROR: Invalid HD path".to_string(),
    };

    // Byte array of the secp256k1 secret key
    hex::encode(secret_key_bytes.secret())
}

fn compute_public_key_inner(hex_private_key: &str) -> String {
    // Decode hex into a byte array
    let hex_private_key_clean: &str = if hex_private_key.starts_with("0x") {
        &hex_private_key[2..] // skip 0x
    } else {
        hex_private_key
    };
    let private_key_bytes = match hex::decode(hex_private_key_clean) {
        Ok(v) => v,
        Err(err) => {
            return format!(
                "ERROR: The given private key ({}) is not a valid hex string - {}",
                hex_private_key, err
            );
        }
    };

    match SecretKey::from_raw(&private_key_bytes) {
        Ok(key) => {
            let pub_key = hex::encode(key.public().bytes().as_ref());
            format!("04{}", &pub_key)
        }
        Err(_) => return "ERROR: Cannot import the raw private key".to_string(),
    }

    // let secp = Secp256k1::new();
    // let secret_key = match SecretKey::from_slice(&private_key_bytes) {
    //     Ok(sk) => sk,
    //     Err(_) => return "ERROR: 32 bytes, within curve order".to_string(),
    // };
    // let pub_key = PublicKey::from_secret_key(&secp, &secret_key);
    // let pub_key_bytes = pub_key.serialize_uncompressed();

    // hex::encode(pub_key_bytes.as_ref())
}

fn compute_address_inner(hex_private_key: &str) -> String {
    // Decode hex into a byte array
    let hex_private_key_clean: &str = if hex_private_key.starts_with("0x") {
        &hex_private_key[2..] // skip 0x
    } else {
        hex_private_key
    };
    let private_key_bytes = match hex::decode(hex_private_key_clean) {
        Ok(v) => v,
        Err(err) => {
            return format!(
                "ERROR: The given private key ({}) is not a valid hex string - {}",
                hex_private_key, err
            );
        }
    };

    match SecretKey::from_raw(&private_key_bytes) {
        Ok(key) => {
            let hex_address = hex::encode(key.public().address().as_ref());
            eth_checksum::checksum(&hex_address)
        }
        Err(_) => return "ERROR: Cannot import the raw private key".to_string(),
    }
}

fn sign_message_inner(message: &str, hex_private_key: &str) -> String {
    // Decode hex into a byte array
    let hex_private_key_clean: &str = if hex_private_key.starts_with("0x") {
        &hex_private_key[2..] // skip 0x
    } else {
        hex_private_key
    };
    let private_key_bytes = match hex::decode(hex_private_key_clean) {
        Ok(v) => v,
        Err(err) => {
            return format!(
                "ERROR: The given private key ({}) is not a valid hex string - {}",
                hex_private_key, err
            );
        }
    };

    let secret_key = match SecretKey::from_raw(&private_key_bytes) {
        Ok(key) => key,
        Err(_) => return "ERROR: Cannot import the raw private key".to_string(),
    };

    let payload = pack_payload_to_sign(message);

    // hash the bytes
    let mut hasher = Keccak256::new();
    hasher.update(payload);
    let result = hasher.finalize();

    // sign the hash
    let signature = secret_key.sign(&result).unwrap();

    // Format R,S,V as a hex string
    let v: &[u8] = &[signature.v + 0x1b]; // NOTE: ChainID is not considered at this point
    let result_bytes = [&signature.r[..], &signature.s[..], &v[..]].concat();
    hex::encode(result_bytes)
}

fn pack_payload_to_sign(payload: &str) -> Vec<u8> {
    let prefix: String = format!("{}{}", ETHEREUM_SIGNATURE_PREFIX, payload.len());
    let prefix: &[u8] = prefix.as_bytes();
    let payload: &[u8] = payload.as_bytes();
    [prefix, payload].concat()
}

///////////////////////////////////////////////////////////////////////////////
// HELPERS
///////////////////////////////////////////////////////////////////////////////

fn pad_bigint_le(num: &BigInt) -> Vec<u8> {
    let mut claim_bytes = num.to_bytes_le().1;
    while claim_bytes.len() < 32 {
        claim_bytes.push(0);
    }
    claim_bytes
}

#[allow(dead_code)]
fn pad_bigint_be(num: &BigInt) -> Vec<u8> {
    let mut claim_bytes = num.to_bytes_be().1;
    while claim_bytes.len() < 32 {
        claim_bytes = [&[0], &claim_bytes[..]].concat();
    }
    claim_bytes
}

///////////////////////////////////////////////////////////////////////////////
// STRING FREE
///////////////////////////////////////////////////////////////////////////////

#[no_mangle]
pub extern "C" fn free_cstr(string: *mut c_char) {
    unsafe {
        if string.is_null() {
            return;
        }
        CString::from_raw(string)
    };
}

///////////////////////////////////////////////////////////////////////////////
// TESTS
///////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::{Sign, ToBigInt};

    // POSEIDON HASH

    #[test]
    fn should_hash_strings() {
        let str_claim = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
        let b64_hash = digest_string_claim_inner(str_claim);

        assert_eq!(b64_hash, "iV5141xlrW8I217IitUHtoDC/gd/LMsgcF0zpDfUaiM=");
    }

    #[test]
    fn should_hash_hex_claims() {
        let hex_claim = "0x045a126cbbd3c66b6d542d40d91085e3f2b5db3bbc8cda0d59615deb08784e4f833e0bb082194790143c3d01cedb4a9663cb8c7bdaaad839cb794dd309213fcf30";
        let b64_hash = digest_hex_claim_inner(hex_claim);
        assert_eq!(b64_hash, "nGOYvS4aqqUVAT9YjWcUzA89DlHPWaooNpBTStOaHRA=");

        let hex_claim = "0x049969c7741ade2e9f89f81d12080651038838e8089682158f3d892e57609b64e2137463c816e4d52f6688d490c35a0b8e524ac6d9722eed2616dbcaf676fc2578";
        let b64_hash = digest_hex_claim_inner(hex_claim);
        assert_eq!(b64_hash, "j7jJlnBN73ORKWbNbVCHG9WkoqSr+IEKDwjcsb6N4xw=");

        let hex_claim = "0x049622878da186a8a31f4dc03454dbbc62365060458db174618218b51d5014fa56c8ea772234341ae326ce278091c39e30c02fa1f04792035d79311fe3283f1380";
        let b64_hash = digest_hex_claim_inner(hex_claim);
        assert_eq!(b64_hash, "6CUGhnmKQchF6Ter05laVgQYcEWm0p2qlLzX24rk3Ck=");

        let hex_claim = "0x04e355263aa6cbc99d2fdd0898f5ed8630115ad54e9073c41a8aa0df6d75842d8b8309d0d26a95565996b17da48f8ddff704ebcd1d8a982dc5ba8be7458c677b17";
        let b64_hash = digest_hex_claim_inner(hex_claim);
        assert_eq!(b64_hash, "k0UwNtWW4UQifisXuoDiO/QGRZNNTY7giWK1Nx/hoSo=");

        let hex_claim = "0x04020d62c94296539224b885c6cdf79d0c2dd437471425be26bf62ab522949f83f3eed34528b0b9a7fbe96e50ca85471c894e1aa819bbf12ff78ad07ce8b4117b2";
        let b64_hash = digest_hex_claim_inner(hex_claim);
        assert_eq!(b64_hash, "5EhP0859lic41RIpIrnotv/BCR7v5nVcXsXkTXlbuhI=");

        let hex_claim = "0x046bd65449f336b888fc36c64708940da0d1c864a0ac46236f60b455841a4d15c9b815ed725093b3266aaca2f15210d14a1eadf34efeda3bd44a803fbf1590cfba";
        let b64_hash = digest_hex_claim_inner(hex_claim);
        assert_eq!(b64_hash, "oseI7fM8wWIYslDUOXJne7AOiK+IpFL3q8MTqiZHWw8=");

        let hex_claim = "0x0412cf2bd4a9613ad988f7f008a5297b8e8c98df8759a2ef9d3dfae63b3870cfbb78d35789745f82710da61a61a9c06c6f6166bf1d5ce73f9416e6b67713001aa2";
        let b64_hash = digest_hex_claim_inner(hex_claim);
        assert_eq!(b64_hash, "9Y3JcjUHZLGmENRQpnML/+TG2EbHWjU46h+LtT9sQi8=");

        let hex_claim = "0x04a2e6914db4a81ea9ec72e71b41cf88d4bc19ea54f29ae2beb3db8e4acf6531b5c163e58427831832b10fce899a030d12e82a398d4eeefe451c7e261fba973be4";
        let b64_hash = digest_hex_claim_inner(hex_claim);
        assert_eq!(b64_hash, "Llx5F6lP/hbU6ZTT10Q5PF+7o1VdylvrolT8vSHJMAA=");

        let hex_claim = "0x041508189a6f1737f50dd2c603c1ded8a83f97073d33cbb317e7409c1487b8351aa2b89455cda61ce8ed3ba3c130372870b187239b900da8948a53ca3e02db9aaf";
        let b64_hash = digest_hex_claim_inner(hex_claim);
        assert_eq!(b64_hash, "MyRpb4ZDTwtJNflc8ZbZdmKOf+fuZjUEZkgZMCmlKxw=");

        let hex_claim = "0x04f11597483032666b20ec51b27e1337577f63a5e1d5962575b555bf899380ae15482f031a297094b0c60980f3c4f1f7ad2346de5357ad82a6a3d4eef2bd1956c6";
        let b64_hash = digest_hex_claim_inner(hex_claim);
        assert_eq!(b64_hash, "ytwkzcBixiBMsblxEEPpiDFV6MCBG/IY+XUc6/+xIQ8=");

        let hex_claim = "0x044c01f3d0ef3d60652aa7c6489b2f10edcae1b04a10460ab2d5e4bd752eb0686cac7aa6057fd4c65606e8a4c33c0b519b1764229395cde2c8537ee01136ef0776";
        let b64_hash = digest_hex_claim_inner(hex_claim);
        assert_eq!(b64_hash, "VS5c2JQT3x++ltSQHqnCFIBHttdjU2Lk2RuCGkUhnQ8=");
    }

    #[test]
    fn should_return_32_byte_hashes() {
        let hex_claim = "0x04c94699a259ec27e1cf67fe46653f0dc2f38e6d32abb33b45fc9ffe793171a44b4ff5c9517c1be22f8a47915debcf1e512717fe33986f287e79d2f3099725f179";
        let b64_hash = digest_hex_claim_inner(hex_claim);
        assert_eq!(b64_hash, "uJM6qiWAIIej9CGonWlR0cU64wqtdlh+csikpC6wSgA=");
        let len = base64::decode(b64_hash)
            .expect("The hash is not a valid base64")
            .len();
        assert_eq!(len, 32);

        let hex_claim = "0x0424a71e7c24b38aaeeebbc334113045885bfae154071426e21c021ebc47a5a85a3a691a76d8253ce6e03bf4e8fe154c89b2d967765bb060e61360305d1b8df7c5";
        let b64_hash = digest_hex_claim_inner(hex_claim);
        assert_eq!(b64_hash, "9wxP7eLFnTk5VDsj9rXL63r7QPKTTjCkNhjZri1nEQA=");
        let len = base64::decode(b64_hash)
            .expect("The hash is not a valid base64")
            .len();
        assert_eq!(len, 32);

        let hex_claim = "0x04ff51151c6bd759d723af2d0571df5e794c28b204242f4b540b0d3449eab192cafd44b241c96b39fa7dd7ead2d2265a598a23cba0f54cb79b9829d355d74304a2";
        let b64_hash = digest_hex_claim_inner(hex_claim);
        assert_eq!(b64_hash, "iS7BUPgGpY/WAdWyZb0s1wE21tMz5ZWBc8LJ6jgqSwA=");
        let len = base64::decode(b64_hash)
            .expect("The hash is not a valid base64")
            .len();
        assert_eq!(len, 32);

        let hex_claim = "0x043f10ff1b295bf4d2f24c40c93cce04210ae812dd5ad1a06d5dafd9a2e18fa1247bdf36bef6a9e45e97d246cfb8a0ab25c406cf6fe7569b17e83fd6d33563003a";
        let b64_hash = digest_hex_claim_inner(hex_claim);
        assert_eq!(b64_hash, "CCxtK0qT7cTxCS7e4uONSHcPQdbQzBqrC3GQvFz4KwA=");
        let len = base64::decode(b64_hash)
            .expect("The hash is not a valid base64")
            .len();
        assert_eq!(len, 32);

        let hex_claim = "0x0409d240a33ca9c486c090135f06c5d801aceec6eaed94b8bef1c9763b6c39708819207786fe92b22c6661957e83923e24a5ba754755b181f82fdaed2ed3914453";
        let b64_hash = digest_hex_claim_inner(hex_claim);
        assert_eq!(b64_hash, "3/AaoqHPrz20tfLmhLz4ay5nrlKN5WiuvlDZkfZyfgA=");
        let len = base64::decode(b64_hash)
            .expect("The hash is not a valid base64")
            .len();
        assert_eq!(len, 32);

        let hex_claim = "0x04220da30ddd87fed1b65ef75706507f397138d8cac8917e118157124b7e1cf45b8a38ac8c8b65a6ed662d62b09d100e53abacbc27500bb9d0365f3d6d60a981fa";
        let b64_hash = digest_hex_claim_inner(hex_claim);
        assert_eq!(b64_hash, "YiEgjvg1VeCMrlWJkAuOQIgDX1fWtkHk9OBJy225UgA=");
        let len = base64::decode(b64_hash)
            .expect("The hash is not a valid base64")
            .len();
        assert_eq!(len, 32);

        let hex_claim = "0x04acdbbdba45841ddcc1c3cb2e8b696eae69ba9d57686bff0cd58e4033a08d9dc6c272a3577508cdb18bdb1c6fcc818538664bb6dc4cc32ee668198c7be044800c";
        let b64_hash = digest_hex_claim_inner(hex_claim);
        assert_eq!(b64_hash, "UPqwKZBMhq21uwgLWJUFMgCBMPzhseiziVaqN4EQvwA=");
        let len = base64::decode(b64_hash)
            .expect("The hash is not a valid base64")
            .len();
        assert_eq!(len, 32);
    }

    #[test]
    fn should_match_string_and_hex() {
        let str_claim = "Hello";
        let hex_claim = "48656c6c6f"; // Hello
        let b64_hash1 = digest_string_claim_inner(str_claim);
        let b64_hash2 = digest_hex_claim_inner(hex_claim);
        assert_eq!(b64_hash1, b64_hash2);

        let str_claim = "Hello UTF8 ©âëíòÚ ✨";
        let hex_claim = "48656c6c6f205554463820c2a9c3a2c3abc3adc3b2c39a20e29ca8"; // Hello UTF8 ©âëíòÚ ✨
        let b64_hash1 = digest_string_claim_inner(str_claim);
        let b64_hash2 = digest_hex_claim_inner(hex_claim);
        assert_eq!(b64_hash1, b64_hash2);
    }

    #[test]
    fn should_hash_hex_with_0x() {
        let b64_hash1 = digest_hex_claim_inner(
            "48656c6c6f48656c6c6f48656c6c6f48656c6c6f48656c6c6f48656c6c6f48656c6c6f",
        );
        let b64_hash2 = digest_hex_claim_inner(
            "0x48656c6c6f48656c6c6f48656c6c6f48656c6c6f48656c6c6f48656c6c6f48656c6c6f",
        );
        assert_eq!(b64_hash1, b64_hash2);

        let b64_hash1 = digest_hex_claim_inner(
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        );
        let b64_hash2 = digest_hex_claim_inner(
            "0x12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        );
        assert_eq!(b64_hash1, b64_hash2);

        let b64_hash1 = digest_hex_claim_inner(
            "01234567890123456789012345678901234567890123456789012345678901234567890123456789",
        );
        let b64_hash2 = digest_hex_claim_inner(
            "0x01234567890123456789012345678901234567890123456789012345678901234567890123456789",
        );
        assert_eq!(b64_hash1, b64_hash2);

        let b64_hash1 = digest_hex_claim_inner(
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        let b64_hash2 = digest_hex_claim_inner(
            "0x0000000000000000000000000000000000000000000000000000000000000000",
        );
        assert_eq!(b64_hash1, b64_hash2);

        let b64_hash1 = digest_hex_claim_inner(
            "8888888888888888888888888888888888888888888888888888888888888888",
        );
        let b64_hash2 = digest_hex_claim_inner(
            "0x8888888888888888888888888888888888888888888888888888888888888888",
        );
        assert_eq!(b64_hash1, b64_hash2);

        let b64_hash1 = digest_hex_claim_inner(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        );
        let b64_hash2 = digest_hex_claim_inner(
            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        );
        assert_eq!(b64_hash1, b64_hash2);

        let b64_hash1 = digest_hex_claim_inner("1234567890123456789012345678901234567890");
        let b64_hash2 = digest_hex_claim_inner("0x1234567890123456789012345678901234567890");
        assert_eq!(b64_hash1, b64_hash2);
    }

    #[test]
    fn should_pad_bigints_in_le() {
        let bigint = -1125.to_bigint().unwrap();
        assert_eq!(bigint.to_bytes_le(), (Sign::Minus, vec![101, 4]));

        let num_bytes = pad_bigint_le(&bigint);

        assert_eq!(num_bytes.len(), 32);
        assert_eq!(
            num_bytes,
            vec![
                101, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0
            ]
        );
    }

    #[test]
    fn should_pad_bigints_in_be() {
        let bigint = -1125.to_bigint().unwrap();
        assert_eq!(bigint.to_bytes_be(), (Sign::Minus, vec![4, 101]));

        let num_bytes = pad_bigint_be(&bigint);

        assert_eq!(num_bytes.len(), 32);
        assert_eq!(
            num_bytes,
            vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 4, 101
            ]
        );
    }

    #[test]
    fn bigint_padding_should_match() {
        let bigint = -1125.to_bigint().unwrap();
        assert_eq!(bigint.to_bytes_be(), (Sign::Minus, vec![4, 101]));

        let num_bytes_le = pad_bigint_le(&bigint);
        let mut num_bytes_be = pad_bigint_be(&bigint);

        assert_eq!(num_bytes_le.len(), 32);
        assert_eq!(num_bytes_be.len(), 32);
        num_bytes_be.reverse();
        assert_eq!(num_bytes_be, num_bytes_le);
    }

    // ECDSA / SECP256K1

    #[test]
    fn should_generate_random_mnemonics() {
        let mnemonic = generate_mnemonic_inner(128);
        assert_eq!(
            mnemonic.split_whitespace().count(),
            12,
            "Should contain 12 words"
        );

        for _ in 0..20 {
            assert_ne!(
                mnemonic,
                generate_mnemonic_inner(128),
                "Mnemonics should be random"
            );
        }

        // All sizes

        assert_eq!(
            generate_mnemonic_inner(160).split_whitespace().count(),
            15,
            "Should contain 15 words"
        );
        assert_eq!(
            generate_mnemonic_inner(192).split_whitespace().count(),
            18,
            "Should contain 18 words"
        );
        assert_eq!(
            generate_mnemonic_inner(224).split_whitespace().count(),
            21,
            "Should contain 21 words"
        );
        assert_eq!(
            generate_mnemonic_inner(256).split_whitespace().count(),
            24,
            "Should contain 24 words"
        );
    }

    #[test]
    fn should_compute_private_public_keys_and_addresses() {
        let priv_key = compute_private_key_inner(
            "coral imitate swim axis note super success public poem frown verify then",
            "",
        );
        assert_eq!(
            priv_key,
            "975a999c921f77c1812833d903799cdb7780b07809eb67070ac2598f45e9fb3f",
        );
        let pub_key = compute_public_key_inner(&priv_key);
        assert_eq!(pub_key,
        "046fbd249af1bf365abd8d0cfc390c87ff32a997746c53dceab3794e2913d4cb26e055c8177faab65b404ea24754d8f56ef5df909a39d99ee0e7ca291a11556b37");
        let address = compute_address_inner(&priv_key);
        assert_eq!(address, "0x6AAa00b7c22021F96B09BB52cb9135F0cB865c5D");

        let priv_key = compute_private_key_inner(
            "almost slush girl resource piece meadow cable fancy jar barely mother exhibit",
            "",
        );
        assert_eq!(
            priv_key,
            "32fa4a65b9cb770235a8f0af497536035a459a98179c2c667972be279fbd1a1a",
        );
        let pub_key = compute_public_key_inner(&priv_key);
        assert_eq!(pub_key,
        "0425eb0aac23fe343e7ac5c8a792898a4f1d55b3150f3609cde6b7ada2dff029a89430669dd7f39ffe72eb9b8335fef52fd70863d123ba0015e90cbf68b58385eb");

        let address = compute_address_inner(&priv_key);
        assert_eq!(address, "0xf0492A8Dc9c84E6c5b66e10D0eC1A46A96FF74D3");

        let priv_key = compute_private_key_inner(
            "civil very heart sock decade library moment permit retreat unhappy clown infant",
            "",
        );
        assert_eq!(
            priv_key,
            "1b3711c03353ecbbf7b686127e30d6a37a296ed797793498ef24c04504ca5048",
        );
        let pub_key = compute_public_key_inner(&priv_key);
        assert_eq!(pub_key,
        "04ae5f2ecb63c4b9c71e1b396c8206720c02bddceb01da7c9f590aa028f110c035fa54045f6361fa0c6b5914a33e0d6f2f435818f0268ec8196062d1521ea8451a");
        let address = compute_address_inner(&priv_key);
        assert_eq!(address, "0x9612bD0deB9129536267d154D672a7f1281eb468");

        let priv_key = compute_private_key_inner(
            "life noble news naive know verb leaf parade brisk chuckle midnight play",
            "",
        );
        assert_eq!(
            priv_key,
            "3c21df88530a25979494c4c7789334ba5dd1c8c73d23c4077a7f223c2274830f",
        );
        let pub_key = compute_public_key_inner(&priv_key);
        assert_eq!(pub_key,
        "041d792012043464ac528d15e3309d4e55b41205380dfe14a01e2be95a30d0ac80a313dbc6881d5f034c38d091cb27a0301b42faca820274e6a84d2268f8c4f556");
        let address = compute_address_inner(&priv_key);
        assert_eq!(address, "0x34E3b8a0299dc7Dc53de09ce8361b41A7D888EC4");
    }

    #[test]
    fn should_derive_keys_using_hd_path() {
        let mnemonic =
            "civil very heart sock decade library moment permit retreat unhappy clown infant";
        // index 0
        let priv_key = compute_private_key_inner(mnemonic, "m/44'/60'/0'/0/0");
        assert_eq!(
            priv_key,
            "1b3711c03353ecbbf7b686127e30d6a37a296ed797793498ef24c04504ca5048",
        );
        let pub_key = compute_public_key_inner(&priv_key);
        assert_eq!(pub_key,
        "04ae5f2ecb63c4b9c71e1b396c8206720c02bddceb01da7c9f590aa028f110c035fa54045f6361fa0c6b5914a33e0d6f2f435818f0268ec8196062d1521ea8451a");
        let address = compute_address_inner(&priv_key);
        assert_eq!(address, "0x9612bD0deB9129536267d154D672a7f1281eb468");

        // index 1
        let priv_key = compute_private_key_inner(mnemonic, "m/44'/60'/0'/0/1");
        assert_eq!(
            priv_key,
            "2b8642b869998d77243669463b68058299260349eba6c893d892d4b74eae95d4",
        );
        let pub_key = compute_public_key_inner(&priv_key);
        assert_eq!(pub_key,
        "04d8b869ceb2d90c2ab0b0eecd2f4215f42cb40a82e7de854ca14e85a1a84e00a45e1c37334666acb08b62b19f42c18524d9d5952fb43054363350820f5190f17d");
        let address = compute_address_inner(&priv_key);
        assert_eq!(address, "0x67b5615fDC5c65Afce9B97bD217804f1dB04bC1b");

        // index 2
        let priv_key = compute_private_key_inner(mnemonic, "m/44'/60'/0'/0/2");
        assert_eq!(
            priv_key,
            "562870cd36727fdca458ada4c2a34e0170b7b4cc4d3dc3b60cba3582bf8c3167",
        );
        let pub_key = compute_public_key_inner(&priv_key);
        assert_eq!(pub_key,
        "04887f399e99ce751f82f73a9a88ab015db74b40f707534f54a807fa6e10982cbfaffe93414466b347b83cd43bc0d1a147443576446b49d0e3d6db24f37fe02567");
        let address = compute_address_inner(&priv_key);
        assert_eq!(address, "0x0887fb27273A36b2A641841Bf9b47470d5C0E420");
    }

    #[test]
    fn should_sign_string_messages() {
        let mnemonic =
            "poverty castle step need baby chair measure leader dress print cruise baby avoid fee sock shoulder rate opinion";
        let mut message = "hello";

        let priv_key = compute_private_key_inner(mnemonic, "");
        assert_eq!(
            priv_key,
            "e8088b11cdf79dab6919103720a424e33ffb68d7f272432e2798f1eaf346967c",
        );
        let mut signature = sign_message_inner(message, &priv_key);

        assert_eq!(signature,
        "9d06b4f31641aba791bb79dfb211c1141c4b3e346f230c05256c657c5c10916229a8f4cee40bfdbe0d90061d60e712ec5ec0c59cb90321814848ec2f6f7763181b");

        message = "àèìòù";
        signature = sign_message_inner(message, &priv_key);
        assert_eq!(signature,
        "2cbf9ae0de3df7e975b68b4cf67e14a0b49a1f8ed5d54c6c13d2ff936585036232fb53846fd49331bf8832fcd7e4517c3f07c951b95d5e0e102e572bbbadda811c");
    }
}
