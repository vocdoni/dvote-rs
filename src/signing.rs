extern crate num_bigint;

use super::util::decode_hex_string;
use ethsign::SecretKey;
use sha3::{Digest, Keccak256};

pub const ETHEREUM_SIGNATURE_PREFIX: &str = "\x19Ethereum Signed Message:\n";

/// Computes the signature of message using hex_private_key and returns it as a hex-encoded string
pub fn sign_message(message: &str, hex_private_key: &str) -> Result<String, String> {
    let private_key_bytes = decode_hex_string(hex_private_key)?;

    let secret_key = SecretKey::from_raw(&private_key_bytes)
        .map_err(|_| "Cannot import the raw private key".to_string())?;

    let payload_hash = hash_signature_message(message);

    // sign the hash
    let signature = secret_key.sign(&payload_hash).unwrap();

    // Format R,S,V as a hex string
    let v: &[u8] = &[signature.v + 0x1b]; // NOTE: ChainID is not considered at this point
    let signature_bytes = [&signature.r[..], &signature.s[..], &v[..]].concat();
    Ok(hex::encode(signature_bytes))
}

/// Returns the public key that signed the given message and produced the given hex_signature
pub fn recover_signer(hex_signature: &str, message: &str) -> Result<String, String> {
    let signature = decode_hex_string(hex_signature)?;

    if signature.len() != 65 {
        return Err("Signature length should be 65 bytes".to_string());
    }

    let mut r: [u8; 32] = [0; 32];
    r.copy_from_slice(&signature[0..32]);
    let mut s: [u8; 32] = [0; 32];
    s.copy_from_slice(&signature[32..64]);
    if signature[64] < 0x1b {
        return Err("V should be either 0x1b or 0x1c".to_string());
    }
    let v: u8 = signature[64] - 0x1b;

    let signature = ethsign::Signature { r, s, v };
    let payload_hash = hash_signature_message(message);

    let public_key = signature
        .recover(&payload_hash)
        .map_err(|err| format!("Cannot recover the public key: {}", err))?;

    let public_key = hex::encode(public_key.bytes().as_ref());
    Ok(format!("04{}", public_key))
}

/// Checks if the given message was signed by hex_public_key by verifying hex_signature
pub fn is_valid(hex_signature: &str, message: &str, hex_public_key: &str) -> bool {
    // skip 0x
    let hex_public_key: &str = if hex_public_key.starts_with("0x") {
        &hex_public_key[2..]
    } else {
        hex_public_key
    };

    match recover_signer(hex_signature, message) {
        Ok(recovered_public_key) => hex_public_key == recovered_public_key,
        Err(_) => false,
    }
}

///////////////////////////////////////////////////////////////////////////////
// HELPERS
///////////////////////////////////////////////////////////////////////////////

fn hash_signature_message(message: &str) -> Vec<u8> {
    let message = pack_signature_message(message);
    let mut hasher = Keccak256::new();
    hasher.update(message);
    let message_hash = hasher.finalize();

    Vec::from(message_hash.as_slice())
}

fn pack_signature_message(payload: &str) -> Vec<u8> {
    let prefix: String = format!("{}{}", ETHEREUM_SIGNATURE_PREFIX, payload.len());
    let prefix: &[u8] = prefix.as_bytes();
    let payload: &[u8] = payload.as_bytes();
    [prefix, payload].concat()
}

///////////////////////////////////////////////////////////////////////////////
// TESTS
///////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::{compute_private_key, compute_public_key};

    #[test]
    fn should_sign_string_messages() {
        let mnemonic =
            "poverty castle step need baby chair measure leader dress print cruise baby avoid fee sock shoulder rate opinion";
        let message = "hello";

        let priv_key = compute_private_key(mnemonic, "").unwrap();
        assert_eq!(
            priv_key,
            "e8088b11cdf79dab6919103720a424e33ffb68d7f272432e2798f1eaf346967c",
        );
        let signature = sign_message(message, &priv_key).unwrap();

        assert_eq!(signature,
        "9d06b4f31641aba791bb79dfb211c1141c4b3e346f230c05256c657c5c10916229a8f4cee40bfdbe0d90061d60e712ec5ec0c59cb90321814848ec2f6f7763181b");

        let message = "àèìòù";
        let signature = sign_message(message, &priv_key).unwrap();
        assert_eq!(signature,
        "2cbf9ae0de3df7e975b68b4cf67e14a0b49a1f8ed5d54c6c13d2ff936585036232fb53846fd49331bf8832fcd7e4517c3f07c951b95d5e0e102e572bbbadda811c");
    }

    #[test]
    fn should_verify_valid_signatures() {
        let mnemonic =
            "poverty castle step need baby chair measure leader dress print cruise baby avoid fee sock shoulder rate opinion";
        let message = "hello";
        let replacements = vec![
            "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f",
        ];

        let priv_key = compute_private_key(mnemonic, "").unwrap();
        let pub_key = compute_public_key(&priv_key).unwrap();

        // 1
        let signature = sign_message(message, &priv_key).unwrap();
        let valid = is_valid(&signature, &message, &pub_key);
        assert_eq!(valid, true, "Signature should be valid");

        // 1 tampered
        for i in 0..replacements.len() {
            for j in 0..replacements.len() {
                if i == j {
                    continue;
                }
                assert_eq!(
                    is_valid(
                        &signature.replace(replacements[i], replacements[j]),
                        &message,
                        &pub_key
                    ),
                    false,
                    "Signature should be invalid"
                )
            }
        }

        // mixed
        let signature = sign_message("hello", &priv_key).unwrap();
        let valid = is_valid(&signature, "another-different-message", &pub_key);
        assert_eq!(valid, false, "Signature should be invalid");

        let signature = sign_message("message-1234", &priv_key).unwrap();
        let valid = is_valid(&signature, "random-message-here", &pub_key);
        assert_eq!(valid, false, "Signature should be invalid");

        // 2
        let message = "àèìòù";

        let signature = sign_message(message, &priv_key).unwrap();
        let valid = is_valid(&signature, &message, &pub_key);
        assert_eq!(valid, true, "Signature should be valid");

        // 2 tampered
        for i in 0..replacements.len() {
            for j in 0..replacements.len() {
                if i == j {
                    continue;
                }
                assert_eq!(
                    is_valid(
                        &signature.replace(replacements[i], replacements[j]),
                        &message,
                        &pub_key
                    ),
                    false,
                    "Signature should be invalid"
                )
            }
        }
    }

    #[test]
    fn should_recover_signers() {
        let mnemonic =
            "poverty castle step need baby chair measure leader dress print cruise baby avoid fee sock shoulder rate opinion";
        let message = "hello";

        let priv_key = compute_private_key(mnemonic, "").unwrap();
        let pub_key = compute_public_key(&priv_key).unwrap();

        // 1
        let signature = sign_message(message, &priv_key).unwrap();
        let result_pub_key = recover_signer(&signature, &message).unwrap();
        assert_eq!(result_pub_key, pub_key, "Signer should match");

        // 1 tampered
        for i in 0..10 {
            let tampered_message = format!("random payload {}", i);
            let result_pub_key = recover_signer(&signature, &tampered_message).unwrap();
            assert_ne!(result_pub_key, pub_key, "Signer should not match");
        }

        // 2
        let message = "àèìòù";

        let signature = sign_message(message, &priv_key).unwrap();
        let result_pub_key = recover_signer(&signature, &message).unwrap();
        assert_eq!(result_pub_key, pub_key, "Signer should match");

        // 2 tampered
        for i in 0..10 {
            let tampered_message = format!("random message {}", i);
            let result_pub_key = recover_signer(&signature, &tampered_message).unwrap();
            assert_ne!(result_pub_key, pub_key, "Signer should not match");
        }
    }
}
