use super::util::decode_hex_string;

use bip39::{Language, Mnemonic, MnemonicType, Seed};
use ethsign::SecretKey;
use sha3::{Digest, Keccak256};
use tiny_hderive::bip32::ExtendedPrivKey;

pub const DEFAULT_HD_PATH: &str = "m/44'/60'/0'/0/0";

/// Generates a random mnemonic of the given size (128, 160, 192, 224 or 256)
pub fn generate_mnemonic(size: i32) -> Result<String, String> {
    let size = match size {
        128 => MnemonicType::Words12,
        160 => MnemonicType::Words15,
        192 => MnemonicType::Words18,
        224 => MnemonicType::Words21,
        256 => MnemonicType::Words24,
        _ => return Err("Invalid size".to_string()),
    };
    let mnemonic = Mnemonic::new(size, Language::English);
    Ok(mnemonic.phrase().to_string())
}

/// Computes the private key generated from the given mnemonic and derivation path.
/// If empty, the HD path used will be `"m/44'/60'/0'/0/0"`.
pub fn compute_private_key(phrase: &str, hd_path: &str) -> Result<String, String> {
    let hd_path = if hd_path == "" {
        DEFAULT_HD_PATH
    } else {
        hd_path
    };
    let mnemonic = Mnemonic::from_phrase(phrase, Language::English)
        .map_err(|_| "Invalid mnemonic".to_string())?;
    // Get the HD wallet seed
    let seed = Seed::new(&mnemonic, "");
    let seed_bytes: &[u8] = seed.as_bytes();

    let secret_key_bytes =
        ExtendedPrivKey::derive(seed_bytes, hd_path).map_err(|_| "Invalid HD path".to_string())?;
    // Byte array of the secp256k1 secret key
    Ok(hex::encode(secret_key_bytes.secret()))
}

/// Computes the public key that corresponds to the given hex private key.
/// The resulting public key is an uncompressed hex-encoded string without the leading "0x".
pub fn compute_public_key(hex_private_key: &str) -> Result<String, String> {
    let private_key_bytes = decode_hex_string(hex_private_key)?;
    let key = SecretKey::from_raw(&private_key_bytes)
        .map_err(|err| format!("Cannot import the raw private key: {}", err))?;
    let pub_key = hex::encode(key.public().bytes().as_ref());
    Ok(format!("04{}", &pub_key))
}

/// Computes the Ethereum address that corresponds to the given hex private key.
pub fn compute_address(hex_private_key: &str) -> Result<String, String> {
    let private_key_bytes = decode_hex_string(hex_private_key)?;
    let key = SecretKey::from_raw(&private_key_bytes)
        .map_err(|_| "Cannot import the raw private key".to_string())?;
    let hex_address = hex::encode(key.public().address().as_ref());
    // Apply the checksum
    let address = checksum_ethereum_address(&hex_address)?;
    Ok(address)
}

///////////////////////////////////////////////////////////////////////////////
// HELPERS
///////////////////////////////////////////////////////////////////////////////

fn checksum_ethereum_address(hex_address: &str) -> Result<String, String> {
    let hex_address: &str = if hex_address.starts_with("0x") {
        &hex_address[2..] // skip 0x
    } else {
        hex_address
    };
    // Check for hex correctness
    hex::decode(&hex_address)
        .map_err(|_| "The given address is an invalid hex value".to_string())?;

    // Hash the address hex string
    let mut hasher = Keccak256::new();
    hasher.update(hex_address.as_bytes());
    let address_hash_bytes = hasher.finalize();
    let hex_address_hash = hex::encode(address_hash_bytes);

    // Process the chars according to the hash
    let mut result = "0x".to_string();
    let hash_chars = hex_address_hash.chars().collect::<Vec<char>>();
    let addr_chars = hex_address.chars().collect::<Vec<char>>();

    for i in 0..addr_chars.len() {
        let n = i64::from_str_radix(&hash_chars[i].to_string(), 16).unwrap();
        let ch = addr_chars[i];

        if n <= 7 {
            result = format!("{}{}", result, ch.to_string());
        } else {
            result = format!("{}{}", result, ch.to_uppercase().to_string());
        }
    }
    Ok(result)
}

///////////////////////////////////////////////////////////////////////////////
// TESTS
///////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_generate_random_mnemonics() {
        let mnemonic = generate_mnemonic(128).unwrap();
        assert_eq!(
            mnemonic.split_whitespace().count(),
            12,
            "Should contain 12 words"
        );

        for _ in 0..20 {
            assert_ne!(
                mnemonic,
                generate_mnemonic(128).unwrap(),
                "Mnemonics should be random"
            );
        }

        // All sizes

        assert_eq!(
            generate_mnemonic(160).unwrap().split_whitespace().count(),
            15,
            "Should contain 15 words"
        );
        assert_eq!(
            generate_mnemonic(192).unwrap().split_whitespace().count(),
            18,
            "Should contain 18 words"
        );
        assert_eq!(
            generate_mnemonic(224).unwrap().split_whitespace().count(),
            21,
            "Should contain 21 words"
        );
        assert_eq!(
            generate_mnemonic(256).unwrap().split_whitespace().count(),
            24,
            "Should contain 24 words"
        );
    }

    #[test]
    fn should_compute_private_public_keys_and_addresses() {
        let priv_key = compute_private_key(
            "coral imitate swim axis note super success public poem frown verify then",
            "",
        )
        .unwrap();
        assert_eq!(
            priv_key,
            "975a999c921f77c1812833d903799cdb7780b07809eb67070ac2598f45e9fb3f",
        );
        let pub_key = compute_public_key(&priv_key).unwrap();
        assert_eq!(pub_key,
        "046fbd249af1bf365abd8d0cfc390c87ff32a997746c53dceab3794e2913d4cb26e055c8177faab65b404ea24754d8f56ef5df909a39d99ee0e7ca291a11556b37");
        let address = compute_address(&priv_key).unwrap();
        assert_eq!(address, "0x6AAa00b7c22021F96B09BB52cb9135F0cB865c5D");

        let priv_key = compute_private_key(
            "almost slush girl resource piece meadow cable fancy jar barely mother exhibit",
            "",
        )
        .unwrap();
        assert_eq!(
            priv_key,
            "32fa4a65b9cb770235a8f0af497536035a459a98179c2c667972be279fbd1a1a",
        );
        let pub_key = compute_public_key(&priv_key).unwrap();
        assert_eq!(pub_key,
        "0425eb0aac23fe343e7ac5c8a792898a4f1d55b3150f3609cde6b7ada2dff029a89430669dd7f39ffe72eb9b8335fef52fd70863d123ba0015e90cbf68b58385eb");

        let address = compute_address(&priv_key).unwrap();
        assert_eq!(address, "0xf0492A8Dc9c84E6c5b66e10D0eC1A46A96FF74D3");

        let priv_key = compute_private_key(
            "civil very heart sock decade library moment permit retreat unhappy clown infant",
            "",
        )
        .unwrap();
        assert_eq!(
            priv_key,
            "1b3711c03353ecbbf7b686127e30d6a37a296ed797793498ef24c04504ca5048",
        );
        let pub_key = compute_public_key(&priv_key).unwrap();
        assert_eq!(pub_key,
        "04ae5f2ecb63c4b9c71e1b396c8206720c02bddceb01da7c9f590aa028f110c035fa54045f6361fa0c6b5914a33e0d6f2f435818f0268ec8196062d1521ea8451a");
        let address = compute_address(&priv_key).unwrap();
        assert_eq!(address, "0x9612bD0deB9129536267d154D672a7f1281eb468");

        let priv_key = compute_private_key(
            "life noble news naive know verb leaf parade brisk chuckle midnight play",
            "",
        )
        .unwrap();
        assert_eq!(
            priv_key,
            "3c21df88530a25979494c4c7789334ba5dd1c8c73d23c4077a7f223c2274830f",
        );
        let pub_key = compute_public_key(&priv_key).unwrap();
        assert_eq!(pub_key,
        "041d792012043464ac528d15e3309d4e55b41205380dfe14a01e2be95a30d0ac80a313dbc6881d5f034c38d091cb27a0301b42faca820274e6a84d2268f8c4f556");
        let address = compute_address(&priv_key).unwrap();
        assert_eq!(address, "0x34E3b8a0299dc7Dc53de09ce8361b41A7D888EC4");
    }

    #[test]
    fn should_derive_keys_using_hd_path() {
        let mnemonic =
            "civil very heart sock decade library moment permit retreat unhappy clown infant";
        // index 0
        let priv_key = compute_private_key(mnemonic, "m/44'/60'/0'/0/0").unwrap();
        assert_eq!(
            priv_key,
            "1b3711c03353ecbbf7b686127e30d6a37a296ed797793498ef24c04504ca5048",
        );
        let pub_key = compute_public_key(&priv_key).unwrap();
        assert_eq!(pub_key,
        "04ae5f2ecb63c4b9c71e1b396c8206720c02bddceb01da7c9f590aa028f110c035fa54045f6361fa0c6b5914a33e0d6f2f435818f0268ec8196062d1521ea8451a");
        let address = compute_address(&priv_key).unwrap();
        assert_eq!(address, "0x9612bD0deB9129536267d154D672a7f1281eb468");

        // index 1
        let priv_key = compute_private_key(mnemonic, "m/44'/60'/0'/0/1").unwrap();
        assert_eq!(
            priv_key,
            "2b8642b869998d77243669463b68058299260349eba6c893d892d4b74eae95d4",
        );
        let pub_key = compute_public_key(&priv_key).unwrap();
        assert_eq!(pub_key,
        "04d8b869ceb2d90c2ab0b0eecd2f4215f42cb40a82e7de854ca14e85a1a84e00a45e1c37334666acb08b62b19f42c18524d9d5952fb43054363350820f5190f17d");
        let address = compute_address(&priv_key).unwrap();
        assert_eq!(address, "0x67b5615fDC5c65Afce9B97bD217804f1dB04bC1b");

        // index 2
        let priv_key = compute_private_key(mnemonic, "m/44'/60'/0'/0/2").unwrap();
        assert_eq!(
            priv_key,
            "562870cd36727fdca458ada4c2a34e0170b7b4cc4d3dc3b60cba3582bf8c3167",
        );
        let pub_key = compute_public_key(&priv_key).unwrap();
        assert_eq!(pub_key,
        "04887f399e99ce751f82f73a9a88ab015db74b40f707534f54a807fa6e10982cbfaffe93414466b347b83cd43bc0d1a147443576446b49d0e3d6db24f37fe02567");
        let address = compute_address(&priv_key).unwrap();
        assert_eq!(address, "0x0887fb27273A36b2A641841Bf9b47470d5C0E420");
    }

    #[test]
    fn should_compute_addresses_with_checksum() {
        let address = "0x6cf64a4463e7ee29d6d102020d66a02ff35e4e5f";
        assert_eq!(
            checksum_ethereum_address(&address).unwrap(),
            "0x6cF64a4463e7ee29D6D102020D66a02FF35e4e5F",
        );
        let address = "0xd083e49a904da3fc5b6e4ff05aacb408b3ec6f05";
        assert_eq!(
            checksum_ethereum_address(&address).unwrap(),
            "0xd083e49a904DA3Fc5B6e4ff05AACb408B3EC6F05",
        );
        let address = "0x82b646a72dfa7a43989ef65c8f2af05914b57c3b";
        assert_eq!(
            checksum_ethereum_address(&address).unwrap(),
            "0x82b646A72DFa7a43989ef65C8f2Af05914b57c3B",
        );
        let address = "0xfda3e74cff68260dcbc67a1b196106bc4946da05";
        assert_eq!(
            checksum_ethereum_address(&address).unwrap(),
            "0xFDA3E74CFF68260dCbc67a1b196106bc4946da05",
        );
        let address = "0xf9312824eb6369e1745c01415a06bd47c2931211";
        assert_eq!(
            checksum_ethereum_address(&address).unwrap(),
            "0xf9312824eb6369E1745c01415a06Bd47c2931211",
        );
        let address = "0x6f96da6345d4a01ff0f8250dc4b9b13d2d49b6db";
        assert_eq!(
            checksum_ethereum_address(&address).unwrap(),
            "0x6F96da6345D4A01ff0F8250Dc4B9b13d2d49B6DB",
        );
        let address = "0xecf9ddfc1c433078276a8c5ef76a1a827978362e";
        assert_eq!(
            checksum_ethereum_address(&address).unwrap(),
            "0xECF9ddfc1C433078276a8C5EF76a1A827978362e",
        );
    }
}
