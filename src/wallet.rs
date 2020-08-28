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
/// The resulting public key is a compressed hex-encoded string without the leading "0x".
pub fn compute_public_key(hex_private_key: &str) -> Result<String, String> {
    let private_key_bytes = decode_hex_string(hex_private_key)?;
    let key = SecretKey::from_raw(&private_key_bytes)
        .map_err(|err| format!("Cannot import the raw private key: {}", err))?;

    Ok(serialize_compressed_public_key(key.public()))
}

/// Computes the public key that corresponds to the given hex private key.
/// The resulting public key is an uncompressed hex-encoded string without the leading "0x".
pub fn compute_public_key_uncompressed(hex_private_key: &str) -> Result<String, String> {
    let private_key_bytes = decode_hex_string(hex_private_key)?;
    let key = SecretKey::from_raw(&private_key_bytes)
        .map_err(|err| format!("Cannot import the raw private key: {}", err))?;

    Ok(serialize_uncompressed_public_key(key.public()))
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

pub fn checksum_ethereum_address(hex_address: &str) -> Result<String, String> {
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

pub fn serialize_uncompressed_public_key(public_key: ethsign::PublicKey) -> String {
    let pub_key = hex::encode(public_key.bytes().as_ref());
    format!("04{}", &pub_key)
}

pub fn serialize_compressed_public_key(public_key: ethsign::PublicKey) -> String {
    let x = hex::encode(&public_key.bytes()[0..32].as_ref());
    let y_sign = public_key.bytes()[63];

    if y_sign & 0x01 == 0 {
        format!("02{}", x)
    } else {
        format!("03{}", x)
    }
}

///////////////////////////////////////////////////////////////////////////////
// TESTS
///////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::decode_hex_string;
    use ethsign::PublicKey;

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
        // 1
        let priv_key = compute_private_key(
            "coral imitate swim axis note super success public poem frown verify then",
            "",
        )
        .unwrap();
        assert_eq!(
            priv_key,
            "975a999c921f77c1812833d903799cdb7780b07809eb67070ac2598f45e9fb3f",
        );
        let pub_key = compute_public_key_uncompressed(&priv_key).unwrap();
        assert_eq!(pub_key,
        "046fbd249af1bf365abd8d0cfc390c87ff32a997746c53dceab3794e2913d4cb26e055c8177faab65b404ea24754d8f56ef5df909a39d99ee0e7ca291a11556b37");
        let pub_key = compute_public_key(&priv_key).unwrap();
        assert_eq!(
            pub_key,
            "036fbd249af1bf365abd8d0cfc390c87ff32a997746c53dceab3794e2913d4cb26"
        );
        let address = compute_address(&priv_key).unwrap();
        assert_eq!(address, "0x6AAa00b7c22021F96B09BB52cb9135F0cB865c5D");

        // 2
        let priv_key = compute_private_key(
            "almost slush girl resource piece meadow cable fancy jar barely mother exhibit",
            "",
        )
        .unwrap();
        assert_eq!(
            priv_key,
            "32fa4a65b9cb770235a8f0af497536035a459a98179c2c667972be279fbd1a1a",
        );
        let pub_key = compute_public_key_uncompressed(&priv_key).unwrap();
        assert_eq!(pub_key,
        "0425eb0aac23fe343e7ac5c8a792898a4f1d55b3150f3609cde6b7ada2dff029a89430669dd7f39ffe72eb9b8335fef52fd70863d123ba0015e90cbf68b58385eb");
        let pub_key = compute_public_key(&priv_key).unwrap();
        assert_eq!(
            pub_key,
            "0325eb0aac23fe343e7ac5c8a792898a4f1d55b3150f3609cde6b7ada2dff029a8"
        );

        let address = compute_address(&priv_key).unwrap();
        assert_eq!(address, "0xf0492A8Dc9c84E6c5b66e10D0eC1A46A96FF74D3");

        // 3
        let priv_key = compute_private_key(
            "civil very heart sock decade library moment permit retreat unhappy clown infant",
            "",
        )
        .unwrap();
        assert_eq!(
            priv_key,
            "1b3711c03353ecbbf7b686127e30d6a37a296ed797793498ef24c04504ca5048",
        );
        let pub_key = compute_public_key_uncompressed(&priv_key).unwrap();
        assert_eq!(pub_key,
        "04ae5f2ecb63c4b9c71e1b396c8206720c02bddceb01da7c9f590aa028f110c035fa54045f6361fa0c6b5914a33e0d6f2f435818f0268ec8196062d1521ea8451a");
        let pub_key = compute_public_key(&priv_key).unwrap();
        assert_eq!(
            pub_key,
            "02ae5f2ecb63c4b9c71e1b396c8206720c02bddceb01da7c9f590aa028f110c035"
        );
        let address = compute_address(&priv_key).unwrap();
        assert_eq!(address, "0x9612bD0deB9129536267d154D672a7f1281eb468");

        // 4
        let priv_key = compute_private_key(
            "life noble news naive know verb leaf parade brisk chuckle midnight play",
            "",
        )
        .unwrap();
        assert_eq!(
            priv_key,
            "3c21df88530a25979494c4c7789334ba5dd1c8c73d23c4077a7f223c2274830f",
        );
        let pub_key = compute_public_key_uncompressed(&priv_key).unwrap();
        assert_eq!(pub_key,
        "041d792012043464ac528d15e3309d4e55b41205380dfe14a01e2be95a30d0ac80a313dbc6881d5f034c38d091cb27a0301b42faca820274e6a84d2268f8c4f556");
        let pub_key = compute_public_key(&priv_key).unwrap();
        assert_eq!(
            pub_key,
            "021d792012043464ac528d15e3309d4e55b41205380dfe14a01e2be95a30d0ac80"
        );
        let address = compute_address(&priv_key).unwrap();
        assert_eq!(address, "0x34E3b8a0299dc7Dc53de09ce8361b41A7D888EC4");

        // 5
        let priv_key = compute_private_key(
            "return guide exotic stem lazy cancel stamp company purse useless pact affair ripple intact destroy finish kite muffin",
            "",
        )
        .unwrap();
        assert_eq!(
            priv_key,
            "c6fd4b75573df00fd8713c5cce929ec41c57398fe9de99eece6b9807132a3b6b",
        );
        let pub_key = compute_public_key_uncompressed(&priv_key).unwrap();
        assert_eq!(pub_key,
        "04ac5bf23ace5fc335c3aa86f47e4f57ec60ef44b5411626340a98b1bc3cf6bc30ccb646953bc03a2deaad31bfc54779e6e58398f5ac143adaa01696a3984881fa");
        let pub_key = compute_public_key(&priv_key).unwrap();
        assert_eq!(
            pub_key,
            "02ac5bf23ace5fc335c3aa86f47e4f57ec60ef44b5411626340a98b1bc3cf6bc30"
        );
        let address = compute_address(&priv_key).unwrap();
        assert_eq!(address, "0xC0dfb272D07e70955EF949DFD951913FDA737d7A");
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
        let pub_key = compute_public_key_uncompressed(&priv_key).unwrap();
        assert_eq!(pub_key,
        "04ae5f2ecb63c4b9c71e1b396c8206720c02bddceb01da7c9f590aa028f110c035fa54045f6361fa0c6b5914a33e0d6f2f435818f0268ec8196062d1521ea8451a");
        let pub_key = compute_public_key(&priv_key).unwrap();
        assert_eq!(
            pub_key,
            "02ae5f2ecb63c4b9c71e1b396c8206720c02bddceb01da7c9f590aa028f110c035"
        );
        let address = compute_address(&priv_key).unwrap();
        assert_eq!(address, "0x9612bD0deB9129536267d154D672a7f1281eb468");

        // index 1
        let priv_key = compute_private_key(mnemonic, "m/44'/60'/0'/0/1").unwrap();
        assert_eq!(
            priv_key,
            "2b8642b869998d77243669463b68058299260349eba6c893d892d4b74eae95d4",
        );
        let pub_key = compute_public_key_uncompressed(&priv_key).unwrap();
        assert_eq!(pub_key,
        "04d8b869ceb2d90c2ab0b0eecd2f4215f42cb40a82e7de854ca14e85a1a84e00a45e1c37334666acb08b62b19f42c18524d9d5952fb43054363350820f5190f17d");
        let pub_key = compute_public_key(&priv_key).unwrap();
        assert_eq!(
            pub_key,
            "03d8b869ceb2d90c2ab0b0eecd2f4215f42cb40a82e7de854ca14e85a1a84e00a4"
        );
        let address = compute_address(&priv_key).unwrap();
        assert_eq!(address, "0x67b5615fDC5c65Afce9B97bD217804f1dB04bC1b");

        // index 2
        let priv_key = compute_private_key(mnemonic, "m/44'/60'/0'/0/2").unwrap();
        assert_eq!(
            priv_key,
            "562870cd36727fdca458ada4c2a34e0170b7b4cc4d3dc3b60cba3582bf8c3167",
        );
        let pub_key = compute_public_key_uncompressed(&priv_key).unwrap();
        assert_eq!(pub_key,
        "04887f399e99ce751f82f73a9a88ab015db74b40f707534f54a807fa6e10982cbfaffe93414466b347b83cd43bc0d1a147443576446b49d0e3d6db24f37fe02567");
        let pub_key = compute_public_key(&priv_key).unwrap();
        assert_eq!(
            pub_key,
            "03887f399e99ce751f82f73a9a88ab015db74b40f707534f54a807fa6e10982cbf"
        );
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

    #[test]
    fn should_compress_public_keys() {
        let public_key_bytes = decode_hex_string("7968f23e6de9e1e9d92a11dc0fbb4381f23a959103e353535b0666a5313983ee2f9b739851d747e90ff2ada2418539add1ca94426ff0416674dffd7e2574a534").unwrap();
        let public_key = PublicKey::from_slice(public_key_bytes.as_slice()).unwrap();
        assert_eq!(
            serialize_compressed_public_key(public_key),
            "027968f23e6de9e1e9d92a11dc0fbb4381f23a959103e353535b0666a5313983ee"
        );
        let public_key_bytes = decode_hex_string("46f141f9de02412ee630ec0a208261f08e6c0dd2925cb17bdd85cf4ab898c9b9743def4f486f75f3e582e0bb0c0ccd8ecd07c3fd1743f8c6ec23841935fb126b").unwrap();
        let public_key = PublicKey::from_slice(public_key_bytes.as_slice()).unwrap();
        assert_eq!(
            serialize_compressed_public_key(public_key),
            "0346f141f9de02412ee630ec0a208261f08e6c0dd2925cb17bdd85cf4ab898c9b9"
        );
        let public_key_bytes = decode_hex_string("9c0367198c513eb69234fd4e6cfb83b74213c077470109927e6aecbb49ff6aceb51f6f33c2252f31de03fbac9fb7e4d5f38d32f4ae217815000fbc3f3b4177f8").unwrap();
        let public_key = PublicKey::from_slice(public_key_bytes.as_slice()).unwrap();
        assert_eq!(
            serialize_compressed_public_key(public_key),
            "029c0367198c513eb69234fd4e6cfb83b74213c077470109927e6aecbb49ff6ace"
        );
        let public_key_bytes = decode_hex_string("a01d66e43dc8fadbaa93c14c55e6c348239f50ac2008df6af0a108395d28e4a497fbd8ef23d186549911aa8626b137bc41565352d1cf42aa741f4e82752cbf27").unwrap();
        let public_key = PublicKey::from_slice(public_key_bytes.as_slice()).unwrap();
        assert_eq!(
            serialize_compressed_public_key(public_key),
            "03a01d66e43dc8fadbaa93c14c55e6c348239f50ac2008df6af0a108395d28e4a4"
        );
        let public_key_bytes = decode_hex_string("4dfcc782a9e9ecb559cbb136349c28d1d1575cb6cb6bf12f2240b75b0e0f5fd2c78e6e0f0dae3581cecc7562c4e390058371589faec05e4733210cf899d106c9").unwrap();
        let public_key = PublicKey::from_slice(public_key_bytes.as_slice()).unwrap();
        assert_eq!(
            serialize_compressed_public_key(public_key),
            "034dfcc782a9e9ecb559cbb136349c28d1d1575cb6cb6bf12f2240b75b0e0f5fd2"
        );

        let public_key_bytes = decode_hex_string("ad6b06dc01f9315fa74b6d260a3443377e421541c068a95405483d9eb3096341dd72b3c4087ad047283c5c7366adaa786da885cd28bc2bf54e94088a2978f52c").unwrap();
        let public_key = PublicKey::from_slice(public_key_bytes.as_slice()).unwrap();
        assert_eq!(
            serialize_compressed_public_key(public_key),
            "02ad6b06dc01f9315fa74b6d260a3443377e421541c068a95405483d9eb3096341"
        );
        let public_key_bytes = decode_hex_string("c6707ad31cc335175646d5afaa5a9c18edc3fff493d68dd64ed7b3fa1bfe4e31c8f2b63d7029e9904e74bea3b00df4df2008344934476ea1fa912a4b75a2216e").unwrap();
        let public_key = PublicKey::from_slice(public_key_bytes.as_slice()).unwrap();
        assert_eq!(
            serialize_compressed_public_key(public_key),
            "02c6707ad31cc335175646d5afaa5a9c18edc3fff493d68dd64ed7b3fa1bfe4e31"
        );
        let public_key_bytes = decode_hex_string("3c737e68eef67093979976dc931fc739778396511617b19f5395dd5034c59301f72b32cdfed11b334b0469140763c9a6961af1a5cc8c994ce936a0033d350415").unwrap();
        let public_key = PublicKey::from_slice(public_key_bytes.as_slice()).unwrap();
        assert_eq!(
            serialize_compressed_public_key(public_key),
            "033c737e68eef67093979976dc931fc739778396511617b19f5395dd5034c59301"
        );
        let public_key_bytes = decode_hex_string("02aaf3b7742e2c105092f6a73fdaeb727d1a0c17c295baf4ad5758003396f8ccd559d1eaf6e5f25d2779aa4a2654d2dfd46231a1d1d4f4238e9b985e10c8ee71").unwrap();
        let public_key = PublicKey::from_slice(public_key_bytes.as_slice()).unwrap();
        assert_eq!(
            serialize_compressed_public_key(public_key),
            "0302aaf3b7742e2c105092f6a73fdaeb727d1a0c17c295baf4ad5758003396f8cc"
        );
        let public_key_bytes = decode_hex_string("2928f818f3d49e253a6ae7694eae211044b46ae27d9bd80ae364a93db8d6bc52a5e976d81de3e8a61d6d257b7d5979b437e80e94ffa43ae7f92421444b5b3606").unwrap();
        let public_key = PublicKey::from_slice(public_key_bytes.as_slice()).unwrap();
        assert_eq!(
            serialize_compressed_public_key(public_key),
            "022928f818f3d49e253a6ae7694eae211044b46ae27d9bd80ae364a93db8d6bc52"
        );
        let public_key_bytes = decode_hex_string("e2b66d947546e03189d1b8e0b714a18480091aa95b1b437a6fd743ea03ecf9c9579b5d4820573dd57bf31333e9c4b05f7513b1a93ac7e1c58a52c4d3655ae82a").unwrap();
        let public_key = PublicKey::from_slice(public_key_bytes.as_slice()).unwrap();
        assert_eq!(
            serialize_compressed_public_key(public_key),
            "02e2b66d947546e03189d1b8e0b714a18480091aa95b1b437a6fd743ea03ecf9c9"
        );
        let public_key_bytes = decode_hex_string("faab16de7836c4e1d1ded1f25e47232de9a7125e6ca262ba318ae0184a507cd3a6d22c0d4f94da972a5339bcb4333a43898e10366a09df97e1c927975d462674").unwrap();
        let public_key = PublicKey::from_slice(public_key_bytes.as_slice()).unwrap();
        assert_eq!(
            serialize_compressed_public_key(public_key),
            "02faab16de7836c4e1d1ded1f25e47232de9a7125e6ca262ba318ae0184a507cd3"
        );
        let public_key_bytes = decode_hex_string("6da29eb7d298e43a894c4b17d9210a7b4a366c7376d49b58714dfe185bd59651727eb8a3c1fa8f73d442e740e3e0091588953ea99c6269669cb349540deeabdb").unwrap();
        let public_key = PublicKey::from_slice(public_key_bytes.as_slice()).unwrap();
        assert_eq!(
            serialize_compressed_public_key(public_key),
            "036da29eb7d298e43a894c4b17d9210a7b4a366c7376d49b58714dfe185bd59651"
        );
        let public_key_bytes = decode_hex_string("7fae4725d9273bab8dc1340cbe30706293099b018ff75823efb80acbdc7a1b0f7d93f1fc10495cf9725a7d1a6f60d75fa56a1a5311097c2d6967c3810e01b45d").unwrap();
        let public_key = PublicKey::from_slice(public_key_bytes.as_slice()).unwrap();
        assert_eq!(
            serialize_compressed_public_key(public_key),
            "037fae4725d9273bab8dc1340cbe30706293099b018ff75823efb80acbdc7a1b0f"
        );
        let public_key_bytes = decode_hex_string("c533e19a9a1a22562c3454ca08b2f74f42d733c069514f599797531137725ffef2d3bee5c5d24aede0a27d344eff9bdfb3741a45a00cea1cb12dc80a2048e79c").unwrap();
        let public_key = PublicKey::from_slice(public_key_bytes.as_slice()).unwrap();
        assert_eq!(
            serialize_compressed_public_key(public_key),
            "02c533e19a9a1a22562c3454ca08b2f74f42d733c069514f599797531137725ffe"
        );
        let public_key_bytes = decode_hex_string("9891696d9982d81d49ebac7b24aa0d463abd047de1885d2b5a586ab57484b52654506c1fa32540e2f69458fa5ccf810e1b2face6619164daa8268448d536b426").unwrap();
        let public_key = PublicKey::from_slice(public_key_bytes.as_slice()).unwrap();
        assert_eq!(
            serialize_compressed_public_key(public_key),
            "029891696d9982d81d49ebac7b24aa0d463abd047de1885d2b5a586ab57484b526"
        );
        let public_key_bytes = decode_hex_string("c4bbdd36a590a1fca946fa73c39351adbec3efe5453533be5486fe516c6e531f702e62f5c17e4049f97b0644225bf46805a5a5dd261837440863d5ecd72f8bf1").unwrap();
        let public_key = PublicKey::from_slice(public_key_bytes.as_slice()).unwrap();
        assert_eq!(
            serialize_compressed_public_key(public_key),
            "03c4bbdd36a590a1fca946fa73c39351adbec3efe5453533be5486fe516c6e531f"
        );
        let public_key_bytes = decode_hex_string("910b2717412429f9a8e3547d8297adb03809ac0ffc25eaad0b21e475f6c7409f648020ff297aa64e8ab3dcec0573171296391110383b2bc9cf4f27f9a32e69dd").unwrap();
        let public_key = PublicKey::from_slice(public_key_bytes.as_slice()).unwrap();
        assert_eq!(
            serialize_compressed_public_key(public_key),
            "03910b2717412429f9a8e3547d8297adb03809ac0ffc25eaad0b21e475f6c7409f"
        );
        let public_key_bytes = decode_hex_string("b464d534cb8027fc1371a5a4605bc8c4522cd914efae1b8b657631e7b91fd6e3b87aa041af8369e71c9da8ddf4f068bd37f1198a64a15ef79552a06ae887dcea").unwrap();
        let public_key = PublicKey::from_slice(public_key_bytes.as_slice()).unwrap();
        assert_eq!(
            serialize_compressed_public_key(public_key),
            "02b464d534cb8027fc1371a5a4605bc8c4522cd914efae1b8b657631e7b91fd6e3"
        );
        let public_key_bytes = decode_hex_string("1fac3bf4ab01fcbb67afb30167f7845988794f619309c2e9b4128e2084d37c0b42361c5962d00d03e96904cfe647546679000fd82836984c52da0dff6246e34c").unwrap();
        let public_key = PublicKey::from_slice(public_key_bytes.as_slice()).unwrap();
        assert_eq!(
            serialize_compressed_public_key(public_key),
            "021fac3bf4ab01fcbb67afb30167f7845988794f619309c2e9b4128e2084d37c0b"
        );
        let public_key_bytes = decode_hex_string("62e8d4ff52a568aa7660038c007991d645e304b090a398b3d089441d81f08d3f9ccd565f9e884a56cc479bde4fe30b59ed56a54418c9be8c3c52b7b9446c9065").unwrap();
        let public_key = PublicKey::from_slice(public_key_bytes.as_slice()).unwrap();
        assert_eq!(
            serialize_compressed_public_key(public_key),
            "0362e8d4ff52a568aa7660038c007991d645e304b090a398b3d089441d81f08d3f"
        );
        let public_key_bytes = decode_hex_string("d662ee30b7c5892f95fa8d7c7e9211da1a842d8fe6bd7e6e60d8b7bffa9cf90cc7d904cc531b2f0146830d5588a0021c6107cd380c5d5fec9b0bcd05b6e1273d").unwrap();
        let public_key = PublicKey::from_slice(public_key_bytes.as_slice()).unwrap();
        assert_eq!(
            serialize_compressed_public_key(public_key),
            "03d662ee30b7c5892f95fa8d7c7e9211da1a842d8fe6bd7e6e60d8b7bffa9cf90c"
        );
        let public_key_bytes = decode_hex_string("d9a9ff8b19a2ad1d1242b14bd89eae6f48e2f1d34ee5fdd641158abfc925a57bc263e27ae6b5f80b4b1a80a1eeff52e5627d5d9f45186d84a74c197b1cc06fd8").unwrap();
        let public_key = PublicKey::from_slice(public_key_bytes.as_slice()).unwrap();
        assert_eq!(
            serialize_compressed_public_key(public_key),
            "02d9a9ff8b19a2ad1d1242b14bd89eae6f48e2f1d34ee5fdd641158abfc925a57b"
        );
        let public_key_bytes = decode_hex_string("72b23c26fa9de8af550513c0a646a56ca303a4d5e77d0331842ac8f6986fd4d5a074b79d4a7423b8f21f25bc5c3ae5db06d5172396e3598ad831eaa097ec09ba").unwrap();
        let public_key = PublicKey::from_slice(public_key_bytes.as_slice()).unwrap();
        assert_eq!(
            serialize_compressed_public_key(public_key),
            "0272b23c26fa9de8af550513c0a646a56ca303a4d5e77d0331842ac8f6986fd4d5"
        );
        let public_key_bytes = decode_hex_string("1725003d3372aa8432654e9337699be7a247157db290d092c79d92eda87048ec6f6bf9559b642bd06bf96ecfd08e478868781cff5485dde8abd1e5f528e4794a").unwrap();
        let public_key = PublicKey::from_slice(public_key_bytes.as_slice()).unwrap();
        assert_eq!(
            serialize_compressed_public_key(public_key),
            "021725003d3372aa8432654e9337699be7a247157db290d092c79d92eda87048ec"
        );
        let public_key_bytes = decode_hex_string("2eeb78abae36e5b4e751f9e3bb06083ad5f1290bc1008649ac723feae2fd29009b5c28fb6fb9b2be76c8db1fe24e27c1c63a08987483dd6c088d863e27a78076").unwrap();
        let public_key = PublicKey::from_slice(public_key_bytes.as_slice()).unwrap();
        assert_eq!(
            serialize_compressed_public_key(public_key),
            "022eeb78abae36e5b4e751f9e3bb06083ad5f1290bc1008649ac723feae2fd2900"
        );
        let public_key_bytes = decode_hex_string("0b347438273f24407221c96ac82de304186d78a9c7f46e54caa8348f492af6b034e8bb1086d3e8f65db55e77dc14c09c87d9477f7cd6cefa0a676db6d278c2f5").unwrap();
        let public_key = PublicKey::from_slice(public_key_bytes.as_slice()).unwrap();
        assert_eq!(
            serialize_compressed_public_key(public_key),
            "030b347438273f24407221c96ac82de304186d78a9c7f46e54caa8348f492af6b0"
        );
        let public_key_bytes = decode_hex_string("1a7fea139b605d0a77e3d3b0e6be02a910b58632eba1ed268f34cb4f2584003457ec791325865d7228db1312ba399c0b1bab88d892fa28d49662c33ee74be4d4").unwrap();
        let public_key = PublicKey::from_slice(public_key_bytes.as_slice()).unwrap();
        assert_eq!(
            serialize_compressed_public_key(public_key),
            "021a7fea139b605d0a77e3d3b0e6be02a910b58632eba1ed268f34cb4f25840034"
        );
        let public_key_bytes = decode_hex_string("6373022360fcebf444886f70596231108909d60a3a261573c1fa39f7c2735d63a36c746f879f97c60e815e4366140ba039302fd7319e5d9273c89456ffdf77a4").unwrap();
        let public_key = PublicKey::from_slice(public_key_bytes.as_slice()).unwrap();
        assert_eq!(
            serialize_compressed_public_key(public_key),
            "026373022360fcebf444886f70596231108909d60a3a261573c1fa39f7c2735d63"
        );
        let public_key_bytes = decode_hex_string("e245a37955fc8940685ea76ca015785b7032aa5859f6552781ba85b44c8ff4ba62c971ce063146b68826608b3c34240ac01ecc5a08e79eba4723202e27659970").unwrap();
        let public_key = PublicKey::from_slice(public_key_bytes.as_slice()).unwrap();
        assert_eq!(
            serialize_compressed_public_key(public_key),
            "02e245a37955fc8940685ea76ca015785b7032aa5859f6552781ba85b44c8ff4ba"
        );
        let public_key_bytes = decode_hex_string("34fae7dd6dac2586b387247bd013b99d06d600d810021c45e803f5f3a60cdf12fa13ab4c4d6cc7a6fff5580b063da512600fc2be9bc030f65e0864d36c224c57").unwrap();
        let public_key = PublicKey::from_slice(public_key_bytes.as_slice()).unwrap();
        assert_eq!(
            serialize_compressed_public_key(public_key),
            "0334fae7dd6dac2586b387247bd013b99d06d600d810021c45e803f5f3a60cdf12"
        );
        let public_key_bytes = decode_hex_string("e786e6f3d75337b19f5eb2cd38b974421590b4e49bd3d01fe28cc76d7c801ff052cde7103ed3646ffced0382e85cfd9881a7d3d29fd95c5b62ba1faefc380451").unwrap();
        let public_key = PublicKey::from_slice(public_key_bytes.as_slice()).unwrap();
        assert_eq!(
            serialize_compressed_public_key(public_key),
            "03e786e6f3d75337b19f5eb2cd38b974421590b4e49bd3d01fe28cc76d7c801ff0"
        );
        let public_key_bytes = decode_hex_string("00ab2e90856765a29020e813c87467b6784013237540c95b7793bc35be40893adccc9b48af087df83b5fb3d27390165e83e22f29cf7163ae57f60253020d9043").unwrap();
        let public_key = PublicKey::from_slice(public_key_bytes.as_slice()).unwrap();
        assert_eq!(
            serialize_compressed_public_key(public_key),
            "0300ab2e90856765a29020e813c87467b6784013237540c95b7793bc35be40893a"
        );
    }
}
