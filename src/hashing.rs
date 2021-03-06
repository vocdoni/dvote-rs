extern crate num_bigint;

use super::util::{decode_hex_string, pad_bigint_le};
use poseidon_rs::Poseidon;

/// Computes the Poseidon hash of the given string and returns a base-64 representation
pub fn digest_string_claim(claim: &str) -> Result<String, String> {
    // Convert into a byte array
    let claim_bytes = claim.as_bytes().to_vec();

    // Hash
    let poseidon = Poseidon::new();
    let hash = poseidon.hash_bytes(claim_bytes)?;

    let claim_bytes = pad_bigint_le(&hash);
    Ok(base64::encode(claim_bytes))
}

/// Computes the Poseidon hash of the given hex string and returns a base-64 representation
pub fn digest_hex_claim(hex_claim: &str) -> Result<String, String> {
    let claim_bytes = decode_hex_string(hex_claim)?;

    // Hash
    let poseidon = Poseidon::new();
    let hash = poseidon.hash_bytes(claim_bytes)?;
    let claim_bytes = pad_bigint_le(&hash);
    Ok(base64::encode(claim_bytes))
}

///////////////////////////////////////////////////////////////////////////////
// TESTS
///////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_hash_strings() {
        let str_claim = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
        let b64_hash = digest_string_claim(str_claim).unwrap();

        assert_eq!(b64_hash, "iV5141xlrW8I217IitUHtoDC/gd/LMsgcF0zpDfUaiM=");
    }

    #[test]
    fn should_hash_hex_pub_keys() {
        let hex_claim = "0x045a126cbbd3c66b6d542d40d91085e3f2b5db3bbc8cda0d59615deb08784e4f833e0bb082194790143c3d01cedb4a9663cb8c7bdaaad839cb794dd309213fcf30";
        let b64_hash = digest_hex_claim(hex_claim).unwrap();
        assert_eq!(b64_hash, "nGOYvS4aqqUVAT9YjWcUzA89DlHPWaooNpBTStOaHRA=");

        let hex_claim = "0x049969c7741ade2e9f89f81d12080651038838e8089682158f3d892e57609b64e2137463c816e4d52f6688d490c35a0b8e524ac6d9722eed2616dbcaf676fc2578";
        let b64_hash = digest_hex_claim(hex_claim).unwrap();
        assert_eq!(b64_hash, "j7jJlnBN73ORKWbNbVCHG9WkoqSr+IEKDwjcsb6N4xw=");

        let hex_claim = "0x049622878da186a8a31f4dc03454dbbc62365060458db174618218b51d5014fa56c8ea772234341ae326ce278091c39e30c02fa1f04792035d79311fe3283f1380";
        let b64_hash = digest_hex_claim(hex_claim).unwrap();
        assert_eq!(b64_hash, "6CUGhnmKQchF6Ter05laVgQYcEWm0p2qlLzX24rk3Ck=");

        let hex_claim = "0x04e355263aa6cbc99d2fdd0898f5ed8630115ad54e9073c41a8aa0df6d75842d8b8309d0d26a95565996b17da48f8ddff704ebcd1d8a982dc5ba8be7458c677b17";
        let b64_hash = digest_hex_claim(hex_claim).unwrap();
        assert_eq!(b64_hash, "k0UwNtWW4UQifisXuoDiO/QGRZNNTY7giWK1Nx/hoSo=");

        let hex_claim = "0x04020d62c94296539224b885c6cdf79d0c2dd437471425be26bf62ab522949f83f3eed34528b0b9a7fbe96e50ca85471c894e1aa819bbf12ff78ad07ce8b4117b2";
        let b64_hash = digest_hex_claim(hex_claim).unwrap();
        assert_eq!(b64_hash, "5EhP0859lic41RIpIrnotv/BCR7v5nVcXsXkTXlbuhI=");

        let hex_claim = "0x046bd65449f336b888fc36c64708940da0d1c864a0ac46236f60b455841a4d15c9b815ed725093b3266aaca2f15210d14a1eadf34efeda3bd44a803fbf1590cfba";
        let b64_hash = digest_hex_claim(hex_claim).unwrap();
        assert_eq!(b64_hash, "oseI7fM8wWIYslDUOXJne7AOiK+IpFL3q8MTqiZHWw8=");

        let hex_claim = "0x0412cf2bd4a9613ad988f7f008a5297b8e8c98df8759a2ef9d3dfae63b3870cfbb78d35789745f82710da61a61a9c06c6f6166bf1d5ce73f9416e6b67713001aa2";
        let b64_hash = digest_hex_claim(hex_claim).unwrap();
        assert_eq!(b64_hash, "9Y3JcjUHZLGmENRQpnML/+TG2EbHWjU46h+LtT9sQi8=");

        let hex_claim = "0x04a2e6914db4a81ea9ec72e71b41cf88d4bc19ea54f29ae2beb3db8e4acf6531b5c163e58427831832b10fce899a030d12e82a398d4eeefe451c7e261fba973be4";
        let b64_hash = digest_hex_claim(hex_claim).unwrap();
        assert_eq!(b64_hash, "Llx5F6lP/hbU6ZTT10Q5PF+7o1VdylvrolT8vSHJMAA=");

        let hex_claim = "0x041508189a6f1737f50dd2c603c1ded8a83f97073d33cbb317e7409c1487b8351aa2b89455cda61ce8ed3ba3c130372870b187239b900da8948a53ca3e02db9aaf";
        let b64_hash = digest_hex_claim(hex_claim).unwrap();
        assert_eq!(b64_hash, "MyRpb4ZDTwtJNflc8ZbZdmKOf+fuZjUEZkgZMCmlKxw=");

        let hex_claim = "0x04f11597483032666b20ec51b27e1337577f63a5e1d5962575b555bf899380ae15482f031a297094b0c60980f3c4f1f7ad2346de5357ad82a6a3d4eef2bd1956c6";
        let b64_hash = digest_hex_claim(hex_claim).unwrap();
        assert_eq!(b64_hash, "ytwkzcBixiBMsblxEEPpiDFV6MCBG/IY+XUc6/+xIQ8=");

        let hex_claim = "0x044c01f3d0ef3d60652aa7c6489b2f10edcae1b04a10460ab2d5e4bd752eb0686cac7aa6057fd4c65606e8a4c33c0b519b1764229395cde2c8537ee01136ef0776";
        let b64_hash = digest_hex_claim(hex_claim).unwrap();
        assert_eq!(b64_hash, "VS5c2JQT3x++ltSQHqnCFIBHttdjU2Lk2RuCGkUhnQ8=");
    }

    #[test]
    fn should_hash_compressed_hex_pub_keys() {
        let hex_claim = "0x025a126cbbd3c66b6d542d40d91085e3f2b5db3bbc8cda0d59615deb08784e4f83";
        let b64_hash = digest_hex_claim(hex_claim).unwrap();
        assert_eq!(b64_hash, "3cZFfsN4tUAhkBsnZ9AyGzK0Sg5PLKMvqRHclsxQcCY=");

        let hex_claim = "0x029969c7741ade2e9f89f81d12080651038838e8089682158f3d892e57609b64e2";
        let b64_hash = digest_hex_claim(hex_claim).unwrap();
        assert_eq!(b64_hash, "pKH7yoPwmArs52+sAYP28F2Bbi4amtrVJoe4b6S9dRs=");

        let hex_claim = "0x029622878da186a8a31f4dc03454dbbc62365060458db174618218b51d5014fa56";
        let b64_hash = digest_hex_claim(hex_claim).unwrap();
        assert_eq!(b64_hash, "RPNeqeFnKzLc6GKvi4iA0EmZRAlpp0BpTJkBfvPFmC8=");

        let hex_claim = "0x03e355263aa6cbc99d2fdd0898f5ed8630115ad54e9073c41a8aa0df6d75842d8b";
        let b64_hash = digest_hex_claim(hex_claim).unwrap();
        assert_eq!(b64_hash, "Zk+WTQNF1+88t4qPjLqpO1qexc2fEeSEaetVn7B6OzA=");

        let hex_claim = "0x02020d62c94296539224b885c6cdf79d0c2dd437471425be26bf62ab522949f83f";
        let b64_hash = digest_hex_claim(hex_claim).unwrap();
        assert_eq!(b64_hash, "wJ+U4/1yBMbmnwj8s0im9iQkVaR49EOuN/N2LFyFeBA=");

        let hex_claim = "0x026bd65449f336b888fc36c64708940da0d1c864a0ac46236f60b455841a4d15c9";
        let b64_hash = digest_hex_claim(hex_claim).unwrap();
        assert_eq!(b64_hash, "r1Z6UwB6iX0l0Yx2FzOh8Nzv7VuTKqNF+4eYqcqaXjA=");

        let hex_claim = "0x0212cf2bd4a9613ad988f7f008a5297b8e8c98df8759a2ef9d3dfae63b3870cfbb";
        let b64_hash = digest_hex_claim(hex_claim).unwrap();
        assert_eq!(b64_hash, "8YKaewMj9cIl/gPgITLbrUGYnLCo00pjTF2vFwI6CRc=");

        let hex_claim = "0x02a2e6914db4a81ea9ec72e71b41cf88d4bc19ea54f29ae2beb3db8e4acf6531b5";
        let b64_hash = digest_hex_claim(hex_claim).unwrap();
        assert_eq!(b64_hash, "H+3VsMxmC5VsTSMawhh0kQ0Kt3EKQQl8ISsNp6TCHR8=");

        let hex_claim = "0x031508189a6f1737f50dd2c603c1ded8a83f97073d33cbb317e7409c1487b8351a";
        let b64_hash = digest_hex_claim(hex_claim).unwrap();
        assert_eq!(b64_hash, "Pf/Q2nfiYnrUTS1Pabe1YjwdqLFX6Hc5M4KwZT9Nuxc=");

        let hex_claim = "0x02f11597483032666b20ec51b27e1337577f63a5e1d5962575b555bf899380ae15";
        let b64_hash = digest_hex_claim(hex_claim).unwrap();
        assert_eq!(b64_hash, "D3uiR1w5Vu/7OPZdBZWxjq4FHsPF1vdU8uMsduUD0x0=");

        let hex_claim = "0x024c01f3d0ef3d60652aa7c6489b2f10edcae1b04a10460ab2d5e4bd752eb0686c";
        let b64_hash = digest_hex_claim(hex_claim).unwrap();
        assert_eq!(b64_hash, "6fn61Hoz4P0v8STJSIUdz6GNi1NyyRBCj07qvQLToSw=");
    }

    #[test]
    fn should_return_32_byte_hashes() {
        let hex_claim = "0x04c94699a259ec27e1cf67fe46653f0dc2f38e6d32abb33b45fc9ffe793171a44b4ff5c9517c1be22f8a47915debcf1e512717fe33986f287e79d2f3099725f179";
        let b64_hash = digest_hex_claim(hex_claim).unwrap();
        assert_eq!(b64_hash, "uJM6qiWAIIej9CGonWlR0cU64wqtdlh+csikpC6wSgA=");
        let len = base64::decode(b64_hash)
            .expect("The hash is not a valid base64")
            .len();
        assert_eq!(len, 32);

        let hex_claim = "0x0424a71e7c24b38aaeeebbc334113045885bfae154071426e21c021ebc47a5a85a3a691a76d8253ce6e03bf4e8fe154c89b2d967765bb060e61360305d1b8df7c5";
        let b64_hash = digest_hex_claim(hex_claim).unwrap();
        assert_eq!(b64_hash, "9wxP7eLFnTk5VDsj9rXL63r7QPKTTjCkNhjZri1nEQA=");
        let len = base64::decode(b64_hash)
            .expect("The hash is not a valid base64")
            .len();
        assert_eq!(len, 32);

        let hex_claim = "0x04ff51151c6bd759d723af2d0571df5e794c28b204242f4b540b0d3449eab192cafd44b241c96b39fa7dd7ead2d2265a598a23cba0f54cb79b9829d355d74304a2";
        let b64_hash = digest_hex_claim(hex_claim).unwrap();
        assert_eq!(b64_hash, "iS7BUPgGpY/WAdWyZb0s1wE21tMz5ZWBc8LJ6jgqSwA=");
        let len = base64::decode(b64_hash)
            .expect("The hash is not a valid base64")
            .len();
        assert_eq!(len, 32);

        let hex_claim = "0x043f10ff1b295bf4d2f24c40c93cce04210ae812dd5ad1a06d5dafd9a2e18fa1247bdf36bef6a9e45e97d246cfb8a0ab25c406cf6fe7569b17e83fd6d33563003a";
        let b64_hash = digest_hex_claim(hex_claim).unwrap();
        assert_eq!(b64_hash, "CCxtK0qT7cTxCS7e4uONSHcPQdbQzBqrC3GQvFz4KwA=");
        let len = base64::decode(b64_hash)
            .expect("The hash is not a valid base64")
            .len();
        assert_eq!(len, 32);

        let hex_claim = "0x0409d240a33ca9c486c090135f06c5d801aceec6eaed94b8bef1c9763b6c39708819207786fe92b22c6661957e83923e24a5ba754755b181f82fdaed2ed3914453";
        let b64_hash = digest_hex_claim(hex_claim).unwrap();
        assert_eq!(b64_hash, "3/AaoqHPrz20tfLmhLz4ay5nrlKN5WiuvlDZkfZyfgA=");
        let len = base64::decode(b64_hash)
            .expect("The hash is not a valid base64")
            .len();
        assert_eq!(len, 32);

        let hex_claim = "0x04220da30ddd87fed1b65ef75706507f397138d8cac8917e118157124b7e1cf45b8a38ac8c8b65a6ed662d62b09d100e53abacbc27500bb9d0365f3d6d60a981fa";
        let b64_hash = digest_hex_claim(hex_claim).unwrap();
        assert_eq!(b64_hash, "YiEgjvg1VeCMrlWJkAuOQIgDX1fWtkHk9OBJy225UgA=");
        let len = base64::decode(b64_hash)
            .expect("The hash is not a valid base64")
            .len();
        assert_eq!(len, 32);

        let hex_claim = "0x04acdbbdba45841ddcc1c3cb2e8b696eae69ba9d57686bff0cd58e4033a08d9dc6c272a3577508cdb18bdb1c6fcc818538664bb6dc4cc32ee668198c7be044800c";
        let b64_hash = digest_hex_claim(hex_claim).unwrap();
        assert_eq!(b64_hash, "UPqwKZBMhq21uwgLWJUFMgCBMPzhseiziVaqN4EQvwA=");
        let len = base64::decode(b64_hash)
            .expect("The hash is not a valid base64")
            .len();
        assert_eq!(len, 32);
    }

    #[test]
    fn should_return_32_byte_hashes_from_compressed() {
        let hex_claim = "0x03c94699a259ec27e1cf67fe46653f0dc2f38e6d32abb33b45fc9ffe793171a44b";
        let b64_hash = digest_hex_claim(hex_claim).unwrap();
        assert_eq!(b64_hash, "fKYmOKLR9mG/VnmIg6I2aLe7ysowrTqkLLAfVazfHAs=");
        let len = base64::decode(b64_hash)
            .expect("The hash is not a valid base64")
            .len();
        assert_eq!(len, 32);

        let hex_claim = "0x0324a71e7c24b38aaeeebbc334113045885bfae154071426e21c021ebc47a5a85a";
        let b64_hash = digest_hex_claim(hex_claim).unwrap();
        assert_eq!(b64_hash, "1unO9DU5kr7lbPUT9YyPY/EQcDr2KFyDJGPR3tTPSCs=");
        let len = base64::decode(b64_hash)
            .expect("The hash is not a valid base64")
            .len();
        assert_eq!(len, 32);

        let hex_claim = "0x02ff51151c6bd759d723af2d0571df5e794c28b204242f4b540b0d3449eab192ca";
        let b64_hash = digest_hex_claim(hex_claim).unwrap();
        assert_eq!(b64_hash, "lV353gFkyjwoh8bjmzJ35ndkC2hof7o0+Tw2x9VPYQs=");
        let len = base64::decode(b64_hash)
            .expect("The hash is not a valid base64")
            .len();
        assert_eq!(len, 32);

        let hex_claim = "0x023f10ff1b295bf4d2f24c40c93cce04210ae812dd5ad1a06d5dafd9a2e18fa124";
        let b64_hash = digest_hex_claim(hex_claim).unwrap();
        assert_eq!(b64_hash, "GnkH1v5cCoLRddAJL13rA5BCyaixVzD8Su2x5FEW4iE=");
        let len = base64::decode(b64_hash)
            .expect("The hash is not a valid base64")
            .len();
        assert_eq!(len, 32);

        let hex_claim = "0x0309d240a33ca9c486c090135f06c5d801aceec6eaed94b8bef1c9763b6c397088";
        let b64_hash = digest_hex_claim(hex_claim).unwrap();
        assert_eq!(b64_hash, "DuOZ467hKLeRjJbhuZy/h4s6FnjLRXAJDSPElEYTOwo=");
        let len = base64::decode(b64_hash)
            .expect("The hash is not a valid base64")
            .len();
        assert_eq!(len, 32);

        let hex_claim = "0x02220da30ddd87fed1b65ef75706507f397138d8cac8917e118157124b7e1cf45b";
        let b64_hash = digest_hex_claim(hex_claim).unwrap();
        assert_eq!(b64_hash, "9pAfgqDFOTkUgYmIRDiopFWNgXIb069EPaInKgGLKRA=");
        let len = base64::decode(b64_hash)
            .expect("The hash is not a valid base64")
            .len();
        assert_eq!(len, 32);

        let hex_claim = "0x02acdbbdba45841ddcc1c3cb2e8b696eae69ba9d57686bff0cd58e4033a08d9dc6";
        let b64_hash = digest_hex_claim(hex_claim).unwrap();
        assert_eq!(b64_hash, "oWlFPwaVT762OHFYdgcGbvkDgSwbMqf5DiqdLwlzohE=");
        let len = base64::decode(b64_hash)
            .expect("The hash is not a valid base64")
            .len();
        assert_eq!(len, 32);
    }

    #[test]
    fn should_match_string_and_hex() {
        let str_claim = "Hello";
        let hex_claim = "48656c6c6f"; // Hello
        let b64_hash1 = digest_string_claim(str_claim);
        let b64_hash2 = digest_hex_claim(hex_claim);
        assert_eq!(b64_hash1, b64_hash2);

        let str_claim = "Hello UTF8 ©âëíòÚ ✨";
        let hex_claim = "48656c6c6f205554463820c2a9c3a2c3abc3adc3b2c39a20e29ca8"; // Hello UTF8 ©âëíòÚ ✨
        let b64_hash1 = digest_string_claim(str_claim);
        let b64_hash2 = digest_hex_claim(hex_claim);
        assert_eq!(b64_hash1, b64_hash2);
    }

    #[test]
    fn should_hash_hex_with_0x() {
        let b64_hash1 = digest_hex_claim(
            "48656c6c6f48656c6c6f48656c6c6f48656c6c6f48656c6c6f48656c6c6f48656c6c6f",
        );
        let b64_hash2 = digest_hex_claim(
            "0x48656c6c6f48656c6c6f48656c6c6f48656c6c6f48656c6c6f48656c6c6f48656c6c6f",
        );
        assert_eq!(b64_hash1, b64_hash2);

        let b64_hash1 = digest_hex_claim(
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        );
        let b64_hash2 = digest_hex_claim(
            "0x12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        );
        assert_eq!(b64_hash1, b64_hash2);

        let b64_hash1 = digest_hex_claim(
            "01234567890123456789012345678901234567890123456789012345678901234567890123456789",
        );
        let b64_hash2 = digest_hex_claim(
            "0x01234567890123456789012345678901234567890123456789012345678901234567890123456789",
        );
        assert_eq!(b64_hash1, b64_hash2);

        let b64_hash1 =
            digest_hex_claim("0000000000000000000000000000000000000000000000000000000000000000");
        let b64_hash2 =
            digest_hex_claim("0x0000000000000000000000000000000000000000000000000000000000000000");
        assert_eq!(b64_hash1, b64_hash2);

        let b64_hash1 =
            digest_hex_claim("8888888888888888888888888888888888888888888888888888888888888888");
        let b64_hash2 =
            digest_hex_claim("0x8888888888888888888888888888888888888888888888888888888888888888");
        assert_eq!(b64_hash1, b64_hash2);

        let b64_hash1 =
            digest_hex_claim("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        let b64_hash2 =
            digest_hex_claim("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        assert_eq!(b64_hash1, b64_hash2);

        let b64_hash1 = digest_hex_claim("1234567890123456789012345678901234567890");
        let b64_hash2 = digest_hex_claim("0x1234567890123456789012345678901234567890");
        assert_eq!(b64_hash1, b64_hash2);
    }
}
