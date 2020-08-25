use num_bigint::BigInt;

/// Transforms a hex string into a byte array. The hex string may start with "0x" or not.
pub fn decode_hex_string(hex_string: &str) -> Result<Vec<u8>, String> {
    // skip 0x
    let hex_string: &str = if hex_string.starts_with("0x") {
        &hex_string[2..]
    } else {
        hex_string
    };

    if hex_string == "0" {
        return Ok(vec![0]);
    };

    hex::decode(hex_string)
        .map_err(|err| format!("The given value is not a valid hex string: {}", err))
}

/// Pads the given big integer into a 32-byte array using Little Endian encoding
pub fn pad_bigint_le(num: &BigInt) -> Vec<u8> {
    let mut claim_bytes = num.to_bytes_le().1;
    while claim_bytes.len() < 32 {
        claim_bytes.push(0);
    }
    claim_bytes
}

/// Pads the given big integer into a 32-byte array using Big Endian encoding
pub fn pad_bigint_be(num: &BigInt) -> Vec<u8> {
    let mut claim_bytes = num.to_bytes_be().1;
    while claim_bytes.len() < 32 {
        claim_bytes = [&[0], &claim_bytes[..]].concat();
    }
    claim_bytes
}

///////////////////////////////////////////////////////////////////////////////
// TESTS
///////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::{Sign, ToBigInt};

    #[test]
    fn should_decode_hex_strings() {
        let bytes = decode_hex_string("0x0").unwrap();
        assert_eq!(bytes.len(), 1);
        assert_eq!(bytes[0], 0);

        let bytes = decode_hex_string("0x00000000").unwrap();
        assert_eq!(bytes.len(), 4);
        assert_eq!(bytes[0], 0);

        let bytes = decode_hex_string("0x10").unwrap();
        assert_eq!(bytes.len(), 1);
        assert_eq!(bytes[0], 0x10);

        let bytes = decode_hex_string("0xff").unwrap();
        assert_eq!(bytes.len(), 1);
        assert_eq!(bytes[0], 0xff);

        let bytes = decode_hex_string("0xffff").unwrap();
        assert_eq!(bytes.len(), 2);
        assert_eq!(bytes[0], 0xff);
        assert_eq!(bytes[1], 0xff);

        let bytes = decode_hex_string("0xffffffff").unwrap();
        assert_eq!(bytes.len(), 4);
        assert_eq!(bytes[0], 0xff);
        assert_eq!(bytes[1], 0xff);
        assert_eq!(bytes[2], 0xff);
        assert_eq!(bytes[3], 0xff);

        let bytes = decode_hex_string("0x5555555555555555").unwrap();
        assert_eq!(bytes.len(), 8);
        assert_eq!(bytes[0], 0x55);
        assert_eq!(bytes[1], 0x55);
        assert_eq!(bytes[2], 0x55);
        assert_eq!(bytes[3], 0x55);
        assert_eq!(bytes[4], 0x55);
        assert_eq!(bytes[5], 0x55);
        assert_eq!(bytes[6], 0x55);
        assert_eq!(bytes[7], 0x55);

        let bytes = decode_hex_string("0x0123456789abcdef").unwrap();
        assert_eq!(bytes.len(), 8);
        assert_eq!(bytes[0], 0x01);
        assert_eq!(bytes[1], 0x23);
        assert_eq!(bytes[2], 0x45);
        assert_eq!(bytes[3], 0x67);
        assert_eq!(bytes[4], 0x89);
        assert_eq!(bytes[5], 0xab);
        assert_eq!(bytes[6], 0xcd);
        assert_eq!(bytes[7], 0xef);
    }

    #[test]
    fn should_decode_hex_strings_without_0x() {
        let bytes = decode_hex_string("0").unwrap();
        assert_eq!(bytes.len(), 1);
        assert_eq!(bytes[0], 0);

        let bytes = decode_hex_string("00000000").unwrap();
        assert_eq!(bytes.len(), 4);
        assert_eq!(bytes[0], 0);

        let bytes = decode_hex_string("10").unwrap();
        assert_eq!(bytes.len(), 1);
        assert_eq!(bytes[0], 0x10);

        let bytes = decode_hex_string("ff").unwrap();
        assert_eq!(bytes.len(), 1);
        assert_eq!(bytes[0], 0xff);

        let bytes = decode_hex_string("ffff").unwrap();
        assert_eq!(bytes.len(), 2);
        assert_eq!(bytes[0], 0xff);
        assert_eq!(bytes[1], 0xff);

        let bytes = decode_hex_string("ffffffff").unwrap();
        assert_eq!(bytes.len(), 4);
        assert_eq!(bytes[0], 0xff);
        assert_eq!(bytes[1], 0xff);
        assert_eq!(bytes[2], 0xff);
        assert_eq!(bytes[3], 0xff);

        let bytes = decode_hex_string("5555555555555555").unwrap();
        assert_eq!(bytes.len(), 8);
        assert_eq!(bytes[0], 0x55);
        assert_eq!(bytes[1], 0x55);
        assert_eq!(bytes[2], 0x55);
        assert_eq!(bytes[3], 0x55);
        assert_eq!(bytes[4], 0x55);
        assert_eq!(bytes[5], 0x55);
        assert_eq!(bytes[6], 0x55);
        assert_eq!(bytes[7], 0x55);

        let bytes = decode_hex_string("0x0123456789abcdef").unwrap();
        assert_eq!(bytes.len(), 8);
        assert_eq!(bytes[0], 0x01);
        assert_eq!(bytes[1], 0x23);
        assert_eq!(bytes[2], 0x45);
        assert_eq!(bytes[3], 0x67);
        assert_eq!(bytes[4], 0x89);
        assert_eq!(bytes[5], 0xab);
        assert_eq!(bytes[6], 0xcd);
        assert_eq!(bytes[7], 0xef);
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
}
