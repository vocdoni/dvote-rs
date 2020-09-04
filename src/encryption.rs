pub mod symmetric {
    use rand::{thread_rng, RngCore};
    use sha2::{Digest, Sha256};
    use sodalite::{secretbox, secretbox_open, SecretboxKey, SecretboxNonce};
    use std::convert::TryInto;

    const CIPHER_TEXT_PADDING: [u8; 16] = [0u8; 16];
    const PAYLOAD_PADDING: [u8; 32] = [0u8; 32];

    /// Encrypts the given message with the given passphrase using SecretBox and returns a buffer containing `nonce[24] + cipherText[]`.
    /// The 24 first bytes represent the nonce, and the rest of the buffer contains the cipher text.
    /// The 16 first bytes of the cipher text are trimmed out (they just contain zeroes)
    pub fn encrypt(message: &str, passphrase: &str) -> Result<std::vec::Vec<u8>, String> {
        let key = digest_passphrase(passphrase)?;
        let (cipher_text, nonce) = encrypt_raw(message, key)?;

        // return <nonce-24> + <encrypted-bytes>
        Ok([&nonce[..], &cipher_text[..]].concat())
    }

    /// Decrypts the given buffer containing `nonce[24] + cipherText[]` with the given passphrase using SecretBox
    pub fn decrypt(cipher_bytes: &std::vec::Vec<u8>, passphrase: &str) -> Result<String, String> {
        // Extract the nonce (24 bytes)
        let mut nonce: SecretboxNonce = [0_u8; 24];
        for i in 0..nonce.len() {
            nonce[i] = cipher_bytes[i];
        }
        // extract the original cipher text
        let cipher_text = &cipher_bytes[24..].to_vec();

        let key = digest_passphrase(passphrase)?;
        let decrypted_bytes = decrypt_raw(cipher_text, nonce, key)?;
        let result = String::from_utf8(decrypted_bytes)
            .map_err(|err| format!("Could not decode the original message: {}", err))?;
        Ok(result)
    }

    /// Encrypts the given message with the given 32 byte key using SecretBox and returns a buffer containing `nonce[24] + cipherText[]`.
    /// The 24 first bytes represent the nonce, and the rest of the buffer contains the cipher text.
    /// The 16 first bytes of the cipher text are trimmed out (they just contain zeroes)
    pub fn encrypt_raw(
        message: &str,
        key: SecretboxKey,
    ) -> Result<(std::vec::Vec<u8>, SecretboxNonce), String> {
        let mut rng = thread_rng();
        let message_bytes = message.as_bytes();

        let payload = [&PAYLOAD_PADDING[..], &message_bytes[..]].concat();

        let mut nonce = [0u8; 24];
        rng.fill_bytes(&mut nonce);

        let mut encrypted_bytes = vec![0u8; 32 + message_bytes.len()];
        secretbox(&mut encrypted_bytes, &payload, &nonce, &key)
            .map_err(|_| "Could not encrypt the payload".to_string())?;

        // Skip the first 16 bytes of zeroes
        // Libsodium does need this to work, but the rest of libraries don't
        let trimmed_bytes = encrypted_bytes.split_at(16).1;
        Ok((trimmed_bytes.to_vec(), nonce))
    }

    /// Decrypts the given buffer containing `nonce[24] + cipherText[]` with the given 32 byte key using SecretBox
    pub fn decrypt_raw(
        cipher_bytes: &std::vec::Vec<u8>,
        nonce: SecretboxNonce,
        key: SecretboxKey,
    ) -> Result<std::vec::Vec<u8>, String> {
        // Prepend 16 bytes of zeroes, so that the cipher text matches the expected input format
        let cipher_bytes = [&CIPHER_TEXT_PADDING[..], &cipher_bytes[..]].concat();
        let mut decrypted_bytes = vec![0u8; cipher_bytes.len()];

        secretbox_open(&mut decrypted_bytes, &cipher_bytes, &nonce, &key)
            .map_err(|_| "Could not open the secret box".to_string())?;
        Ok(decrypted_bytes.split_at(32).1.to_vec())
    }

    /// Transforms the given passphrase into a fixed-size buffer to be used as an encryption key
    pub fn digest_passphrase(passphrase: &str) -> Result<SecretboxKey, String> {
        let mut hasher = Sha256::new();
        hasher.input(passphrase.as_bytes());
        let key_buffer = hasher.result();

        key_buffer
            .as_slice()
            .try_into()
            .map_err(|err| format!("Cannot fit the buffer into 32 bytes: {}", err))
    }
}

///////////////////////////////////////////////////////////////////////////////
// TESTS
///////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::symmetric::*;
    use rand::{thread_rng, RngCore};

    #[test]
    fn should_encrypt_and_decrypt_raw_bytes() {
        let mut rng = thread_rng();
        let messages = vec![
            "Hello there, I am super secret",
            "Super secret",
            "Super super super super secret",
            "The meaning of life is...",
            "The universe is indeed...",
        ];

        for message in messages.iter() {
            let mut key = [0u8; 32];
            rng.fill_bytes(&mut key); // random key
            let (encrypted_bytes, nonce) = encrypt_raw(&message, key).unwrap();
            let decrypted_bytes = decrypt_raw(&encrypted_bytes, nonce, key).unwrap();
            let decrypted_message = String::from_utf8(decrypted_bytes.to_vec()).unwrap();
            assert_eq!(&decrypted_message, message);
        }
    }

    #[test]
    fn should_encrypt_and_decrypt_strings() {
        let messages = vec![
            "Hello there, I am super secret",
            "Super secret",
            "Super super super super secret",
            "The meaning of life is...",
            "The universe is indeed...",
        ];
        let keys = vec![
            "I am a passphrase",
            "Do not use without prior permission",
            "Please, don't crack me",
        ];

        for message in messages.iter() {
            for key in keys.iter() {
                let encrypted_bytes = encrypt(&message, &key).unwrap();
                let decrypted_message = decrypt(&encrypted_bytes, key).unwrap();
                assert_eq!(&decrypted_message, message);
            }
        }
    }

    #[test]
    fn should_decrypt_payloads_from_pineacl() {
        // 1
        let encrypted_b64 = "QCBYWqHesUX8ayKDgN5mDMu2FVyV1o+qgYrOl2ltF6WtUqH/AOql5iBg5/hMyZKUvgoYCIGyKnwhDOSKOm4oljuB0jIfjgGk8LQx1Elo7G5lKyIOWuzuRaJt7p4mMgySFy13gEVtssGm/qjO";
        let passphrase = "Top secret";
        let expected_message =
            "Change is a tricky thing, it threatens what we find familiar with...";

        let encrypted_bytes = base64::decode(encrypted_b64).unwrap();
        let decrypted_message = decrypt(&encrypted_bytes, passphrase).unwrap();
        assert_eq!(decrypted_message, expected_message);

        // 2
        let encrypted_b64 = "88x7SFd7Y9kffc/AY1rhGLspg5jTuzz8EpDUJxQjMzAc9RgSOalaIhfxGBGwBp4sRbKCepq7TrVlJ43NYKwXpgRAEhHgTdyqHH81ViYj3cMDOH4PnPiIomub6+qg1oyd86qbhNWjEQsE0CnH";
        let passphrase = "Top secret";
        let expected_message =
            "Changes are a hacky thing that threaten what we are familiar with...";

        let encrypted_bytes = base64::decode(encrypted_b64).unwrap();
        let decrypted_message = decrypt(&encrypted_bytes, passphrase).unwrap();
        assert_eq!(decrypted_message, expected_message);

        // 3
        let encrypted_b64 = "SbhufHJv22HWK9Siy6ZXpRnRqodMTRMSw7zgKJQ0y9oL5nNg3GxpSexa7t3kKX70xbh7cTdnxIcIHfEAdLle7O0hhjyHqLe6X1vcpNemQx1yT9Dom5KJSQ3Iu2NULZHwTImxD7cVw6mjWJW8";
        let passphrase = "Ultra top secret";
        let expected_message =
            "Change is a tricky thing, it threatens what we find familiar with...";

        let encrypted_bytes = base64::decode(encrypted_b64).unwrap();
        let decrypted_message = decrypt(&encrypted_bytes, passphrase).unwrap();
        assert_eq!(decrypted_message, expected_message);

        // 4
        let encrypted_b64 = "OGiaEN1OpjOywrXCOpyluzRDTsPo8bahvKdJZL7zcXBj6hxxuJ+lJ03jSUkQd7ghQ5gBiNfSq9PETNb/6ZpT++rj1h4ROLU/TCsZWLwquET9FGLKG4GW15X+EYIqKFDLPHiPulE4skKlH/2d";
        let passphrase = "Ultra top secret";
        let expected_message =
            "Changes are a hacky thing that threaten what we are familiar with...";

        let encrypted_bytes = base64::decode(encrypted_b64).unwrap();
        let decrypted_message = decrypt(&encrypted_bytes, passphrase).unwrap();
        assert_eq!(decrypted_message, expected_message);
    }

    #[test]
    fn should_digest_passphrases() {
        let passphrases = vec![
            "Hello",
            "12341234",
            "Password",
            "I am another passphrase",
            "More passphrases",
            "Super very hard passphrase",
            "161%854078sdf80bsA(SN",
            "%¬1$(/$·(73$)&(2304987 asg98 sD(F ∂ß",
        ];
        let mut keys = Vec::<String>::new();

        for p in passphrases {
            let key = digest_passphrase(p).unwrap();
            let key = hex::encode(key);
            for k in keys.iter() {
                assert_ne!(k, &key);
            }
            keys.push(key);
        }
    }
}
