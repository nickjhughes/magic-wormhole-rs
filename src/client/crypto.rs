use crypto_secretbox::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XSalsa20Poly1305,
};
use hkdf::Hkdf;
use sha2::{
    digest::{generic_array::GenericArray, typenum::U32},
    Digest, Sha256,
};
use std::str::FromStr;

use magic_wormhole::message::Phase;

/// Calculate the SHA256 hash of the given string.
fn sha256_str(input: &str) -> GenericArray<u8, U32> {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hasher.finalize()
}

/// Construct the "purpose" for the message encryption.
fn generate_purpose(side: &str, phase: &Phase) -> Vec<u8> {
    let mut result = String::from_str("wormhole:phase:")
        .unwrap()
        .as_bytes()
        .to_vec();
    result.extend(sha256_str(side));
    result.extend(sha256_str(
        serde_json::to_value(phase).unwrap().as_str().unwrap(),
    ));
    result
}

/// Construct the particular key to use for message encryption.
fn derive_phase_key(key: &[u8], side: &str, phase: &Phase) -> Vec<u8> {
    let purpose = generate_purpose(side, phase);
    let hk = Hkdf::<Sha256>::new(None, key);
    let mut phase_key = [0u8; 42];
    hk.expand(&purpose, &mut phase_key).unwrap();
    phase_key[..crypto_secretbox::SecretBox::<()>::KEY_SIZE].to_vec()
}

/// Encrypt the given message.
pub(crate) fn encrypt_message(message: &str, key: &[u8], side: &str, phase: &Phase) -> Vec<u8> {
    let phase_key = derive_phase_key(key, side, phase);
    let nonce = XSalsa20Poly1305::generate_nonce(&mut OsRng);
    let cipher = XSalsa20Poly1305::new(crypto_secretbox::Key::from_slice(&phase_key));
    let cipher_text = cipher
        .encrypt(&nonce, message.as_bytes())
        .expect("failed to encrypt message");
    {
        // Concatenate nonce and cipher text
        let mut result = nonce.to_vec();
        result.extend(cipher_text);
        result
    }
}

/// Descrypt the given message.
pub(crate) fn decrypt_message(
    message: &[u8],
    key: &[u8],
    side: &str,
    phase: &Phase,
) -> Result<String, crypto_secretbox::Error> {
    let phase_key = derive_phase_key(key, side, phase);
    let (nonce, cipher_text) = message.split_at(crypto_secretbox::SecretBox::<()>::NONCE_SIZE);
    let cipher = XSalsa20Poly1305::new(crypto_secretbox::Key::from_slice(&phase_key));
    let plain_text = cipher.decrypt(crypto_secretbox::Nonce::from_slice(nonce), cipher_text)?;
    Ok(String::from_utf8(plain_text).expect("message is invalid utf-8"))
}

#[cfg(test)]
mod tests {
    use super::{decrypt_message, derive_phase_key, encrypt_message, generate_purpose, Phase};

    #[test]
    fn purpose() {
        let side = "abcd1234";
        let phase = Phase::Version;

        let purpose = generate_purpose(side, &phase);
        assert_eq!(
            purpose,
            vec![
                119, 111, 114, 109, 104, 111, 108, 101, 58, 112, 104, 97, 115, 101, 58, 233, 206,
                231, 26, 185, 50, 253, 232, 99, 51, 141, 8, 190, 77, 233, 223, 227, 158, 160, 73,
                189, 175, 179, 66, 206, 101, 158, 197, 69, 11, 105, 174, 92, 164, 243, 133, 12,
                204, 51, 26, 175, 138, 37, 125, 96, 134, 229, 38, 163, 180, 42, 99, 225, 140, 177,
                29, 2, 8, 71, 152, 91, 49, 209, 136
            ]
        );
    }

    #[test]
    fn phase_key() {
        let key = b"password";
        let side = "abcd1234";
        let phase = Phase::Version;

        let phase_key = derive_phase_key(key, side, &phase);
        assert_eq!(
            phase_key,
            vec![
                237, 218, 144, 42, 103, 199, 244, 239, 96, 138, 231, 203, 191, 38, 177, 107, 31,
                230, 31, 159, 77, 193, 128, 177, 171, 179, 160, 36, 244, 251, 193, 42
            ]
        );
    }

    #[test]
    fn roundtrip_encryption() {
        let key = b"password";
        let side = "abcd1234";
        let phase = Phase::Version;
        let message = "hello";

        let cipher_text = encrypt_message(message, key, side, &phase);
        let plain_text = decrypt_message(&cipher_text, key, side, &phase).unwrap();
        assert_eq!(plain_text, message);
    }
}
