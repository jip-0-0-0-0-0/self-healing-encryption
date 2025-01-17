use self_healing_encryption::Encryptor;
use base64::{encode as base64_encode, decode as base64_decode};

#[test]
fn test_encrypt_decrypt() {
    let key = b"thisisatestkey1234567890123456".to_vec();
    let encryptor = Encryptor::new(key.clone());
    let plaintext = b"Hello, World!";
    let ciphertext = encryptor.encrypt(plaintext);
    let decrypted = encryptor.decrypt(&ciphertext);
    assert_eq!(plaintext.to_vec(), decrypted);
}

#[test]
fn test_invalid_decryption() {
    let key = b"anotherkeyforencryption1234567890".to_vec();
    let encryptor = Encryptor::new(key.clone());
    let invalid_ciphertext = b"invalidciphertext";
    let decrypted = encryptor.decrypt(&invalid_ciphertext);
    // Since XOR is symmetric, decrypting invalid ciphertext will produce garbled data
    // This test ensures that decryption does not panic and returns some data
    assert_eq!(decrypted.len(), invalid_ciphertext.len());
}

#[test]
fn test_key_rotation() {
    let key1 = b"initialkeyforencryption1234567890".to_vec();
    let key2 = b"rotatedkeyforencryption1234567890".to_vec();
    let mut encryptor = Encryptor::new(key1.clone());
    let plaintext = b"Key rotation test.";
    let ciphertext1 = encryptor.encrypt(plaintext);
    let decrypted1 = encryptor.decrypt(&ciphertext1);
    assert_eq!(plaintext.to_vec(), decrypted1);
    encryptor.rotate_key(key2.clone());
    let ciphertext2 = encryptor.encrypt(plaintext);
    let decrypted2 = encryptor.decrypt(&ciphertext2);
    assert_eq!(plaintext.to_vec(), decrypted2);
    // Ensure ciphertext1 cannot be decrypted with the new key
    let decrypted_wrong = encryptor.decrypt(&ciphertext1);
    assert_ne!(plaintext.to_vec(), decrypted_wrong);
}
