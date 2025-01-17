use self_healing_encryption::Encryptor;
use base64::{encode as base64_encode, decode as base64_decode};
use std::io::{self, Write};

fn main() {
    let encryptor = Encryptor::new(/* Initialize with a key */);
    loop {
        print!("Enter command (encrypt/decrypt/exit): ");
        io::stdout().flush().unwrap();
        let mut command = String::new();
        io::stdin().read_line(&mut command).unwrap();
        let command = command.trim();
        match command {
            "encrypt" => {
                print!("Enter plaintext: ");
                io::stdout().flush().unwrap();
                let mut plaintext = String::new();
                io::stdin().read_line(&mut plaintext).unwrap();
                let ciphertext = encryptor.encrypt(plaintext.trim().as_bytes());
                println!("Ciphertext (Base64): {}", base64_encode(&ciphertext));
            }
            "decrypt" => {
                print!("Enter ciphertext (Base64): ");
                io::stdout().flush().unwrap();
                let mut ciphertext = String::new();
                io::stdin().read_line(&mut ciphertext).unwrap();
                match base64_decode(ciphertext.trim()) {
                    Ok(data) => {
                        let decrypted = encryptor.decrypt(&data);
                        match String::from_utf8(decrypted) {
                            Ok(text) => println!("Decrypted text: {}", text),
                            Err(_) => println!("Decrypted data is not valid UTF-8."),
                        }
                    }
                    Err(_) => println!("Invalid Base64 input."),
                }
            }
            "exit" => {
                println!("Exiting interactive mode.");
                break;
            }
            _ => println!("Unknown command."),
        }
    }
}
