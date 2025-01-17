use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime},
};
use chrono::{DateTime, Utc};
use log::{error, info, warn};
use simplelog::*;
use base64::{encode as base64_encode, decode as base64_decode};
use hex::{encode as hex_encode, decode as hex_decode};
use std::collections::HashMap;
use std::env;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Config {
    key_store_path: String,
    log_path: String,
    monitoring_interval_seconds: u64,
    key_rotation_interval_days: u64,
    encryption_algorithm: String,
    backup_key_count: usize,
    max_key_versions: usize,
}

impl Config {
    fn load_from_file(path: &str) -> std::io::Result<Self> {
        let mut file = File::open(path)?;
        let mut data = String::new();
        file.read_to_string(&mut data)?;
        let config: Config = serde_json::from_str(&data).unwrap();
        Ok(config)
    }

    fn save_to_file(&self, path: &str) -> std::io::Result<()> {
        let serialized = serde_json::to_string_pretty(self).unwrap();
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        file.write_all(serialized.as_bytes())?;
        Ok(())
    }

    fn default_config() -> Self {
        Config {
            key_store_path: "data/keystore.json".to_string(),
            log_path: "data/logs/encryption.log".to_string(),
            monitoring_interval_seconds: 60,
            key_rotation_interval_days: 30,
            encryption_algorithm: "custom_xor".to_string(),
            backup_key_count: 3,
            max_key_versions: 5,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct KeyVersion {
    version: u32,
    key: String,
    backup_keys: Vec<String>,
    created_at: DateTime<Utc>,
    hash: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct KeyStore {
    versions: Vec<KeyVersion>,
}

impl KeyStore {
    fn new(config: &Config) -> Self {
        let mut rng = rand::thread_rng();
        let key: String = (0..32).map(|_| rng.gen::<char>()).collect();
        let mut backup_keys = Vec::new();
        for _ in 0..config.backup_key_count {
            let backup_key: String = (0..32).map(|_| rng.gen::<char>()).collect();
            backup_keys.push(backup_key);
        }
        let mut hasher = Sha256::new();
        hasher.update(&key);
        for bk in &backup_keys {
            hasher.update(bk);
        }
        let hash = hex_encode(hasher.finalize());
        let initial_version = KeyVersion {
            version: 1,
            key: key.clone(),
            backup_keys,
            created_at: Utc::now(),
            hash,
        };
        KeyStore {
            versions: vec![initial_version],
        }
    }

    fn save_to_file(&self, path: &str) -> std::io::Result<()> {
        let serialized = serde_json::to_string_pretty(self).unwrap();
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        file.write_all(serialized.as_bytes())?;
        info!("KeyStore saved to {}", path);
        Ok(())
    }

    fn load_from_file(path: &str) -> std::io::Result<Self> {
        let mut file = File::open(path)?;
        let mut data = String::new();
        file.read_to_string(&mut data)?;
        let keystore: KeyStore = serde_json::from_str(&data).unwrap();
        Ok(keystore)
    }

    fn validate_latest_version(&self) -> bool {
        if let Some(latest) = self.versions.last() {
            let mut hasher = Sha256::new();
            hasher.update(&latest.key);
            for bk in &latest.backup_keys {
                hasher.update(bk);
            }
            let computed_hash = hex_encode(hasher.finalize());
            if computed_hash == latest.hash {
                info!("KeyStore integrity validated for version {}", latest.version);
                true
            } else {
                warn!(
                    "KeyStore integrity check failed for version {}",
                    latest.version
                );
                false
            }
        } else {
            error!("KeyStore is empty.");
            false
        }
    }

    fn recover_latest_version(&mut self) -> bool {
        if let Some(latest) = self.versions.last_mut() {
            if !self.validate_latest_version() {
                info!(
                    "Attempting to recover key for version {} using backup keys.",
                    latest.version
                );
                for bk in &latest.backup_keys {
                    latest.key = bk.clone();
                    let mut hasher = Sha256::new();
                    hasher.update(&latest.key);
                    for backup in &latest.backup_keys {
                        hasher.update(backup);
                    }
                    latest.hash = hex_encode(hasher.finalize());
                    if self.save_to_file("data/keystore.json").is_ok() {
                        info!("Recovery successful for version {}", latest.version);
                        return true;
                    }
                }
                false
            } else {
                false
            }
        } else {
            false
        }
    }

    fn rotate_keys(&mut self, config: &Config) {
        let new_version_number = self.versions.len() as u32 + 1;
        let mut rng = rand::thread_rng();
        let new_key: String = (0..32).map(|_| rng.gen::<char>()).collect();
        let mut new_backup_keys = Vec::new();
        for _ in 0..config.backup_key_count {
            let backup_key: String = (0..32).map(|_| rng.gen::<char>()).collect();
            new_backup_keys.push(backup_key);
        }
        let mut hasher = Sha256::new();
        hasher.update(&new_key);
        for bk in &new_backup_keys {
            hasher.update(bk);
        }
        let new_hash = hex_encode(hasher.finalize());
        let new_version = KeyVersion {
            version: new_version_number,
            key: new_key,
            backup_keys: new_backup_keys,
            created_at: Utc::now(),
            hash: new_hash,
        };
        self.versions.push(new_version);
        if self.versions.len() > config.max_key_versions {
            self.versions.remove(0);
        }
        if let Err(e) = self.save_to_file("data/keystore.json") {
            error!("Failed to rotate keys: {}", e);
        } else {
            info!("Keys rotated to version {}", new_version_number);
        }
    }

    fn get_latest_key(&self) -> Option<&KeyVersion> {
        self.versions.last()
    }
}

struct Encryptor {
    key: Vec<u8>,
}

impl Encryptor {
    fn new(key: Vec<u8>) -> Self {
        Encryptor { key }
    }

    fn key_stretching(&self) -> Vec<u8> {
        let mut stretched = self.key.clone();
        for _ in 0..1000 {
            stretched = Sha256::digest(&stretched).to_vec();
        }
        stretched
    }

    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let stretched_key = self.key_stretching();
        plaintext
            .iter()
            .enumerate()
            .map(|(i, byte)| byte ^ stretched_key[i % stretched_key.len()])
            .collect()
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        self.encrypt(ciphertext)
    }

    fn rotate_key(&mut self, new_key: Vec<u8>) {
        self.key = new_key;
        info!("Encryptor key rotated.");
    }
}

struct SelfHealer {
    keystore: Arc<Mutex<KeyStore>>,
    encryptor: Arc<Mutex<Encryptor>>,
    config: Config,
}

impl SelfHealer {
    fn new(
        keystore: Arc<Mutex<KeyStore>>,
        encryptor: Arc<Mutex<Encryptor>>,
        config: Config,
    ) -> SelfHealer {
        SelfHealer {
            keystore,
            encryptor,
            config,
        }
    }

    fn start_monitoring(&self) {
        let keystore = Arc::clone(&self.keystore);
        let encryptor = Arc::clone(&self.encryptor);
        let config = self.config.clone();
        thread::spawn(move || {
            let rotation_interval = Duration::from_secs(config.key_rotation_interval_days * 86400);
            loop {
                {
                    let mut ks = keystore.lock().unwrap();
                    if !ks.validate_latest_version() {
                        warn!("Self-Healing: KeyStore integrity compromised.");
                        if ks.recover_latest_version() {
                            if let Some(latest) = ks.get_latest_key() {
                                let mut enc = encryptor.lock().unwrap();
                                let key_bytes = latest.key.clone().into_bytes();
                                enc.rotate_key(key_bytes);
                                info!(
                                    "Self-Healing: Encryptor updated with recovered key for version {}.",
                                    latest.version
                                );
                            }
                        } else {
                            warn!("Self-Healing: Recovery failed. Rotating keys.");
                            ks.rotate_keys(&config);
                            if let Some(latest) = ks.get_latest_key() {
                                let mut enc = encryptor.lock().unwrap();
                                let key_bytes = latest.key.clone().into_bytes();
                                enc.rotate_key(key_bytes);
                                info!(
                                    "Self-Healing: Encryptor updated with new key for version {}.",
                                    latest.version
                                );
                            }
                        }
                    } else {
                        info!("Self-Healing: KeyStore integrity verified.");
                    }
                    if let Some(latest) = ks.get_latest_key() {
                        let elapsed = latest.created_at.elapsed().unwrap_or(Duration::from_secs(0));
                        if elapsed >= rotation_interval {
                            info!("Self-Healing: Key rotation interval reached. Rotating keys.");
                            ks.rotate_keys(&config);
                            if let Some(new_latest) = ks.get_latest_key() {
                                let mut enc = encryptor.lock().unwrap();
                                let key_bytes = new_latest.key.clone().into_bytes();
                                enc.rotate_key(key_bytes);
                                info!(
                                    "Self-Healing: Encryptor updated with new key for version {}.",
                                    new_latest.version
                                );
                            }
                        }
                    }
                }
                thread::sleep(Duration::from_secs(config.monitoring_interval_seconds));
            }
        });
    }
}

fn init_logger(log_path: &str) {
    CombinedLogger::init(vec![
        TermLogger::new(
            LevelFilter::Info,
            ConfigBuilder::new()
                .set_time_format_str("%Y-%m-%d %H:%M:%S")
                .build(),
            TerminalMode::Mixed,
            ColorChoice::Auto,
        ),
        WriteLogger::new(
            LevelFilter::Debug,
            Config::default(),
            OpenOptions::new()
                .create(true)
                .write(true)
                .append(true)
                .open(log_path)
                .unwrap(),
        ),
    ])
    .unwrap();
}

fn ensure_directory(path: &str) {
    if !Path::new(path).exists() {
        fs::create_dir_all(path).expect(&format!("Failed to create directory: {}", path));
        info!("Created directory: {}", path);
    }
}

fn setup_logging(log_path: &str) {
    ensure_directory(log_path);
    init_logger(log_path);
}

fn main() {
    let config_path = "data/config.json";
    let config = if Path::new(config_path).exists() {
        match Config::load_from_file(config_path) {
            Ok(cfg) => {
                info!("Configuration loaded from {}", config_path);
                cfg
            }
            Err(e) => {
                error!(
                    "Failed to load configuration from {}: {}. Using default configuration.",
                    config_path, e
                );
                Config::default_config()
            }
        }
    } else {
        info!("No configuration file found. Creating default configuration.");
        let cfg = Config::default_config();
        ensure_directory("data");
        if let Err(e) = cfg.save_to_file(config_path) {
            error!("Failed to save default configuration: {}", e);
        }
        cfg
    };

    setup_logging(&config.log_path);
    ensure_directory("data");
    ensure_directory("data/logs");

    let keystore = if Path::new(&config.key_store_path).exists() {
        match KeyStore::load_from_file(&config.key_store_path) {
            Ok(mut ks) => {
                if !ks.validate_latest_version() {
                    warn!("Main: KeyStore integrity compromised. Attempting recovery.");
                    if ks.recover_latest_version() {
                        info!("Main: Recovery successful.");
                        ks
                    } else {
                        warn!("Main: Recovery failed. Rotating keys.");
                        ks.rotate_keys(&config);
                        ks
                    }
                } else {
                    info!("Main: KeyStore loaded and verified.");
                    ks
                }
            }
            Err(e) => {
                error!(
                    "Main: Failed to load KeyStore from {}: {}",
                    config.key_store_path, e
                );
                info!("Main: Creating a new KeyStore.");
                let ks = KeyStore::new(&config);
                if let Err(e) = ks.save_to_file(&config.key_store_path) {
                    error!("Main: Failed to save new KeyStore: {}", e);
                }
                ks
            }
        }
    } else {
        info!("Main: No existing KeyStore found. Creating a new one.");
        let ks = KeyStore::new(&config);
        if let Err(e) = ks.save_to_file(&config.key_store_path) {
            error!("Main: Failed to save new KeyStore: {}", e);
        }
        ks
    };

    let latest_key = keystore.get_latest_key().expect("No key available in KeyStore.");
    let encryptor = Encryptor::new(latest_key.key.clone().into_bytes());

    let keystore_arc = Arc::new(Mutex::new(keystore));
    let encryptor_arc = Arc::new(Mutex::new(encryptor));

    let healer = SelfHealer::new(
        Arc::clone(&keystore_arc),
        Arc::clone(&encryptor_arc),
        config.clone(),
    );
    healer.start_monitoring();

    let plaintext = b"Sensitive data that needs encryption.";
    let ciphertext = {
        let enc = encryptor_arc.lock().unwrap();
        enc.encrypt(plaintext)
    };
    info!("Plaintext: {}", String::from_utf8_lossy(plaintext));
    info!("Ciphertext: {}", base64_encode(&ciphertext));

    let decrypted = {
        let enc = encryptor_arc.lock().unwrap();
        enc.decrypt(&ciphertext)
    };
    match String::from_utf8(decrypted.clone()) {
        Ok(text) => info!("Decrypted: {}", text),
        Err(_) => warn!("Decrypted data is not valid UTF-8."),
    }

    let args: Vec<String> = env::args().collect();
    if args.len() > 1 && args[1] == "interactive" {
        let keystore_clone = Arc::clone(&keystore_arc);
        let encryptor_clone = Arc::clone(&encryptor_arc);
        thread::spawn(move || loop {
            println!("Enter command (encrypt/decrypt/exit):");
            let mut command = String::new();
            std::io::stdin().read_line(&mut command).unwrap();
            let command = command.trim();
            if command == "encrypt" {
                println!("Enter plaintext:");
                let mut input = String::new();
                std::io::stdin().read_line(&mut input).unwrap();
                let input = input.trim().as_bytes();
                let ciphertext = {
                    let enc = encryptor_clone.lock().unwrap();
                    enc.encrypt(input)
                };
                println!("Ciphertext (Base64): {}", base64_encode(&ciphertext));
                info!("User encrypted data.");
            } else if command == "decrypt" {
                println!("Enter ciphertext (Base64):");
                let mut input = String::new();
                std::io::stdin().read_line(&mut input).unwrap();
                let input = input.trim();
                match base64_decode(input) {
                    Ok(data) => {
                        let decrypted = {
                            let enc = encryptor_clone.lock().unwrap();
                            enc.decrypt(&data)
                        };
                        match String::from_utf8(decrypted.clone()) {
                            Ok(text) => {
                                println!("Decrypted text: {}", text);
                                info!("User decrypted data.");
                            }
                            Err(_) => {
                                println!("Decrypted data is not valid UTF-8.");
                                warn!("User attempted to decrypt invalid UTF-8 data.");
                            }
                        }
                    }
                    Err(_) => {
                        println!("Invalid Base64 input.");
                        warn!("User provided invalid Base64 input.");
                    }
                }
            } else if command == "exit" {
                println!("Exiting interactive mode.");
                break;
            } else {
                println!("Unknown command.");
            }
        });
    }

    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}
