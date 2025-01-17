# Self-Healing Encryption

A Rust-based self-healing encryption framework featuring custom encryption algorithms, comprehensive key management with backups and rotation, and automated integrity monitoring and recovery.

## 🚀 Features

- **Custom Encryption Algorithm:** Implements a XOR-based cipher with key stretching.
- **Key Management:** Supports multiple backup keys, key versioning, and scheduled key rotations.
- **Self-Healing Mechanism:** Monitors key integrity and automatically recovers or rotates keys upon detecting anomalies.
- **Logging:** Comprehensive logging to both console and log files.
- **Interactive Mode:** Encrypt and decrypt data via command-line interface.
- **Configuration Management:** External JSON configuration file for customizable settings.

## 🛠️ Installation

### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (Ensure Rust and Cargo are installed)

### Steps

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/yourusername/self-healing-encryption
   cd self-healing-encryption
   ```

2. **Build the Project:**

   ```bash
   cargo build --release
   ```

3. **Run the Project:**

   ```bash
   cargo run --release
   ```

   To enter interactive mode:

   ```bash
   cargo run --release -- interactive
   ```

4. **Configure the Application:**

   - Copy the example configuration:

     ```bash
     cp data/config.example.json data/config.json
     ```end

   - Modify `data/config.json` as needed.

## 🔧 Configuration

Modify the `data/config.json` file to adjust settings such as key rotation intervals, logging paths, and encryption algorithms.

**Example Configuration:**

```json
{
    "key_store_path": "data/keystore.json",
    "log_path": "data/logs/encryption.log",
    "monitoring_interval_seconds": 60,
    "key_rotation_interval_days": 30,
    "encryption_algorithm": "custom_xor",
    "backup_key_count": 3,
    "max_key_versions": 5
}
```

## 🧪 Testing

Run tests using Cargo:

```bash
cargo test
```

## 📜 License

This project is licensed under the [MIT License](LICENSE).

## 📌 Best Practices

- **Secure the Keystore:** Ensure that `keystore.json` is stored securely and not exposed publicly.
- **Regular Key Rotation:** Follow the configured key rotation intervals to maintain security.
- **Monitor Logs:** Regularly review log files for any unusual activities or errors.
- **Backup Configuration:** Keep backups of your configuration files and keystore in secure locations.

## 🔍 Troubleshooting

- **Missing Directories:** Ensure that the `data/` and `data/logs/` directories exist. The application should create them automatically, but verify permissions if issues arise.
- **Invalid Configuration:** Ensure that `config.json` is correctly formatted in JSON and contains valid parameters.
- **Permission Issues:** Run the application with appropriate permissions to read/write necessary files.

