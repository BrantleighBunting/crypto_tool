use clap::{Parser, Subcommand};
use crypto::{chacha20_poly1305_cipher, generate_key, generate_nonce, Rc4};
use std::fs::File;
use std::io::prelude::{Read, Seek, Write};

#[derive(Parser, Debug)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// RC4 file en/decryption (symmetric — same operation for encrypt and decrypt)
    Rc4 {
        #[arg(short, long, required = true, value_name = "FILE_NAME")]
        file: String,

        /// En/Decryption key (hexadecimal bytes)
        #[arg(short, long, required = true, value_name = "HEX_BYTE", num_args = 5..=256)]
        key: Vec<String>,
    },

    /// Generate a random 256-bit key for ChaCha20-Poly1305 (printed as hex bytes)
    Keygen,

    /// ChaCha20-Poly1305 file encryption/decryption
    Chacha {
        #[arg(short, long, required = true, value_name = "FILE_NAME")]
        file: String,

        /// 256-bit key (exactly 32 hexadecimal bytes)
        #[arg(short, long, required = true, value_name = "HEX_BYTE", num_args = 32)]
        key: Vec<String>,

        /// Encrypt the file
        #[arg(long, conflicts_with = "decrypt")]
        encrypt: bool,

        /// Decrypt the file
        #[arg(long, conflicts_with = "encrypt")]
        decrypt: bool,
    },
}

fn parse_hex_key(hex_strings: &[String]) -> Vec<u8> {
    hex_strings
        .iter()
        .map(|s| s.trim_start_matches("0x"))
        .map(|s| u8::from_str_radix(s, 16).expect("Invalid key hex byte!"))
        .collect()
}

fn main() -> std::io::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen => {
            let mut key_bytes = vec![0u8; 32];
            generate_key(&mut key_bytes);
            let hex: Vec<String> = key_bytes.iter().map(|b| format!("{:02x}", b)).collect();
            println!("{}", hex.join(" "));
        }
        Commands::Rc4 { file, key } => {
            let key_bytes = parse_hex_key(&key);

            let mut contents = Vec::new();
            let mut f = File::options().read(true).write(true).open(&file)?;
            f.read_to_end(&mut contents)?;

            Rc4::apply_keystream_static(&key_bytes, &mut contents);

            f.rewind()?;
            f.write_all(&contents)?;

            println!("Processed {}", file);
        }
        Commands::Chacha {
            file,
            key,
            encrypt,
            decrypt,
        } => {
            if !encrypt && !decrypt {
                eprintln!("Error: either --encrypt or --decrypt must be specified");
                std::process::exit(1);
            }

            let key_bytes = parse_hex_key(&key);

            let mut contents = Vec::new();
            let mut f = File::options().read(true).write(true).open(&file)?;
            f.read_to_end(&mut contents)?;

            if encrypt {
                let mut nonce_bytes = [0u8; 12];
                generate_nonce(&mut nonce_bytes);

                let ciphertext =
                    chacha20_poly1305_cipher(&key_bytes, &nonce_bytes, contents, true)
                        .map_err(|_| {
                            std::io::Error::other("Encryption failed")
                        })?;

                // Write nonce (12 bytes) || ciphertext+tag
                f.rewind()?;
                f.set_len(0)?;
                f.write_all(&nonce_bytes)?;
                f.write_all(&ciphertext)?;

                println!("Encrypted {}", file);
            } else {
                // decrypt
                if contents.len() < 12 {
                    eprintln!("Error: file too short to contain a nonce");
                    std::process::exit(1);
                }

                let nonce_bytes: [u8; 12] = contents[..12].try_into().unwrap();
                let ciphertext = contents[12..].to_vec();

                let plaintext =
                    chacha20_poly1305_cipher(&key_bytes, &nonce_bytes, ciphertext, false)
                        .map_err(|_| {
                            std::io::Error::other("Decryption failed")
                        })?;

                f.rewind()?;
                f.set_len(0)?;
                f.write_all(&plaintext)?;

                println!("Decrypted {}", file);
            }
        }
    }

    Ok(())
}
