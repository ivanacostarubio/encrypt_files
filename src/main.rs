/* TODO:
 *  - Skip .DS_Store ?
 *
 */

use std::fs;
use std::fs::File;

extern crate base64;

extern crate crypto;
use self::crypto::digest::Digest;
use self::crypto::sha2::Sha256;

extern crate aesstream;
extern crate rand;

use aesstream::{AesReader, AesWriter};
use crypto::aessafe::{AesSafe128Decryptor, AesSafe128Encryptor};

use rand::{OsRng, Rng};

use std::io::{Cursor, Read, Write};

#[derive(Debug)]
struct IFile {
    path: String,
    file_name: String,
}

struct Configuration {
    folder_to_encrypt: String,
    encrypted_folder: String,
    decrypted_folder: String,
}

fn generate_config() -> Configuration {
    Configuration {
        folder_to_encrypt: "/Users/ivan/code/rust/list_all_files/examples/".to_string(),
        encrypted_folder: "/Users/ivan/code/rust/list_all_files/encrypted/".to_string(),
        decrypted_folder: "/Users/ivan/code/rust/list_all_files/decrypted/".to_string(),
    }
}

fn key_file() -> String {
    let p = "/Users/ivan/code/rust/list_all_files/key";

    if let Ok(file) = File::open(p) {
        let mut contents = String::new();
        let mut f = file;
        f.read_to_string(&mut contents);
        return contents;
    } else {
        // TODO: WHAT IS UP WITH THIS
        return String::from("error");
    }
}

impl IFile {
    fn file_string(&self) -> String {
        let p = &self.path;

        if let Ok(file) = File::open(p) {
            let mut contents = String::new();
            let mut f = file;
            f.read_to_string(&mut contents);
            return contents;
        } else {
            // TODO: WHAT IS UP WITH THIS
            return String::from("error");
        }
    }

    fn sha_256(&self) -> String {
        let mut hasher = Sha256::new();

        hasher.input_str(&self.file_string());

        let hex = hasher.result_str();
        return hex;
    }

    fn save_encrypted(&self) -> std::io::Result<()> {
        let encrypted_text = self.encrypt();

        let config = generate_config();

        let mut full_name = config.encrypted_folder;

        let file_name: &str = &self.file_name;

        full_name.push_str(file_name);

        println!("path to save: {:?}", full_name);
        println!("{:?}", encrypted_text);

        let mut file = File::create(full_name)?;
        file.write_all(encrypted_text.as_bytes());
        Ok(())
    }

    fn save_decrypted(&self) -> std::io::Result<()> {
        let d_text = self.decrypt();

        let config = generate_config();

        let mut full_name = config.decrypted_folder;

        let file_name: &str = &self.file_name;

        full_name.push_str(file_name);

        let mut file = File::create(full_name)?;
        file.write_all(d_text.as_bytes());
        Ok(())
    }

    fn encrypt(&self) -> String {
        let key: [u8; 16] = self.gen_key();

        let encryptor = AesSafe128Encryptor::new(&key);
        let mut encrypted = Vec::new();

        {
            let mut writer = AesWriter::new(&mut encrypted, encryptor).unwrap();
            writer.write_all(self.file_string().as_bytes()).unwrap();
        }

        let base64_encoded = base64::encode(&encrypted);
        println!("{:<20} {:?}", "base64 encrypted", base64_encoded);

        return base64_encoded;
    }

    fn decrypt(&self) -> String {
        let b = self.file_string().clone();

        //println!("{: <20} {:?}", "TEXT TO DECRYPT B64 BASE", b);

        match base64::decode(&b) {
            Ok(encrypted) => {
                //println!("{: <20} {:?}", "ENCRYPTED", encrypted);
                //println!("{: <20} {:?}", "KEY ():", self.key());

                let gen_key: [u8; 16] = self.key();

                //println!("{: <20} {:?}", "KEY {:?}", gen_key);

                let decryptor = AesSafe128Decryptor::new(&gen_key);
                let mut reader = AesReader::new(Cursor::new(encrypted), decryptor).unwrap();
                let mut decrypted = String::new();

                match reader.read_to_string(&mut decrypted) {
                    Ok(_) => return decrypted,
                    Err(e) => {
                        println!("{:>20} {:?}", "ERROR:", e);
                        return "error".to_string();
                    }
                }
            }
            Err(e) => {
                println!("Error decoding base64: {:?}", e);
                return "error".to_string();
            }
        }
    }

    fn key(&self) -> [u8; 16] {
        let r = key_file();

        let base64_decoded = base64::decode(&r).unwrap();

        println!("{:<20} {:?}", "Base 64 Decoded", base64_decoded);

        let mut aaa: [u8; 16] = [255; 16];

        for (i, item) in base64_decoded.iter().enumerate() {
            //println!("{:?}", i);
            aaa[i] = item.clone();
        }

        return aaa;
    }

    fn gen_key(&self) -> [u8; 16] {
        let path = "/Users/ivan/code/rust/list_all_files/key";

        let mut rng = match OsRng::new() {
            Ok(g) => g,
            Err(e) => panic!("Failed to obtain OS RNG: {}", e),
        };

        if let Ok(contents) = fs::read_to_string(path) {
            println!("{:<20} {:?}", "READING KEY", contents);

            let file = IFile {
                path: path.to_string(),
                // We may want to refactor this
                file_name: "".to_string(),
            };

            return file.key();
        } else {
            println!("Generating new key ... ");
            let da_key: [u8; 16] = rng.gen();
            let base64_encoded = base64::encode(&da_key);
            println!("{:>20} {:?}", "hex key", da_key);
            println!("{:>20} {:?}", "base64 key", base64_encoded);

            let w_path = "/Users/ivan/code/rust/list_all_files/key";
            let file = match File::create(w_path) {
                Ok(file) => {
                    let mut ff = &file;
                    ff.write_all(&base64_encoded.as_bytes());
                }
                Err(e) => println!("Error saving key to file {}", e),
            };

            return da_key;
        }
    }
}

fn list_all_files(folder: String) -> Vec<IFile> {
    let mut result = Vec::new();

    if let Ok(r) = std::fs::read_dir(folder) {
        for entry in r {
            //println!("{:?}", entry);
            if let Ok(rr) = entry {
                if rr.path().is_dir() {
                    let r = list_all_files(rr.path().to_string_lossy().to_string());

                    for file in r {
                        result.push(file);
                    }
                } else {
                    let f = IFile {
                        path: rr.path().to_string_lossy().to_string(),
                        file_name: rr.file_name().into_string().unwrap(),
                    };

                    result.push(f);
                }
            } else {
                // TODO: Deal with it
            }
        }
    } else {
        // TODO: deal with it
        println!("Error reading the directory");
    }

    return result;
}

fn encrypt() {
    println!("Encrypting!");

    let folder = generate_config().folder_to_encrypt;

    let all_files = list_all_files(folder);

    for file in all_files {
        println!("############################");
        println!("{:<20} {:?}", "path", file.path);
        println!("{:<20} {:?}", "COMTENT", file.file_string());
        println!("{:<20} {:?}", "Encrypted", file.encrypt());
        file.save_encrypted();
        //println!("{:<20} {:?}", "Decrypted", file.decrypt());
    }
}

fn decrypt() {
    println!("Decrypting!");

    let folder = generate_config().encrypted_folder;

    let all_files = list_all_files(folder);

    for file in all_files {
        println!("############################");
        println!("{:<20} {:?}", "path", file.path);
        println!("{:<20} {:?}", "COMTENT", file.file_string());
        println!("{:<20} {:?}", "Decrypted", file.decrypt());
        file.save_decrypted();
    }
}

fn main() {
    encrypt();
    decrypt();
}
