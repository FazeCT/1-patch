use std::process::Command;
use std::env;
use std::path::PathBuf;
use std::error::Error;

use rand::Rng;
use sha2::{Sha256, Digest};
use std::fs::File;
use std::io::{Write, Read};
use hex;

pub fn random_string() -> String {
    let rand_bytes: [u8; 8] = rand::thread_rng().gen();
    let rand_string = hex::encode(rand_bytes);

    let mut hasher = Sha256::new();
    hasher.update(rand_string);
    hex::encode(hasher.finalize())
}

pub fn exec_compile(c_file: &str, output_path: &str) -> Result<(), Box<dyn Error>> {
    let output = Command::new("gcc")
        .arg("-Wall")
        .arg(c_file)
        .arg("-o")
        .arg(output_path)
        .arg("-g")
        .output()?;

    if !output.status.success() {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            String::from_utf8_lossy(&output.stderr),
        )));
    }

    Ok(())
}

pub fn compile(c_file: &str) -> Result<PathBuf, Box<dyn Error>> {
    let tmp_dir = env::temp_dir();
    let output_path = tmp_dir.join(random_string());

    match exec_compile(c_file, output_path.to_str().unwrap()) {
        Ok(_) => Ok(output_path),
        Err(e) => {
            if e.to_string().contains("undefined reference to `main'") {
                let tmp_main_path = tmp_dir.join(random_string() + ".c");
                let mut tmp_main_file = std::fs::File::create(&tmp_main_path).unwrap();

                let mut original_file = File::open(c_file).unwrap();
                let mut original_content = String::new();
                original_file.read_to_string(&mut original_content).unwrap();

                writeln!(tmp_main_file, "{}\n\nint main() {{ return 0; }}", original_content).unwrap();

                match exec_compile(tmp_main_path.to_str().unwrap(), output_path.to_str().unwrap()) {
                    Ok(_) => {
                        std::fs::remove_file(tmp_main_path).unwrap();
                        Ok(output_path)
                    },
                    Err(e) => {
                        std::fs::remove_file(tmp_main_path).unwrap();
                        Err(e)
                    }
                }
            }
            else {
                Err(e)
            }
        }
    }
}