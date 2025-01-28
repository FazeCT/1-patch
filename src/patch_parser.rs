use lazy_static::lazy_static;
use std::path::PathBuf;

use lief::Binary;

lazy_static! {
    pub static ref PREFIX_FIX: &'static str = "fix_";
    pub static ref PREFIX_DEL: &'static str = "del_";
    pub static ref PREFIX_REF: &'static str = "ref_";
}

pub fn parse(path: &PathBuf) {
    let mut file = std::fs::File::open(path).expect("Can't open the file");
    match Binary::from(&mut file) {
        Some(Binary::ELF(elf)) => {
            for symbol in elf.exported_symbols() {
                let name = &symbol.demangled_name();

                if name.starts_with(*PREFIX_FIX) {
                    println!("[+] Found symbol: {}", name);
                    let a = &symbol.information();
                    println!("{:?}", a);
                } 
                
                else if name.starts_with(*PREFIX_DEL) {
                    println!("[+] Found symbol: {}", name);
                } 
                
                else if name.starts_with(*PREFIX_REF) {
                    println!("[+] Found symbol: {}", name);
                }
            }
        },
        Some(Binary::PE(_pe)) => {
            println!("[-] PE binary not supported");
        },
        Some(Binary::MachO(_macho)) => {
            println!("[-] Mach-O binary not supported");
        },
        None => {
            println!("[-] Unsupported binary format");
        }
    }
}