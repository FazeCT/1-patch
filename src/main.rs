use argparse::{ArgumentParser, StoreTrue, Store};
use colored::*;
use std::env;

pub mod compiler;
pub mod patch_parser;

fn print_help() {
    println!("\n{}", "1-PATCH [v0.1.0]".bold().green());
    println!("{}", "----------------".green());

    println!("{}", "Static Binary Rewriting With Code Insertion".cyan());
    println!("{}", "Patch an ELF binary with user-input C program".cyan());

    println!("\n{}", "Usage: 1-patch <OPTIONS> [PATCH_CODE] [TARGET_BINARY] [OUTPUT_BINARY]".yellow());

    println!("{}", "\nPatch Syntax:".cyan());
    println!("{}", "  Prefixes:".cyan());
    println!("    {}{:<17}{}", "volatile".green(), " fix_".magenta(), "Fix a symbol within the target binary".white());
    println!("    {}{:<17}{}", "volatile".green(), " ref_".magenta(), "Reference a symbol within the target binary".white());

    println!("{}", "\n  Suffix:".cyan());
    println!("    {:<25}", "Address of the symbol within the target binary".white());

    println!("{}", "\n  Note:".cyan());
    println!("    {:<25}", "Any symbols that do not adhere to the defined syntax will be automatically added to the target binary".white());

    println!("{}", "\nOptions:".cyan());
    println!("    {:<25}{}", "-h, --help".magenta(), "Show this help".white());
    println!("    {:<25}{}", "-v, --verbose".magenta(), "Enable verbose output".white());

    println!("{}", "\nArguments:".cyan());
    println!("    {:<25}{}", "PATCH_CODE".magenta(), "Path to the C program".white());
    println!("    {:<25}{}", "TARGET_BINARY".magenta(), "Path to the target binary".white());
    println!("    {:<25}{}", "OUTPUT_BINARY".magenta(), "Path to the output binary".white());
    return;
}

fn main() {
    let mut verbose = false;
    let mut help = false;
    let mut patch_code_path = String::new();
    let mut target_binary_path = String::new();
    let mut output_binary_path = String::new();

    {
        let mut ap = ArgumentParser::new();
        ap.set_description("
            1-PATCH [v0.1.0]\n
            FazeCT - https://github.com/FazeCT/1-patch\n\n
            Usage: 1-patch <OPTIONS> [PATCH_CODE] [TARGET_BINARY] [OUTPUT_BINARY]\n
        ");
        
        ap.refer(&mut help)
            .add_option(&["-h", "--help"], StoreTrue, "Show this help");

        ap.refer(&mut verbose)
            .add_option(&["-v", "--verbose"], StoreTrue, "Enable verbose output");

        ap.refer(&mut patch_code_path)
            .add_argument("PATCH_CODE", Store, "Path to the C program");

        ap.refer(&mut target_binary_path)
            .add_argument("TARGET_BINARY", Store, "Path to the target binary");

        ap.refer(&mut output_binary_path)
            .add_argument("OUTPUT_BINARY", Store, "Path to the output binary");

        ap.parse_args_or_exit();
    }

    if env::args().len() == 1 || help || patch_code_path.is_empty() || target_binary_path.is_empty() {
        print_help();
        return;
    }

    match compiler::compile(&patch_code_path) {
        Ok(file) => {
            println!("[+] Compiled {} into {}", patch_code_path, file.to_str().unwrap());
            patch_parser::parse(&file);
        },
        Err(e) => {
            println!("{}", format!("[!] Error: {}", e).red());
            return;
        }
    };

    // std::fs::remove_file(tmp_file).unwrap();
}