#include <iostream>
#include <string>
#include <filesystem>
#include <fstream>

#ifndef COMPILER_HPP
#define COMPILER_HPP

#include "utils.hpp"

// Execute gcc compiler command
void exec_compile(const std::string& input_path, const std::string& output_path) {
    // Check if the input file is valid
    if (!std::filesystem::exists(input_path)) {
        std::cerr << "\033[1;31m[!]\033[0m Patch file does not exist: " << input_path << "\033[0m\n";
        throw std::runtime_error("Compilation failed");
    }

    if (std::filesystem::is_directory(input_path)) {
        std::cerr << "\033[1;31m[!]\033[0m Patch file path is a directory, not a file: " << input_path << "\033[0m\n";
        throw std::runtime_error("Compilation failed");
    }

    if (std::filesystem::path(input_path).extension() != ".c") {
        std::cerr << "\033[1;31m[!]\033[0m Patch file extension is not .c: " << input_path << "\033[0m\n";
        throw std::runtime_error("Compilation failed");
    }

    std::string command = "gcc " + input_path + " -o " + output_path + " -Wall -g";
    int result = system(command.c_str());
    if (result != 0) {
        std::ostringstream error_message;
        error_message << "Compilation failed with error code: " << result;
        throw std::runtime_error(error_message.str());
    }
}

// Compile the C patch code
std::string compile(const std::string& input_path) {
    std::filesystem::path temp_dir;

    try {
        temp_dir = std::filesystem::temp_directory_path();
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "\033[1;31m[!]\033[0m Failed to find temp directory\033[0m\n";
        throw std::runtime_error("Compilation failed");
    }

    // Save the binary in tmp directory
    std::string temp_file = temp_dir.string() + "/" + generate_random_string();

    try {
        exec_compile(input_path, temp_file);
        return temp_file;
    } catch (const std::runtime_error& e) {
        if (std::string(e.what()).find("Compilation failed") != std::string::npos) {
            throw std::runtime_error("Compilation failed");
        }

        // Missing main() function
        if (std::string(e.what()).find("undefined reference to `main'") != std::string::npos) {
            std::filesystem::path tmp_main_file = temp_dir / (generate_random_string() + ".c");

            // Create a temporary file with a minimal main() function
            std::ofstream tmp_main(tmp_main_file);
            if (!tmp_main.is_open()) {
                std::cerr << "\033[1;31m[!]\033[0m Failed to create temporary file: " << tmp_main_file << std::endl;
                throw std::runtime_error("Compilation failed");
            }

            std::ifstream original_file(input_path);
            if (!original_file.is_open()) {
                std::cerr << "\033[1;31m[!]\033[0m Failed to open original file: " << input_path << std::endl;
                throw std::runtime_error("Compilation failed");
            }

            std::string original_content((std::istreambuf_iterator<char>(original_file)), std::istreambuf_iterator<char>());
            tmp_main << original_content << "\n\nint main() { return 0; }" << std::endl;
            tmp_main.close();

            try {
                // Re-compile with main() function
                exec_compile(tmp_main_file.string(), temp_file);

                // Clean up the temporary main file
                std::filesystem::remove(tmp_main_file);
                return temp_file;
            } catch (const std::runtime_error& e) {
                // Clean up the temporary main file
                std::filesystem::remove(tmp_main_file);

                std::cerr << "\033[1;31m[!]\033[0m Failed to compile " << input_path << "\033[0m\n";
                throw std::runtime_error("Compilation failed");
            } 
        }

        std::cerr << "\033[1;31m[!]\033[0m Failed to compile " << input_path << "\033[0m\n";
        throw std::runtime_error("Compilation failed");
    }
}

#endif // COMPILER_HPP