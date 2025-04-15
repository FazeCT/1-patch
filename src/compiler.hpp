#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <filesystem>
#include <cstdio>
#include <memory>
#include <fstream>
#include <array> 

#ifndef COMPILER_HPP
#define COMPILER_HPP

#include "utils.hpp"

// Execute a command, return the output
std::string execute_command(const std::string& command) {
    std::array<char, 128> buffer;
    std::string result;

    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen((command + " 2>&1").c_str(), "r"), &pclose);
    if (!pipe) {
        throw std::runtime_error("Failed to open pipe for command execution");
    }

    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }

    return result;
}

// Execute gcc compiler command
void exec_compile(const std::string& input_path, const std::string& output_path) {
    if (!std::filesystem::exists(input_path)) {
        std::cout << "\033[1;31m[!]\033[0m Patch file does not exist: " << input_path << std::endl;
        throw std::runtime_error("Compilation failed");
    }

    if (std::filesystem::is_directory(input_path)) {
        std::cout << "\033[1;31m[!]\033[0m Patch file path is a directory, not a file: " << input_path << std::endl;
        throw std::runtime_error("Compilation failed");
    }

    if (std::filesystem::path(input_path).extension() != ".c") {
        std::cout << "\033[1;31m[!]\033[0m Patch file extension is not .c: " << input_path << std::endl;
        throw std::runtime_error("Compilation failed");
    }

    std::string command = "gcc " + input_path + " -o " + output_path + " -g";
    std::string output = execute_command(command);

    if (output.find("undefined reference to `main'") != std::string::npos) {
        throw std::runtime_error("Missing main() function");
    }
}

// Compile the C patch code
std::string compile(const std::string& input_path) {
    std::filesystem::path temp_dir;

    try {
        temp_dir = std::filesystem::temp_directory_path();
    } catch (const std::filesystem::filesystem_error& e) {
        std::cout << "\033[1;31m[!]\033[0m Failed to find temp directory" << std::endl;
        throw std::runtime_error("Compilation failed");
    }

    // Save the binary in tmp directory
    std::string temp_file = temp_dir.string() + "/" + generate_random_string();

    try {
        exec_compile(input_path, temp_file);
        return temp_file;
    } catch (const std::runtime_error& e) {
        // Missing main() function
        if (std::string(e.what()).find("Missing main() function") != std::string::npos) {
            std::filesystem::path tmp_main_file = temp_dir / (generate_random_string() + ".c");

            // Create a temporary file with a minimal main() function
            std::ofstream tmp_main(tmp_main_file);
            if (!tmp_main.is_open()) {
                std::cout << "\033[1;31m[!]\033[0m Failed to create temporary file: " << tmp_main_file << std::endl;
                throw std::runtime_error("Compilation failed");
            }

            std::ifstream original_file(input_path);
            if (!original_file.is_open()) {
                std::cout << "\033[1;31m[!]\033[0m Failed to open original file: " << input_path << std::endl;
                throw std::runtime_error("Compilation failed");
            }

            std::string original_content((std::istreambuf_iterator<char>(original_file)), std::istreambuf_iterator<char>());
            tmp_main << original_content << "\n\nint main() {}" << std::endl;
            tmp_main.close();

            std::cout << "\033[1;33m[?]\033[0m Missing main() function in " << input_path << ", added main()" << std::endl;

            try {
                // Re-compile with main() function
                exec_compile(tmp_main_file.string(), temp_file);

                // Clean up the temporary main file
                std::filesystem::remove(tmp_main_file);
                return temp_file;
            } catch (const std::runtime_error& e) {
                // Clean up the temporary main file
                std::filesystem::remove(tmp_main_file);

                std::cout << "\033[1;31m[!]\033[0m Failed to compile " << input_path << std::endl;
                throw std::runtime_error("Compilation failed");
            } 
        }

        std::cout << "\033[1;31m[!]\033[0m Failed to compile " << input_path << std::endl;
        throw std::runtime_error("Compilation failed");
    }
}

#endif // COMPILER_HPP