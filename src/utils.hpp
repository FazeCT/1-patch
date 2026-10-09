#include <stdint.h> 
#include <unistd.h>
#include <string>
#include <ctime>
#include <cstdlib>
#include <iomanip>
#include <sstream>
#include <vector>
#include <iostream>
#include <stdexcept>
#include <dwarf.h>
#include <libdwarf.h>
#include <regex>
#include <fcntl.h>
#include <map>
#include <optional>
#include <atomic>
#include <random>

#include <capstone/capstone.h>
#include <keystone/keystone.h>

#ifndef UTILS_HPP
#define UTILS_HPP

enum class SymbolType {
    GlobalVariable,
    Function,
};

enum class OperationType {
    Add,
    Fix,
    Ref,
    None,
};

struct GlobalVariableType {
    std::string primitive;
    uint8_t pointer_depth = 0;
    bool is_array = false;
    uint64_t element_count = 1;
};

struct Reference {
    uint64_t address;
    uint64_t size;
    SymbolType reference_type;
    uint64_t reference_address;

    Reference(uint64_t address, uint64_t size, SymbolType reference_type, uint64_t reference_address)
        : address(address), size(size), reference_type(reference_type), reference_address(reference_address) {}
};

class ReferenceMap {
    private:
        std::map<uint64_t, std::unique_ptr<Reference>> reference_map;

    public:
        ReferenceMap() = default;
        ~ReferenceMap() = default;

        void insert(std::unique_ptr<Reference> ref) {
            reference_map[ref->address] = std::move(ref);
        }

        Reference* find_reference(uint64_t address) const {
            auto it = reference_map.find(address);
            return (it != reference_map.end()) ? it->second.get() : nullptr;
        }

        std::vector<Reference*> get_references() const {
            std::vector<Reference*> result;
            for (const auto& [_, ref_ptr] : reference_map) {
                result.push_back(ref_ptr.get());
            }
            return result;
        }
};

struct GlobalVar {
    OperationType operation;
    uint64_t size;
    uint64_t patch_address;
    uint64_t target_address;
    GlobalVariableType variable_type;
    uint64_t new_address;

    GlobalVar(OperationType operation, uint64_t size, uint64_t patch_address, uint64_t target_address, GlobalVariableType variable_type, uint64_t new_address)
        : operation(operation), size(size), patch_address(patch_address), target_address(target_address), variable_type(variable_type), new_address(new_address) {}
};

class GlobalVarMap {
    private:
        std::map<uint64_t, std::unique_ptr<GlobalVar>> var_map;

    public:
        GlobalVarMap() = default;
        ~GlobalVarMap() = default;

        void insert(std::unique_ptr<GlobalVar> var) {
            var_map[var->patch_address] = std::move(var);
        }

        GlobalVar* find_global_var(uint64_t address) const {
            auto it = var_map.find(address);
            return (it != var_map.end()) ? it->second.get() : nullptr;
        }

        std::vector<GlobalVar*> get_global_vars() const {
            std::vector<GlobalVar*> result;
            for (const auto& pair : var_map) {
                result.push_back(pair.second.get());
            }
            return result;
        }
};

struct Function {
    OperationType operation;
    uint64_t size;
    uint64_t patch_address;
    uint64_t target_address;
    std::unique_ptr<ReferenceMap> reference_table;
    uint64_t new_address;

    Function(OperationType operation, uint64_t size, uint64_t patch_address, uint64_t target_address, std::unique_ptr<ReferenceMap> reference_table, uint64_t new_address)
        : operation(operation), size(size), patch_address(patch_address), target_address(target_address), reference_table(std::move(reference_table)), new_address(new_address) {}
};

class FunctionMap {
    private:
        std::map<uint64_t, std::unique_ptr<Function>> function_map;

    public:
        FunctionMap() = default;
        ~FunctionMap() = default;

        void insert(std::unique_ptr<Function> func) {
            function_map[func->patch_address] = std::move(func);
        }

        Function* find_function(uint64_t address) const {
            auto it = function_map.find(address);
            return (it != function_map.end()) ? it->second.get() : nullptr;
        }

        std::vector<Function*> get_functions() const {
            std::vector<Function*> result;
            for (const auto& [_, func_ptr] : function_map) {
                result.push_back(func_ptr.get());
            }
            return result;
        }
};

// Print functions
// Print help
void print_help() {
    auto help_row = [](const std::string& label,
                       const std::string& styled_label,
                       const std::string& description) {
        constexpr size_t label_width = 30;
        const size_t spaces = label.size() < label_width
            ? label_width - label.size() : 2;
        std::cout << "    " << styled_label << std::string(spaces, ' ')
                  << description << '\n';
    };

    std::cout << "\n\033[1;32m1-PATCH [v1.0.0]\033[0m\n";
    std::cout << "\033[1;32m----------------\033[0m\n";
    std::cout << "\033[1;36mStatic Binary Rewriting With Code Insertion\033[0m\n";
    std::cout << "\033[1;36mPatch an ELF binary with user-input C program\033[0m\n";
    std::cout << "\n\033[1;33mUsage: 1-patch -p PATCH_CODE -i TARGET_BINARY [-o OUTPUT_BINARY] [OPTIONS]\033[0m\n";

    std::cout << "\n\033[1;36mPatch Syntax:\033[0m\n";
    std::cout << "\033[1;36m  Prefix:\033[0m\n";
    help_row("(volatile) add_",
             "\033[1;32m(volatile)\033[0m \033[1;35madd_\033[0m",
             "Add a symbol to the target binary");
    help_row("(volatile) fix_",
             "\033[1;32m(volatile)\033[0m \033[1;35mfix_\033[0m",
             "Fix a symbol within the target binary");
    help_row("ref_", "\033[1;35mref_\033[0m",
             "Reference a symbol within the target binary");

    std::cout << "\n\033[1;36m  Suffix:\033[0m\n";
    help_row("add_", "\033[1;35madd_\033[0m", "Any suffix");
    help_row("fix_ / ref_",
             "\033[1;35mfix_\033[0m / \033[1;35mref_\033[0m",
             "Target symbol address followed by an optional name");

    std::cout << "\n\033[1;36m  Note:\033[0m\n";
    std::cout << "    Symbols outside the defined syntax are skipped\n";

    std::cout << "\n\033[1;36mOptions:\033[0m\n";
    help_row("-h, --help", "\033[1;35m-h, --help\033[0m",
             "Show this help message");
    help_row("-v, --verbose", "\033[1;35m-v, --verbose\033[0m",
             "Enable verbose output");
    help_row("--allow-unverified-targets",
             "\033[1;35m--allow-unverified-targets\033[0m",
             "Permit fix_ writes when target symbol sizes are unavailable");

    std::cout << "\n\033[1;36mArguments:\033[0m\n";
    help_row("-p, --patch", "\033[1;35m-p, --patch\033[0m",
             "Path to the C patch source file");
    help_row("-i, --input", "\033[1;35m-i, --input\033[0m",
             "Path to the target input binary");
    help_row("-o, --output", "\033[1;35m-o, --output\033[0m",
             "Path to the output binary (optional)");
}

namespace verbose_print {
    inline bool verbose = false; 

    inline void print_red(const std::string& output) {
        if (verbose) std::cout << "\033[1;31m[!]\033[0m " << output << std::endl;
    }

    inline void print_green(const std::string& output) {
        if (verbose) std::cout << "\033[1;32m[+]\033[0m " << output << std::endl;
    }

    inline void print_yellow(const std::string& output) {
        if (verbose) std::cout << "\033[1;33m[?]\033[0m " << output << std::endl;
    }

    inline void print_blue(const std::string& output) {
        if (verbose) std::cout << "\033[1;36m[-]\033[0m " << output << std::endl;
    }

    inline void print_module(const std::string& output) {
        if (verbose) std::cout << "\033[1;32m[" << output << "]\033[0m " << std::endl;
    }
}

// Parse the target address of a patch in patch binary
uint64_t parse_address(const std::string& hex) {
    // [valid hexadecimal]_[optional string]
    static const std::regex hex_pattern(R"(^0x[0-9a-fA-F]+(_.*)?$|^[0-9a-fA-F]+(_.*)?$)");

    if (!std::regex_match(hex, hex_pattern)) {
        return UINT64_MAX;
    }

    try {
        size_t underscore_pos = hex.find('_');
        std::string valid_hex = (underscore_pos == std::string::npos) ? hex : hex.substr(0, underscore_pos);

        return std::stoull(valid_hex, nullptr, 16);
    } catch (...) {
        return UINT64_MAX;
    }
}

// Convert decimal to hexadecimal
std::string decimal_to_hex(uint64_t decimal) {
    std::stringstream ss;
    ss << std::hex << decimal;
    return "0x" + ss.str();
}

// Convert vector to little-endian integer
uint64_t vector_to_int(const std::vector<uint8_t>& data) {
    if (data.empty() || data.size() > sizeof(uint64_t)) {
        throw std::invalid_argument("Input vector must contain 1 to 8 bytes");
    }

    uint64_t result = 0;
    for (size_t i = 0; i < data.size(); ++i) {
        result |= static_cast<uint64_t>(data[i]) << (i * 8);
    }

    return result;
}

// Calculate FNV-1a hash
std::string fnv1a_hash(const std::string& input) {
    const uint64_t fnv_prime = 0x100000001b3u;
    const uint64_t offset_basis = 0xcbf29ce484222325u;

    uint64_t hash = offset_basis;
    for (unsigned char c : input) {
        hash ^= static_cast<uint64_t>(c);
        hash *= fnv_prime;
    }

    std::stringstream hash_string;
    hash_string << std::hex << std::setw(16) << std::setfill('0') << hash;
    return hash_string.str();
}

// Generate random string
std::string generate_random_string() {
    static std::atomic<uint64_t> counter{0};
    std::random_device random;
    return fnv1a_hash(std::to_string(random()) + ":" +
                      std::to_string(random()) + ":" +
                      std::to_string(getpid()) + ":" +
                      std::to_string(counter.fetch_add(1)));
}

// Split a string by a delimiter
std::vector<std::string> split(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::stringstream ss(str);
    std::string token;

    while (std::getline(ss, token, delimiter)) {
        tokens.push_back(token);
    }

    return tokens;
}

// Extract global variables/functions references from a code section
void extract_references(const std::vector<uint8_t>& code, uint64_t start_address, ReferenceMap& reference_map) {
    csh handle;
    cs_insn* insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        throw std::runtime_error("Failed to initialize Capstone");
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    count = cs_disasm(handle, code.data(), code.size(), start_address, 0, &insn);

    if (count > 0) {
        for (size_t i = 0; i < count; i++) {
            const cs_insn& instruction = insn[i];
            const cs_detail* detail = instruction.detail;

            if (detail) {
                bool control_flow_instruction = cs_insn_group(handle, &instruction, CS_GRP_JUMP) || cs_insn_group(handle, &instruction, CS_GRP_CALL);

                if (control_flow_instruction) {
                    if (detail->x86.op_count == 0) {
                        continue;
                    }
                    std::optional<uint64_t> resolved_address;

                    switch (detail->x86.operands[0].type) {
                        case X86_OP_IMM:
                            resolved_address = detail->x86.operands[0].imm;
                            break;
                        case X86_OP_MEM:
                            if (detail->x86.operands[0].mem.base == X86_REG_RIP) {
                                resolved_address = instruction.address + instruction.size + detail->x86.operands[0].mem.disp;
                            } 
                            break;
                        default:
                            break;
                    }

                    // Register and non-RIP memory branches have no static destination.
                    if (!resolved_address) {
                        continue;
                    }
                    if (*resolved_address >= start_address &&
                        *resolved_address - start_address < code.size()) {
                        continue;
                    }

                    reference_map.insert(std::make_unique<Reference>(
                        instruction.address,
                        instruction.size,
                        SymbolType::Function,
                        *resolved_address
                    ));
                }

                else {
                    for (size_t j = 0; j < detail->x86.op_count; j++) {
                        const cs_x86_op& op = detail->x86.operands[j];
                        if (op.type == X86_OP_MEM && op.mem.base == X86_REG_RIP) {
                            uint64_t resolved_address = instruction.address + instruction.size + op.mem.disp;

                            reference_map.insert(std::make_unique<Reference>(
                                instruction.address,
                                instruction.size,
                                SymbolType::GlobalVariable,
                                resolved_address
                            ));
                        }
                    }
                }
            }
        }
        cs_free(insn, count);
    } else {
        cs_close(&handle);
        throw std::runtime_error("Failed to disassemble code");
    }

    cs_close(&handle);
}

std::vector<uint8_t> assemble_instruction(const std::string& instruction) {
    ks_engine *ks;
    ks_err err;

    if (ks_open(KS_ARCH_X86, KS_MODE_64, &ks) != KS_ERR_OK) {
        throw std::runtime_error("Failed to initialize Keystone");
    }

    size_t size;
    size_t count_ks;
    unsigned char *encode = nullptr;

    if (ks_asm(ks, instruction.c_str(), 0, &encode, &size, &count_ks) != KS_ERR_OK) {
        ks_free(encode);
        ks_close(ks);
        verbose_print::print_red("Failed to assemble instruction: " + instruction);
        throw std::runtime_error("Failed to assemble instruction");
    } else {
        std::vector<uint8_t> assembled_code(encode, encode + size);
        ks_free(encode);
        ks_close(ks);
        if (assembled_code.empty()) {
            verbose_print::print_red("Failed to assemble instruction: " + instruction);
            throw std::runtime_error("Failed to assemble instruction");
        }
        return assembled_code;
    }
}

class DWARFResolver {
public:
    DWARFResolver(const std::string& path) {
        fd = open(path.c_str(), O_RDONLY);
        if (fd < 0) throw std::runtime_error("Failed to open binary");

        if (dwarf_init(fd, DW_DLC_READ, nullptr, nullptr, &dbg, &err) != DW_DLV_OK) {
            close(fd);
            throw std::runtime_error("Failed to init DWARF");
        }
    }

    ~DWARFResolver() {
        if (dbg) dwarf_finish(dbg, &err);
        if (fd >= 0) close(fd);
    }

    GlobalVariableType resolve(const std::string& var_name) {
        // The first lookup uses the constructor's session. Later lookups
        // restart the CU iterator without reopening the file descriptor.
        if (used) reset_state();
        used = true;

        GlobalVariableType result;

        Dwarf_Unsigned cu_header_length, abbrev_offset, next_cu_header;
        Dwarf_Half version_stamp, address_size;
        Dwarf_Die cu_die = 0;

        while (dwarf_next_cu_header(dbg, &cu_header_length, &version_stamp,
                                     &abbrev_offset, &address_size, &next_cu_header, &err) == DW_DLV_OK) {

            if (dwarf_siblingof(dbg, nullptr, &cu_die, &err) != DW_DLV_OK) continue;

            if (find_variable_recursive(cu_die, var_name, result)) {
                return result;
            }
        }

        throw std::runtime_error("Variable with name '" + var_name + "' not found.");
    }

private:
    int fd = -1;
    Dwarf_Debug dbg = nullptr;
    Dwarf_Error err = nullptr;
    bool used = false;

    void reset_state() {
        // Reset any necessary internal states for a new resolve
        if (dbg) {
            dwarf_finish(dbg, &err); // Finish the previous session
            dbg = nullptr;
        }

        // Reinitialize
        if (dwarf_init(fd, DW_DLC_READ, nullptr, nullptr, &dbg, &err) != DW_DLV_OK) {
            throw std::runtime_error("Failed to reinitialize DWARF");
        }
    }

    bool find_variable_recursive(Dwarf_Die die, const std::string& var_name, GlobalVariableType& out) {
        // Walk siblings once per level; recursive calls only descend into children.
        for (Dwarf_Die current = die; current != nullptr;) {
            char* name = nullptr;
            if (dwarf_diename(current, &name, &err) == DW_DLV_OK && name) {
                if (var_name == std::string(name)) {
                    Dwarf_Attribute attr;
                    if (dwarf_attr(current, DW_AT_type, &attr, &err) == DW_DLV_OK) {
                        resolve_type(attr, out);
                        dwarf_dealloc(dbg, name, DW_DLA_STRING);
                        return true;
                    }
                }
                dwarf_dealloc(dbg, name, DW_DLA_STRING);
            }

            Dwarf_Die child = nullptr;
            if (dwarf_child(current, &child, &err) == DW_DLV_OK &&
                find_variable_recursive(child, var_name, out)) {
                return true;
            }

            Dwarf_Die sibling = nullptr;
            if (dwarf_siblingof(dbg, current, &sibling, &err) != DW_DLV_OK) {
                break;
            }
            current = sibling;
        }

        return false;
    }

    bool extract_array_size(Dwarf_Die subrange_die, uint64_t& count) {
        Dwarf_Attribute attr;
        Dwarf_Unsigned uvalue;
        Dwarf_Signed svalue;
        Dwarf_Half form;

        // DW_AT_count
        if (dwarf_attr(subrange_die, DW_AT_count, &attr, &err) == DW_DLV_OK) {
            if (dwarf_formudata(attr, &uvalue, &err) == DW_DLV_OK) {
                count = uvalue;
                return true;
            }
            if (dwarf_formsdata(attr, &svalue, &err) == DW_DLV_OK && svalue >= 0) {
                count = static_cast<uint64_t>(svalue);
                return true;
            }
        }

        // DW_AT_upper_bound
        if (dwarf_attr(subrange_die, DW_AT_upper_bound, &attr, &err) == DW_DLV_OK) {
            if (dwarf_formudata(attr, &uvalue, &err) == DW_DLV_OK) {
                if (uvalue == UINT64_MAX) {
                    throw std::runtime_error("DWARF array bound overflows");
                }
                count = uvalue + 1;
                return true;
            }
            if (dwarf_formsdata(attr, &svalue, &err) == DW_DLV_OK && svalue >= 0) {
                count = static_cast<uint64_t>(svalue + 1);
                return true;
            }
        }

        return false;
    }

    void resolve_type(Dwarf_Attribute attr, GlobalVariableType& result) {
        Dwarf_Off offset;
        if (dwarf_global_formref(attr, &offset, &err) != DW_DLV_OK) return;

        Dwarf_Die die;
        if (dwarf_offdie(dbg, offset, &die, &err) != DW_DLV_OK) return;

        Dwarf_Half tag;
        if (dwarf_tag(die, &tag, &err) != DW_DLV_OK) return;

        switch (tag) {
            case DW_TAG_base_type: {
                char* name = nullptr;
                if (dwarf_diename(die, &name, &err) == DW_DLV_OK && name) {
                    result.primitive = std::string(name);
                }
                break;
            }
            case DW_TAG_pointer_type:
                ++result.pointer_depth;
                follow_type(die, result);
                break;
            case DW_TAG_array_type: {
                result.is_array = true;

                uint64_t total_elements = 1;
                Dwarf_Die child;
                if (dwarf_child(die, &child, &err) == DW_DLV_OK) {
                    do {
                        Dwarf_Half child_tag;
                        if (dwarf_tag(child, &child_tag, &err) == DW_DLV_OK && child_tag == DW_TAG_subrange_type) {
                            uint64_t count = 1;
                            if (extract_array_size(child, count)) {
                                if (count != 0 && total_elements > UINT64_MAX / count) {
                                    throw std::runtime_error("DWARF array element count overflows");
                                }
                                total_elements *= count;
                            } else {
                                total_elements = 0;
                            }
                        }
                    } while (dwarf_siblingof(dbg, child, &child, &err) == DW_DLV_OK);
                }

                result.element_count = total_elements;
                follow_type(die, result);
                break;
            }
            case DW_TAG_const_type:
            case DW_TAG_volatile_type:
            case DW_TAG_typedef:
            case DW_TAG_restrict_type:
                follow_type(die, result);
                break;
            default:
                break;
        }
    }

    void follow_type(Dwarf_Die die, GlobalVariableType& result) {
        Dwarf_Attribute attr;
        if (dwarf_attr(die, DW_AT_type, &attr, &err) == DW_DLV_OK) {
            resolve_type(attr, result);
        }
    }
};
#endif // UTILS_HPP
