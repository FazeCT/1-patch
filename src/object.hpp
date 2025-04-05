#include <unistd.h>
#include <string>
#include <vector>

#ifndef OBJECT_HPP
#define OBJECT_HPP

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

struct Reference {
    uint64_t address;
    SymbolType reference_type;
    std::string instruction;
    uint64_t target_address;
};

struct GlobalVariableType {
    std::string primitive;
    uint8_t pointer_depth;
    bool is_array;
};

struct GlobalVar {
    OperationType operation;
    uint64_t patch_address;
    uint64_t target_address;
    std::string variable_name;
    // GlobalVariableType variable_type;
    std::vector<uint8_t> variable_value;
    // uint64_t new_address;
};

struct Function {
    OperationType operation;
    uint64_t size;
    uint64_t patch_address;
    uint64_t target_address;
    std::string function_name;
    std::vector<Reference> reference_table;
    uint64_t new_address;
};

#endif // OBJECT_HPP