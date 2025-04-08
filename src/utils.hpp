#include <stdint.h> 
#include <unistd.h>
#include <string>
#include <ctime>
#include <cstdlib>
#include <iomanip>
#include <sstream>
#include <vector>

#include <capstone/capstone.h>

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
    uint8_t pointer_depth;
    bool is_array;
};

class Node {
    protected:
        Node* left;
        Node* right;

    public:
        Node() : left(nullptr), right(nullptr) {}
        Node(Node* left, Node* right) : left(left), right(right) {}
        virtual ~Node() {
            delete left;
            delete right;
        }

        Node* get_left() const { return left; }
        Node* get_right() const { return right; }

        void set_left(Node* node) { left = node; }
        void set_right(Node* node) { right = node; }
};

class BinaryTree {
    protected:
        Node* root;

    public:
        BinaryTree() : root(nullptr) {}
        virtual ~BinaryTree() {
            delete root;
            root = nullptr;
        }
};

struct Reference {
    uint64_t address;
    SymbolType reference_type;
    std::string instruction;
    uint64_t reference_address;
};

class ReferenceNode : public Node {
    private:
        Reference* reference;

    public:
        ReferenceNode(Reference* reference) : Node(), reference(reference) {}
        ~ReferenceNode() override {
            delete reference;
            reference = nullptr;
        }
        Reference* get_reference() const {
            return reference;
        }
};

class ReferenceTree : public BinaryTree {
    public:
        ReferenceTree() : BinaryTree() {}
        ~ReferenceTree() override {}

        void insert(ReferenceNode* node) {
            if (root == nullptr) {
                root = node;
            } else {
                insert(static_cast<ReferenceNode*>(root), node);
            }
        }

        void insert(ReferenceNode* current, ReferenceNode* node) {
            if (node->get_reference()->address < current->get_reference()->address) {
                if (current->get_left() == nullptr) {
                    current->set_left(node);
                } else {
                    insert(static_cast<ReferenceNode*>(current->get_left()), node);
                }
            } else {
                if (current->get_right() == nullptr) {
                    current->set_right(node);
                } else {
                    insert(static_cast<ReferenceNode*>(current->get_right()), node);
                }
            }
        }

        void traverse(ReferenceNode* node, std::vector<Reference*>& references) const {
            if (node == nullptr) return;

            traverse(static_cast<ReferenceNode*>(node->get_left()), references);
            references.push_back(node->get_reference());
            traverse(static_cast<ReferenceNode*>(node->get_right()), references);
        }

        std::vector<Reference*> get_references() const {
            std::vector<Reference*> references;
            if (root != nullptr) {
                traverse(static_cast<ReferenceNode*>(root), references);
            }
            return references;
        }
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

class GlobalVarNode : public Node {
    private:
        GlobalVar* global_var;

    public:
        GlobalVarNode(GlobalVar* global_var) : Node(), global_var(global_var) {}
        ~GlobalVarNode() override {
            delete global_var;
            global_var = nullptr;
        }
        GlobalVar* get_global_var() const {
            return global_var;
        }
};

class GlobalVarTree : public BinaryTree {
    public:
        GlobalVarTree() : BinaryTree() {}
        ~GlobalVarTree() override {}

        void insert(GlobalVarNode* node) {
            if (root == nullptr) {
                root = node;
            } else {
                insert(static_cast<GlobalVarNode*>(root), node);
            }
        }

        void insert(GlobalVarNode* current, GlobalVarNode* node) {
            if (node->get_global_var()->patch_address < current->get_global_var()->patch_address) {
                if (current->get_left() == nullptr) {
                    current->set_left(node);
                } else {
                    insert(static_cast<GlobalVarNode*>(current->get_left()), node);
                }
            } else {
                if (current->get_right() == nullptr) {
                    current->set_right(node);
                } else {
                    insert(static_cast<GlobalVarNode*>(current->get_right()), node);
                }
            }
        }

        void traverse(GlobalVarNode* node, std::vector<GlobalVar*>& global_vars) const {
            if (node == nullptr) return;

            traverse(static_cast<GlobalVarNode*>(node->get_left()), global_vars);
            global_vars.push_back(node->get_global_var());
            traverse(static_cast<GlobalVarNode*>(node->get_right()), global_vars);
        }

        std::vector<GlobalVar*> get_global_vars() const {
            std::vector<GlobalVar*> global_vars;
            if (root != nullptr) {
                traverse(static_cast<GlobalVarNode*>(root), global_vars);
            }
            return global_vars;
        }
};

struct Function {
    OperationType operation;
    uint64_t size;
    uint64_t patch_address;
    uint64_t target_address;
    std::string function_name;
    ReferenceTree reference_table;
    uint64_t new_address;
};

class FunctionNode : public Node {
    private:
        Function* function;

    public:
        FunctionNode(Function* function) : Node(), function(function) {}
        ~FunctionNode() override {
            delete function;
            function = nullptr;
        }
        Function* get_function() const {
            return function;
        }
};

class FunctionTree : public BinaryTree {
    public:
        FunctionTree() : BinaryTree() {}
        ~FunctionTree() override {}

        void insert(FunctionNode* node) {
            if (root == nullptr) {
                root = node;
            } else {
                insert(static_cast<FunctionNode*>(root), node);
            }
        }

        void insert(FunctionNode* current, FunctionNode* node) {
            if (node->get_function()->patch_address < current->get_function()->patch_address) {
                if (current->get_left() == nullptr) {
                    current->set_left(node);
                } else {
                    insert(static_cast<FunctionNode*>(current->get_left()), node);
                }
            } else {
                if (current->get_right() == nullptr) {
                    current->set_right(node);
                } else {
                    insert(static_cast<FunctionNode*>(current->get_right()), node);
                }
            }
        }

        void traverse(FunctionNode* node, std::vector<Function*>& functions) const {
            if (node == nullptr) return;

            traverse(static_cast<FunctionNode*>(node->get_left()), functions);
            functions.push_back(node->get_function());
            traverse(static_cast<FunctionNode*>(node->get_right()), functions);
        }

        std::vector<Function*> get_functions() const {
            std::vector<Function*> functions;
            if (root != nullptr) {
                traverse(static_cast<FunctionNode*>(root), functions);
            }
            return functions;
        }
};

// Convert hexadecimal to decimal
uint64_t hex_to_decimal(const std::string& hex) {
    return std::stoull(hex, nullptr, 16);
}

// Calculate FNV-1a hash
std::string fnv1a_hash(const std::string& input) {
    const uint64_t fnv_prime = 0x100000001b3u;
    const uint64_t offset_basis = 0xcbf29ce484222325u;

    uint64_t hash = offset_basis;
    for (char c : input) {
        hash ^= static_cast<uint64_t>(c);
        hash *= fnv_prime;
    }

    std::stringstream hash_string;
    hash_string << std::hex << std::setw(16) << std::setfill('0') << hash;
    return hash_string.str();
}

// Generate random string
std::string generate_random_string() {
    std::srand(static_cast<unsigned int>(std::time(nullptr)));
    int rand = std::rand();

    return fnv1a_hash(std::to_string(rand));
}

// Extract global variables/functions references from a code section
void extract_references(const std::vector<uint8_t>& code, uint64_t start_address, ReferenceTree& reference_tree) {
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
                bool control_flow_instruction = false;

                for (size_t j = 0; j < detail->groups_count; j++) {
                    if (detail->groups[j] == CS_GRP_JUMP || detail->groups[j] == CS_GRP_CALL) {
                        control_flow_instruction = true;
                        uint64_t resolved_address = std::stoull(instruction.op_str, nullptr, 16);
                        if (resolved_address >= start_address && resolved_address < start_address + code.size()) {
                            continue;
                        }

                        ReferenceNode* reference_node = new ReferenceNode(new Reference{
                            instruction.address, SymbolType::Function, instruction.mnemonic, resolved_address
                        });
                        reference_tree.insert(reference_node);
                        break;
                    }
                }

                if (!control_flow_instruction) {
                    for (size_t j = 0; j < detail->x86.op_count; j++) {
                        const cs_x86_op& op = detail->x86.operands[j];
                        if (op.type == X86_OP_MEM && op.mem.base == X86_REG_RIP) {
                            uint64_t resolved_address = instruction.address + instruction.size + op.mem.disp;

                            ReferenceNode* reference_node = new ReferenceNode(new Reference{
                                instruction.address, SymbolType::GlobalVariable, instruction.mnemonic, resolved_address
                            });

                            reference_tree.insert(reference_node);
                        }
                    }
                }
            }
        }
        cs_free(insn, count);
    } else {
        throw std::runtime_error("Failed to disassemble code");
    }

    cs_close(&handle);
}

#endif // UTILS_HPP