#include "utils.hpp"
#include "object.hpp"

#ifndef BINARY_TREE_HPP
#define BINARY_TREE_HPP

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

#endif // BINARY_TREE_HPP