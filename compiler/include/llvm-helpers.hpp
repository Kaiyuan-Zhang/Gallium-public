#pragma once

#include "llvm-incl.hpp"


struct StructLayout {
    struct FieldInfo {
        int offset;
        int size;
    };
    std::vector<FieldInfo> fields;
};


std::string get_llvm_inst_str(const llvm::Instruction *inst);
std::string get_llvm_name(const llvm::Value &value);
std::string get_llvm_type_name(llvm::Type *t);
bool is_llvm_constant(const llvm::Value &value);
uint64_t get_type_size(const llvm::Module *module, llvm::Type *type);

int64_t get_llvm_int_val(const llvm::Value *value);
std::string get_llvm_type_str(const llvm::Type &type);
std::vector<int> llvm_flatten_struct(const llvm::Module *module, llvm::Type *type);
StructLayout llvm_flatten_struct_layout(const llvm::Module *module, llvm::Type *type);

bool llvm_contains_no_ptr(llvm::Type *type);
bool cxx_demangle(const std::string &name, std::string &result);
std::string cxx_try_demangle(const std::string &name);
bool is_template_type(const std::string &t);
bool is_class_method(const std::string &method);
std::string get_class_name(const std::string &method);
std::string get_template_base(const std::string &method);
std::string remove_template(const std::string &name);
std::string remove_func_args(const std::string &name);
std::string remove_func_paran(const std::string &name);
