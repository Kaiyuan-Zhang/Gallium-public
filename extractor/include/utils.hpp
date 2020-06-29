#ifndef _UTILS_HPP_
#define _UTILS_HPP_


#include <iostream>
#include <unordered_map>
#include <string>

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
bool is_llvm_constant(const llvm::Value &value);
uint64_t get_type_size(const llvm::Module *module, llvm::Type *type);

int64_t get_llvm_int_val(const llvm::Value *value);
std::string get_llvm_type_str(const llvm::Type &type);
std::vector<int> llvm_flatten_struct(const llvm::Module *module, llvm::Type *type);
StructLayout llvm_flatten_struct_layout(const llvm::Module *module, llvm::Type *type);

bool llvm_contains_no_ptr(llvm::Type *type);

class NameFactory {
    std::unordered_map<std::string, uint64_t> name_map_;
    std::string delimiter_;
public:
    NameFactory();
    NameFactory(const std::string &delimiter);
    std::string GetUniqueName(const std::string &base_name);
    std::string gen(const std::string &base_name) { return this->GetUniqueName(base_name);}
    std::string operator()(const std::string &base_name) {
        return GetUniqueName(base_name);
    }
};


bool cxx_demangle(const std::string &name, std::string &result);
bool is_template_type(const std::string &t);
bool is_class_method(const std::string &method);
std::string get_class_name(const std::string &method);
std::string get_template_base(const std::string &method);
std::string remove_template(const std::string &name);
std::string remove_func_args(const std::string &name);
std::string remove_func_paran(const std::string &name);


bool str_begin_with(const std::string &s, const std::string &prefix);

std::string str_escape_html(const std::string &s);
std::string str_line_break(const std::string &s, int line_limit, const std::string &delimiter);

std::string str_replace_first(const std::string &s, const std::string &from, const std::string &to);
std::string str_replace_all(const std::string &s, const std::string &from, const std::string &to);


#endif /* _UTILS_HPP_ */
