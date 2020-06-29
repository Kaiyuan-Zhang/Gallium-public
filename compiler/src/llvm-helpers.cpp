#include "llvm-helpers.hpp"
#include <iostream>
#include <cassert>
#include <sstream>
#include <cxxabi.h>
#include <algorithm>

std::string get_llvm_inst_str(const llvm::Instruction *inst) {
    std::string res;
    llvm::raw_string_ostream stream{res};
    inst->print(stream);
    stream.str();
    return res;
}

std::string get_llvm_name(const llvm::Value &value) {
    std::string res;
    llvm::raw_string_ostream stream{res};
    value.printAsOperand(stream, false);
    stream.str();
    return res;
}

std::string get_llvm_type_name(llvm::Type *t) {
    std::string res;
    llvm::raw_string_ostream stream{res};
    t->print(stream);
    stream.str();
    return res;
}

bool is_llvm_constant(const llvm::Value &value) {
    auto val_name = get_llvm_name(value);
    if (val_name == "null") {
        return true;
    }

    if (val_name == "true") {
        return true;
    }

    if (val_name == "false") {
        return true;
    }

    if (val_name == "undef") {
        return true;
    }

    if (const llvm::ConstantInt* CI = llvm::dyn_cast<const llvm::ConstantInt>(&value)) {
        // constant integer
        return true;
    }
    return false;
}

uint64_t get_type_size(const llvm::Module *module, llvm::Type *type) {
    llvm::DataLayout* dl = new llvm::DataLayout(module);
    uint64_t type_size = dl->getTypeStoreSize(type);
    delete dl;
    return type_size;
}

int64_t get_llvm_int_val(const llvm::Value *value) {
    if (const llvm::ConstantInt* CI = llvm::dyn_cast<llvm::ConstantInt>(value)) {
        if (CI->getBitWidth() <= 64) {
            return CI->getSExtValue();
        }
    }
    assert(false && "not an integer constant");
    throw "not an integer constant";
}

std::string get_llvm_type_str(const llvm::Type &type) {
    std::string res;
    llvm::raw_string_ostream stream{res};
    type.print(stream);
    stream.str();
    return res;
}

bool llvm_contains_no_ptr(llvm::Type *t) {
    if (t->isPointerTy()) {
        std::cerr << "found pointer: " << get_llvm_type_str(*t) << std::endl;
        return false;
    }

    if (t->isIntegerTy()) {
        return true;
    }

    if (t->isStructTy()) {
        auto struct_t = static_cast<llvm::StructType *>(t);
        auto num_elements = struct_t->getNumElements();
        for (auto i = 0; i < num_elements; i++) {
            // std::cerr << "struct : " << get_llvm_type_str(*t)
            //           << " : " << i << std::endl;
            auto ele_t = struct_t->getElementType(i);
            if (!llvm_contains_no_ptr(ele_t)) {
                return false;
            }
        }
        return true;
    }

    if (t->isVectorTy()) {
        assert(false && "vector not supported");
        return false;
    }

    if (t->isArrayTy()) {
        auto ele_t = t->getArrayElementType();
        return llvm_contains_no_ptr(ele_t);
    }

    return false;
}

std::vector<int> llvm_flatten_struct(const llvm::Module *m, llvm::Type *t) {
    std::vector<int> result;
    if (t->isStructTy()) {
        auto struct_t = static_cast<llvm::StructType *>(t);
        auto n_eles = struct_t->getNumElements();
        for (auto i = 0; i < n_eles; i++) {
            auto ele_t = struct_t->getElementType(i);
            auto segments = llvm_flatten_struct(m, ele_t);
            for (auto seg : segments) {
                result.push_back(seg);
            }
        }
    } else if (t->isArrayTy()) {
        auto ele_t = t->getArrayElementType();
        auto n = t->getArrayNumElements();
        auto segments = llvm_flatten_struct(m, ele_t);
        for (auto i = 0; i < n; i++) {
            for (auto seg : segments) {
                result.push_back(seg);
            }
        }
    } else {
        result.push_back((int)get_type_size(m, t));
    }
    return result;
}

StructLayout llvm_flatten_struct_layout(const llvm::Module *module, llvm::Type *type) {
    StructLayout result;
    llvm::DataLayout *dl = new llvm::DataLayout(module);
    if (type->isStructTy()) {
        const llvm::StructLayout* sl = dl->getStructLayout(static_cast<llvm::StructType *>(type));
        auto struct_t = static_cast<llvm::StructType *>(type);
        auto n_eles = struct_t->getNumElements();
        for (auto i = 0; i < n_eles; i++) {
            auto ele_t = struct_t->getElementType(i);
            auto segments = llvm_flatten_struct_layout(module, ele_t);
            auto off = sl->getElementOffset(i);
            for (auto seg : segments.fields) {
                StructLayout::FieldInfo field;
                field.offset = off + seg.offset;
                field.size = seg.size;
                result.fields.push_back(field);
            }
        }
    } else if (type->isArrayTy()) {
        auto ele_t = type->getArrayElementType();
        auto n = type->getArrayNumElements();
        auto segments = llvm_flatten_struct_layout(module, ele_t);
        int size = (int)get_type_size(module, ele_t);
        for (auto i = 0; i < n; i++) {
            auto off = i * size;
            for (auto seg : segments.fields) {
                StructLayout::FieldInfo field;
                field.offset = off + seg.offset;
                field.size = seg.size;
                result.fields.push_back(field);
            }
        }
    } else {
        StructLayout::FieldInfo field;
        field.offset = 0;
        field.size = (int)get_type_size(module, type);
        result.fields.push_back(field);
    }
    delete dl;
    return result;
}

bool cxx_demangle(const std::string &name, std::string &result) {
    size_t size = 0;
    int status = 0;
    char *n = abi::__cxa_demangle(name.c_str(), NULL, &size, &status);
    std::string func_name = "";
    if (n != NULL) {
        func_name = std::string(n);
        result = func_name;
        return true;
    } else {
        return false;
    }
}

std::string cxx_try_demangle(const std::string &name) {
    std::string demangled = "";
    if (cxx_demangle(name, demangled)) {
        return demangled;
    } else {
        return name;
    }
}

bool is_template_type(const std::string &t) {
    // check if there are matching number of < and >
    int level = 0;
    bool found = false;
    for (int i = 0; i < t.length(); i++) {
        if (t[i] == '<') {
            level++;
            found = true;
        }
        if (t[i] == '>') {
            level--;
        }
    }
    return found && (level == 0);
}

bool is_class_method(const std::string &method) {
    auto pos = method.find("::");
    return (pos != std::string::npos);
}

std::string get_class_name(const std::string &method) {
    auto pos = method.find("::");
    return method.substr(0, pos);
}

std::string get_template_base(const std::string &method) {
    auto pos = method.find("<");
    return method.substr(0, pos);
}

std::string remove_template(const std::string &s) {
    std::vector<char> no_tmp_vec;
    int lvl = 0;
    for (auto i = 0; i < s.length(); i++) {
        char c = s[i];
        switch (c) {
        case '<':
            lvl++;
            break;
        case '>':
            lvl = std::max(0, lvl - 1);
            break;
        }
        if (lvl == 0 && c != '>') {
            no_tmp_vec.push_back(c);
        }
    }
    std::string no_tmp_str(no_tmp_vec.begin(), no_tmp_vec.end());
    return no_tmp_str;
}

std::string remove_func_args(const std::string &s) {
    std::vector<char> result_vec;
    int lvl = 0;
    for (auto i = 0; i < s.length(); i++) {
        char c = s[i];
        switch (c) {
        case '(':
            lvl++;
            break;
        case ')':
            lvl = std::max(0, lvl - 1);
            break;
        }
        if (lvl == 0 && c != ')') {
            result_vec.push_back(c);
        }
    }
    std::string result_str(result_vec.begin(), result_vec.end());
    return result_str;
}

std::string remove_func_paran(const std::string &name) {
    auto pos = name.find("(");
    if (pos != std::string::npos) {
        return name.substr(0, pos);
    }
    return name;
}

std::string str_escape_html(const std::string &s) {
    static std::unordered_map<char, std::string> escape_dict = {
        {'&', "&amp;"},
        {'<', "&lt;"},
        {'>', "&gt;"},
        {'"', "&quot;"},
        {'\'', "&#39;"},
        {'\n', "<br/>"},
    };
    std::string result;
    for (int i = 0; i < s.size(); i++) {
        if (escape_dict.find(s[i]) != escape_dict.end()) {
            result = result + escape_dict.find(s[i])->second;
        } else {
            result.push_back(s[i]);
        }
    }
    return result;
}

std::string str_line_break(const std::string &s, int line_limit, const std::string &delimiter) {
    std::vector<std::string> lines;
    int i = 0;
    if (line_limit < 0) {
        return s;
    }
    while (i < s.length()) {
        int step_len = std::min(line_limit, (int)s.length() - i);
        lines.push_back(s.substr(i, line_limit));
        i += step_len;
    }
    std::string result;
    for (int i = 0; i < lines.size(); i++) {
        result = result + lines[i];
        if (i + 1 < lines.size()) {
            result = result + delimiter;
        }
    }
    return result;
}

std::string str_replace_first(const std::string &s, const std::string &from, const std::string &to) {
    std::string result(s);
    auto pos = s.find(from);
    if (pos != std::string::npos) {
        result.replace(pos, from.length(), to);
    }
    return result;
}

std::string str_replace_all(const std::string &s, const std::string &from, const std::string &to) {
    std::string result(s);
    auto pos = s.find(from);
    while (pos != std::string::npos) {
        result.replace(pos, from.length(), to);
        pos = result.find(from);
    }

    return result;
}
