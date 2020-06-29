#pragma once

#include <iostream>
#include <optional>
#include "hilvl-ir.hpp"
#include "hir-common-pass.hpp"

class CodePrinter {
public:
    CodePrinter(std::ostream& os);

    void PrintLine(const std::string& line, std::optional<char> eol = ';', int indent_off = 0);
    void NewLine() { PrintLine("", std::nullopt); }
    void OpenBlock(const std::string& line, const std::string& open_str = "{");
    void CloseBlock(const std::string& s = "}");
protected:
    std::ostream& os_;
    size_t indent_lvl_;

    void PrintIndent();
};

class DpdkGen {
public:
    DpdkGen(const std::string& name, std::ostream& header, std::ostream& source);
    void PrintStructDef(
            HIR::Type* t,
            std::unordered_map<HIR::Type *, bool>& printed);
    void PrintFunction(HIR::Function* f, const HIR::Element* ele);
    void PrintOperation(HIR::Operation* op, bool need_decl = true);
    void PrintCode(const HIR::Module& m);
    std::string TypeName(HIR::Type* t);
    std::string VarName(std::shared_ptr<HIR::Var> v);
    std::string BBName(std::shared_ptr<HIR::BasicBlock> bb);
    std::string FuncName(const std::string& func_name, bool* is_built_in=nullptr);

protected:
    CodePrinter header_;
    CodePrinter source_;
    std::unordered_map<HIR::Type *, std::string> type_name_;
    std::unordered_map<std::shared_ptr<HIR::Var>, std::string> var_name_;
    std::unordered_map<std::shared_ptr<HIR::BasicBlock>, std::string> bb_name_;

    std::shared_ptr<HIR::Var> element_this_;
};
