#ifndef _TARGET_CODEGEN_HPP_
#define _TARGET_CODEGEN_HPP_

#include <iostream>
#include "target-lang.hpp"
#include "utils.hpp"

namespace Target {

    class CodeGenException {
    public:
        CodeGenException(const std::string &m) : msg(m) {}
        
        std::string msg;
    };

    class CodeGen {
    public:
        CodeGen(std::unordered_map<std::string, BasicBlock *> &blocks,
                llvm::Module *module,
                std::vector<std::string> &entries);

        virtual std::vector<std::string> gen_code() const = 0;
        void print_code(std::ostream &os) const;
    protected:
        std::unordered_map<std::string, BasicBlock *> &blocks_;
        std::vector<std::string> &entries_;
        llvm::Module *module_;
    };

    
    class CppGen : public CodeGen {
    public:
        CppGen(std::unordered_map<std::string, BasicBlock *> &blocks,
               llvm::Module *module,
               std::vector<std::string> &entries,
               const GlobalTypes &types);

        virtual std::vector<std::string> gen_code() const override;

    protected:
        const GlobalTypes &types_;
    };

    class P4Gen : public CodeGen {
    public:
        P4Gen(std::unordered_map<std::string, BasicBlock *> &blocks,
              std::vector<std::string> &entries);

        virtual std::vector<std::string> gen_code() const override;
    };
}

#endif /*_TARGET_CODEGEN_HPP_ */
