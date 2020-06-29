#ifndef __MORULA_LLVM_VARTRACE_HPP__
#define __MORULA_LLVM_VARTRACE_HPP__


#include "llvm-incl.hpp"
#include <unordered_map>
#include <unordered_set>
#include <iostream>
#include <string>


namespace Morula {
    namespace LLVMAnalysis {
        struct RegInfo {
            enum class Type {
                NUMBER,
                POINTER,
                GLOBAL_STATE_PTR,
                HEADER_PTR,
            };
            Type t;
            
            std::string header;
            std::string field;
            bool is_known_obj = false;
            std::string global_state;
        };

        class Analyzer {
        public:
            std::unordered_map<llvm::Value *, RegInfo> cache_;

            RegInfo get_reg_info(llvm::Value *reg);
        };
    }
}


#endif
 
