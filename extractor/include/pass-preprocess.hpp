#ifndef _MORULA_PASS_PREPROCESS_HPP_
#define _MORULA_PASS_PREPROCESS_HPP_

#include "target-lang.hpp"
#include "pass.hpp"

namespace Morula {

    struct RegInfo {
        bool is_pointer = false;
        int pointer_offset = 0;
        std::string var_name;
        std::string entry_name;
        std::string reg_type;

        // the states where the entry come from
        std::unordered_set<std::string> effected_states;
        
        RegInfo() {}
        RegInfo(bool a1, int a2, const std::string &a3, const std::string &a4):
            is_pointer(a1),
            pointer_offset(a2),
            var_name(a3),
            reg_type(a4) {
        }
    };

    struct TraceCtx;

    RegInfo trace_reg(const std::string &reg, TraceCtx &ctx);
    
    class ClickStateOp : public Pass<ClickStateOp, PassCtx, PassCtx> {
        friend class Pass<ClickStateOp, PassCtx, PassCtx>;
        static std::unique_ptr<PassCtx> pass_impl(std::unique_ptr<PassCtx> s);
    };
    
    class ClickPktOp : public Pass<ClickPktOp, PassCtx, PassCtx> {
        friend class Pass<ClickPktOp, PassCtx, PassCtx>;
        static std::unique_ptr<PassCtx> pass_impl(std::unique_ptr<PassCtx> s);
    };

    DECLARE_PASS(RewriteEntryOp, PassCtx, PassCtx);
}

std::ostream &operator<<(std::ostream &os, const Morula::RegInfo &info);

#endif /* _MORULA_PASS_PREPROCESS_HPP_ */
