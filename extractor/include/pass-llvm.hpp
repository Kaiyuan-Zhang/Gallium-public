#ifndef _MORULA_PASS_LLVM_HPP_
#define _MORULA_PASS_LLVM_HPP_

#include "click-state.hpp"
#include "target-lang.hpp"
#include "pass.hpp"

#define DECL_PASS_SEQ(x)

namespace Morula {

    struct LLVMCtx {
        std::unique_ptr<llvm::Module> module;
        std::shared_ptr<NameFactory> name_gen;
        llvm::Function *entry_func;

        std::shared_ptr<Click::ElementStateType> element_state;
    };

    /*
     * FromLLVM Pass:
     * load llvm instructions as LLVMInst
     * Will also translate llvm phinode to our PhiInst
     */
    class FromLLVM : public Pass<FromLLVM, LLVMCtx, PassCtx> {
        friend class Pass<FromLLVM, LLVMCtx, PassCtx>;
        static std::unique_ptr<PassCtx> pass_impl(std::unique_ptr<LLVMCtx> s);
    };

    /* 
     * RemoveFunc Pass:
     * translate llvm call into CallInst
     * also remove llvm debug and lifetime func calls
     */
    class RemoveFunc : public Pass<RemoveFunc, PassCtx, PassCtx> {
        friend class Pass<RemoveFunc, PassCtx, PassCtx>;
        static std::unique_ptr<PassCtx> pass_impl(std::unique_ptr<PassCtx> s);
    };

    class TranslateAlloca : public Pass<TranslateAlloca, PassCtx, PassCtx> {
        friend class Pass<TranslateAlloca, PassCtx, PassCtx>;
        static std::unique_ptr<PassCtx> pass_impl(std::unique_ptr<PassCtx> s);
    };
}

#endif /* _MORULA_PASS_LLVM_HPP_ */
