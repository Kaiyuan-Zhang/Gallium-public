#ifndef _MORULA_PASS_LLVM2PIPE_
#define _MORULA_PASS_LLVM2PIPE_


#include "click-state.hpp"
#include "utils.hpp"
#include "llvm-vartrace.hpp"
#include "pipeline-ir.hpp"
#include "pass-pipeline.hpp"
#include "pass-pipeline-p4gen.hpp"
#include <climits>

namespace Morula {
    struct PipeIRCtx {
        std::unique_ptr<llvm::Module> module;
        std::shared_ptr<llvm::DataLayout> llvm_layout;
        std::vector<std::shared_ptr<PipeIR::VarType>> types;
        std::unordered_map<std::string, std::unique_ptr<PipeIR::Function>> funcs;
        std::string entry_name;
        std::shared_ptr<NameFactory> name_gen;

        std::unordered_map<std::string, std::shared_ptr<PipeIR::GlobalState>> states;

        std::unordered_map<llvm::Type *, std::shared_ptr<PipeIR::VarType>> type_mapping;

        static std::string get_func_name(llvm::Function *f);
        bool have_func(llvm::Function *f) const;
        void insert_func(llvm::Function * llvm_f, std::unique_ptr<PipeIR::Function> f);
        PipeIR::VarType *from_llvm_type(llvm::Type *t);

        std::shared_ptr<Click::ElementStateType> element_state;

        void clean_up(void); // used after pass to clean up temperary data
    };

    void generate_graphviz(std::ostream &os, const PipeIRCtx &ctx,
                           unsigned line_lenght_limit=UINT_MAX);
    DECLARE_PASS(LLVM2PipeP1, LLVMCtx, PipeIRCtx);
    DECLARE_PASS(PipeP1Inline, PipeIRCtx, PipeIRCtx);
    DECLARE_PASS(PipeUpdateUseDef, PipeIRCtx, PipeIRCtx);

    using LLVM2PipeSeq = PassSeq<LLVM2PipeP1, PipeP1Inline, PipeUpdateUseDef>;
}


#endif
