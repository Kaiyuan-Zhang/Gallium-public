#ifndef _MORULA_PASS_PIPELINE_HPP_
#define _MORULA_PASS_PIPELINE_HPP_

#include "pass.hpp"
#include "pass-llvm.hpp"
#include "pipeline-ir.hpp"

namespace Morula {
    struct PrePipeCtx {
        std::unique_ptr<llvm::Module> llvm_module;
        std::unordered_map<PipeIR::uuid_t,
                           std::unique_ptr<PipeIR::PreStage>,
                           boost::hash<PipeIR::uuid_t>> stages;
        PipeIR::uuid_t root_stage_id;
        std::unordered_map<llvm::Function *, PipeIR::uuid_t> func_map;
        std::unordered_map<llvm::Function *, PipeIR::uuid_t> bb_map;
        std::unordered_map<llvm::BasicBlock *, PipeIR::uuid_t> bb_end_map;
    };

    struct PipeCtx {
        using dependency_map_t = std::unordered_map<PipeIR::Operation *,
                                                    std::unordered_set<PipeIR::Operation *>>;

        std::unique_ptr<PipeIR::Prog> program;
        dependency_map_t dependency;
        dependency_map_t rev_dep;

        std::unordered_map<PipeIR::Operation *,
                           std::unordered_set<std::string>> labels;
    };

    bool should_inline(llvm::CallInst *call);
    bool should_ignore_inst(llvm::Instruction *inst);
    std::string get_bb_name_for_graphviz(const std::string &s);
    void generate_graphviz(std::ostream &os, const PrePipeCtx &ctx);
    void generate_graphviz(std::ostream &os, const PipeCtx &ctx);

    PipeIR::VarType *from_llvm_type(llvm::Type *t);

    DECLARE_PASS(LLVM2PrePipe, LLVMCtx, PrePipeCtx);
    DECLARE_PASS(LLVM2Pipe, LLVMCtx, PipeCtx);
    DECLARE_PASS(PrePipe2Pipe, PrePipeCtx, PipeCtx);

    DECLARE_PASS(PipeDataDep, PipeCtx, PipeCtx);
    DECLARE_PASS(PipeLabel, PipeCtx, PipeCtx);
}


#endif
