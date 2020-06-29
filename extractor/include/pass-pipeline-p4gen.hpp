#ifndef _MORULA_PASS_PIPELINE_P4GEN_HPP_
#define _MORULA_PASS_PIPELINE_P4GEN_HPP_

#include "pass.hpp"
#include "pass-llvm.hpp"
#include "pipeline-ir.hpp"
#include "pass-pipeline.hpp"
#include "pass-p4gen.hpp"
#include "formatter.hpp"

namespace Morula {
    struct P4GlobalState {
        enum class Type {
            TABLE,
            REGISTER,
        };
        Type type;

        std::string name;

        bool default_only = false;
        std::vector<int> tab_key_sizes;
        std::vector<int> tab_val_sizes;

        std::vector<PipeIR::Var *> key_vars;

        std::string default_action;
        std::vector<std::string> actions;
    };

    struct P4Stage {
        int stage_idx;
        bool is_table_lookup = false;
        std::vector<std::unique_ptr<PipeIR::Operation>> ops;
        std::vector<std::string> code;
    };

    struct P4Action {
        std::string action_name;
        std::shared_ptr<Code> code;
    };

    struct P4Prog {
        std::shared_ptr<PipeIR::Var> prev_stage_var;
        std::shared_ptr<PipeIR::Var> next_stage_var;
        std::vector<std::unique_ptr<P4GlobalState>> states;
        std::vector<std::unique_ptr<P4Stage>> stages;
    };

    struct P4CodeGenCtx {
        std::unique_ptr<P4Prog> prog;
        std::shared_ptr<NameFactory> name_gen;
        std::shared_ptr<Code> code;

        std::unordered_map<PipeIR::Var *, std::string> var_names;
        std::unordered_map<PipeIR::GlobalState *, std::string> state_names;
    };

    DECLARE_PASS(SplitPipeStage, PipeCtx, PipeCtx);
    DECLARE_PASS(GenP4Prog, PipeCtx, P4CodeGenCtx);
}

#endif
