#ifndef __MORULA_PIPE_OPRW_HPP__
#define __MORULA_PIPE_OPRW_HPP__

#include "pass.hpp"
#include "pipeline-ir.hpp"
#include "pass-llvm2pipe.hpp"

#include "headerdef.hpp"

namespace Morula {
    struct PktPtrInfo {
        bool is_pkt_hdr_ptr = false;
        bool is_pkt_obj = false;
        bool have_offset = false;
        bool is_element_ptr = false;
        bool is_element_state_ptr = false;

        bool is_stack_ptr = false;

        std::vector<int> element_state_off;
        std::vector<Click::StateEntry> possible_state_entry;

        std::shared_ptr<PipeIR::Var> element_obj;
        int element_offset = 0;
        std::shared_ptr<PipeIR::Var> pkt_obj;
        std::string header_name;
        std::string field_name;
        std::shared_ptr<PipeIR::Var> off;
    };

    struct PktPtrTraceCtx {
        std::unordered_map<PipeIR::Var *, PktPtrInfo> cache;
        PipeIRCtx *pass_ctx;
    };

    PktPtrInfo find_pkt_ptr_info(PipeIR::Var *v, PktPtrTraceCtx &ctx);

    DECLARE_PASS(PipePktOpRw, PipeIRCtx, PipeIRCtx);
}

#endif
