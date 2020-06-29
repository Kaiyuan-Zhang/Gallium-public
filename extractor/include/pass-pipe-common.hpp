#ifndef __MORULA_PASS_PIPE_COMMON_HPP__
#define __MORULA_PASS_PIPE_COMMON_HPP__

#include "pass.hpp"
#include "pass-llvm2pipe.hpp"
#include "pipeline-ir.hpp"

namespace Morula {
    DECLARE_PASS(PipeIRRemoveUnused, PipeIRCtx, PipeIRCtx);
}

#endif
