#pragma once

#include "hilvl-ir.hpp"
#include "hir-common-pass.hpp"

namespace HIR {
    void split_stateptr_branch(Element& ele);
    void replace_vector_ops(Element& ele);
    void replace_map_ops(Element& ele);
    void replace_fixsized_array_ops(Element& ele);

    void replace_regular_struct_access(Function& func);
}
