#pragma once

#include "hilvl-ir.hpp"
#include "hir-common-pass.hpp"
#include "hir-partition.hpp"
#include "p4-ir.hpp"

namespace P4IR {
    struct P4OffloadResult {
        std::shared_ptr<Program> ingress_prog;
        std::shared_ptr<HIR::Element> ele;
        std::shared_ptr<Program> egress_prog;
    };

    void p4_initial_label(const HIR::Module& m, const HIR::Operation& op, HIR::LabelSet& labels);
    void print_element_with_label(std::ostream& os, const HIR::Element& ele);
    P4OffloadResult partition_hir(std::shared_ptr<HIR::Element> ele);

    std::shared_ptr<Program> p4_program_from_function(
            std::shared_ptr<HIR::Element> ele,
            std::shared_ptr<HIR::Function> func,
            bool is_egress);
}
