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

    struct StructMetaMapping {
        struct Entry {
            std::string var_name;
            int bw;
        };
        std::vector<StructMetaMapping> fields;
        Entry unit;

        bool is_unit() const { return fields.size() == 0; }
        std::vector<Entry> get_flattened_metas() const;
        Entry struct_get(const std::vector<int>& indices) const;
    };

    struct HIRP4Function {
        std::vector<std::shared_ptr<HIR::Type>> arg_types;
        std::vector<std::shared_ptr<HIR::Var>> args;

        std::vector<std::shared_ptr<HIR::Var>> extra_consts;

        // sequence of stages
        std::vector<std::shared_ptr<HIR::BasicBlock>> bbs;
        HIR::Module* m;
    };

    struct TranslateCtx {
        std::unordered_map<HIR::Var *, std::string> meta_mapping;
        std::unordered_map<HIR::Var *, std::string> transferred_vars;
        std::unordered_map<HIR::Var *, StructMetaMapping> alloca_meta_mapping;
        std::unordered_map<
            std::shared_ptr<HIR::BasicBlock>,
            std::unordered_set<std::shared_ptr<HIR::BasicBlock>>> from;
        std::unordered_map<std::string, int> meta_bw;

        std::unordered_map<HIR::Var *, std::shared_ptr<HIR::Var>> map_hit_var;

        bool is_egress = false;
    };

    void print_p4_func(std::ostream& os, const HIRP4Function& func);

    void p4_prog_default_init(Program& prog);
    void p4_prog_add_stages(Program& prog, TranslateCtx& ctx, HIRP4Function& func);
    std::shared_ptr<Program> p4_program_from_function_v2(
            std::shared_ptr<HIR::Element> ele,
            std::shared_ptr<HIR::Function> func,
            bool is_egress);

    std::shared_ptr<Program> p4_program_from_function(
            std::shared_ptr<HIR::Element> ele,
            std::shared_ptr<HIR::Function> func,
            bool is_egress);
}
