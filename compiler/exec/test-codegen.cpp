#include "hilvl-ir.hpp"
#include "hir-common-pass.hpp"
#include "llvm-load.hpp"
#include "hir-pktop.hpp"
#include "hir-stateop.hpp"
#include "hir-partition.hpp"
#include "hir-dpdkgen.hpp"
#include "hir-p4.hpp"
#include "p4-ir.hpp"
#include <iostream>
#include <fstream>

int main(int argc, char *argv[]) {
    LLVMStore store;
    store.load_directory("../../click-llvm-ir/ele_ll/tcpudp");
    store.load_directory("../../click-llvm-ir/lib_ll");

    auto m = std::make_shared<HIR::Module>();
    auto ele = std::make_shared<HIR::Element>(*m, store, "MyIPRewriter");
    element_function_inline(*ele);
    replace_packet_access_op(*ele, CommonHdr::default_layout);
    remove_unused_phi_entry(*ele->entry());

    split_stateptr_branch(*ele);
    replace_vector_ops(*ele);
    replace_map_ops(*ele);
    replace_regular_struct_access(*ele->entry());
    replace_packet_meta_op(*ele);
    remove_unused_ops(*ele);

    // auto partition_result = P4IR::partition_hir(ele);

    P4IR::P4OffloadResult result;
    HIR::LabelInitFn init_fn = P4IR::p4_initial_label;
    HIR::label(*ele, init_fn);
    auto partition_result = partition(*ele->entry());
    result.ingress_prog = P4IR::p4_program_from_function_v2(ele, partition_result.pre, false);
    P4IR::print_p4_prog_tofino(*result.ingress_prog, std::cout);
    return 0;
    result.egress_prog = P4IR::p4_program_from_function_v2(ele, partition_result.post, true);
    result.ele = std::make_shared<HIR::Element>(*ele);
    result.ele->funcs[ele->entry_func_idx()] = partition_result.cpu;
    return 0;
}
