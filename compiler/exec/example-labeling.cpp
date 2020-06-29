#include "hilvl-ir.hpp"
#include "hir-common-pass.hpp"
#include "llvm-load.hpp"
#include "hir-pktop.hpp"
#include "hir-stateop.hpp"
#include "hir-partition.hpp"
#include "hir-p4.hpp"
#include <iostream>

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

    HIR::LabelInitFn init_fn = P4IR::p4_initial_label;
    HIR::label(*ele, init_fn);
    P4IR::print_element_with_label(std::cout, *ele);
    std::cout << std::endl;
    return 0;
}
