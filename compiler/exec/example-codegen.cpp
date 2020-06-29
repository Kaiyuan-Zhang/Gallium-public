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

    auto partition_result = P4IR::partition_hir(ele);

    std::ofstream file;
    file.open("offloaded.p4", std::ios::trunc);
    P4IR::print_p4_prog_tofino(*partition_result.ingress_prog, file);
    file << std::endl;
    file.close();

    std::ofstream header_file;
    header_file.open("cpu.h");
    std::ofstream source_file;
    source_file.open("cpu.c");
    DpdkGen codegen("cpu", header_file, source_file);
    m->elements.insert({"cpu", partition_result.ele});
    codegen.PrintCode(*m);

    header_file.close();
    source_file.close();
    return 0;
}
