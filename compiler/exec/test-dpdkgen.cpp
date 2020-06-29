#include "hilvl-ir.hpp"
#include "hir-common-pass.hpp"
#include "llvm-load.hpp"
#include "hir-pktop.hpp"
#include "hir-stateop.hpp"
#include "hir-dpdkgen.hpp"
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
    remove_unused_ops(*ele);

    m->elements.insert({ele->name(), ele});

    ele->print(std::cout);

    std::ofstream header_file;
    header_file.open("foo.h");
    std::ofstream source_file;
    source_file.open("foo.c");
    DpdkGen codegen("foo", header_file, source_file);
    codegen.PrintCode(*m);

    header_file.close();
    source_file.close();

    return 0;
}
