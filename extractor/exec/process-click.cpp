#include <iostream>
#include <fstream>
#include <unordered_map>
#include <unordered_set>
#include <queue>
#include "llvm-incl.hpp"
#include "target-lang.hpp"
#include "target-codegen.hpp"
#include "target-partition.hpp"
#include "pass-llvm.hpp"
#include "pass-preprocess.hpp"
#include "pass-labeling.hpp"
#include "pass-p4gen.hpp"
#include "utils.hpp"
#include <cxxabi.h>


int main(int argc, char *argv[]) {
    llvm::LLVMContext llvm_ctx;
    llvm::SMDiagnostic err;
    if (argc < 2) {
        printf("Usage: %s <ir-file> [-o cpp-file] [-dot dot-file]\n", argv[0]);
        return -1;
    }

    const std::string ir_filename = std::string(argv[1]);
    //const std::string function_name = std::string(argv[2]);
    std::string dot_filename = "";
    std::string output_file = "";
    for (int i = 2; i < argc; i++) {
        if (std::string(argv[i]) == "-o") {
            if (i >= argc - 1) {
                std::cerr << "Expect parameter for option!" << std::endl;
                exit(-1);
            }
            i++;
            output_file = argv[i];
        } else if (std::string(argv[i]) == "-dot") {
            if (i >= argc - 1) {
                std::cerr << "Expect parameter for option!" << std::endl;
                exit(-1);
            }
            i++;
            dot_filename = argv[i];
        }
    }

    auto module = llvm::parseIRFile(ir_filename, err, llvm_ctx);

    if (module == nullptr) {
        err.print("prog", llvm::errs());
    }

    //auto func = module->getFunction(function_name);
    llvm::Function *func = nullptr;
    int num_entries = 0;
    for (auto iter = module->begin(); iter != module->end(); iter++) {
        auto func_name = iter->getName().str();
        std::string demangled;
        if (cxx_demangle(func_name, demangled)) {
            auto pos = demangled.find("::push(int, Packet*)");
            if (pos != std::string::npos) {
                func = module->getFunction(func_name);
                num_entries++;
            }
        }
    }

    if (num_entries > 1) {
        assert(false && "found multiple entries");
    } else if (num_entries == 0) {
        assert(false && "could not find entry");
    }

    auto ctx = std::make_unique<Morula::LLVMCtx>();
    ctx->module = std::move(module);
    ctx->name_gen = std::make_shared<NameFactory>("_");
    ctx->entry_func = func;

    using UpdateMeta = Morula::PassSeq<Morula::UpdateVarSource<Morula::PassCtx>,
                                       Morula::UpdateEdges,
                                       Morula::UpdateDeps>;
    
    using Passes = Morula::PassSeq<Morula::FromLLVM,
                                   Morula::RemoveFunc,
                                   Morula::TranslateAlloca,
                                   Morula::UpdateVarSource<Morula::PassCtx>,
                                   Morula::ClickPktOp,
                                   Morula::ClickStateOp,
                                   Morula::UpdateEdges,
                                   Morula::UpdateDeps,
                                   Morula::RewriteEntryOp,
                                   UpdateMeta,
                                   Morula::RemoveUnusedInst,
                                   Morula::Labeling<Morula::P4Label>>;
    auto labeled = Passes::apply_pass(std::move(ctx));
    
    if (dot_filename != "") {
        std::ofstream dot_file;
        dot_file.open(dot_filename + ".dot");
        const auto &labels_dict = labeled->labels;
        auto inst_color = [&](InstID id) -> std::string {
                              using namespace Morula;
                              auto labels = labels_dict.find(id)->second;
                              if (labels.find(PREFIX) != labels.end()
                                  && labels.find(SUFFIX) != labels.end()) {
                                  return "#90ee90";
                              } else if (labels.find(PREFIX) != labels.end()) {
                                  return "lightblue";
                              } else if (labels.find(SUFFIX) != labels.end()) {
                                  return "lightyellow";
                              } else {
                                  return "lightgray";
                              }
                          };
        Target::generate_dot_file(dot_file, labeled->blocks, inst_color);
        dot_file.close();
    }

    auto splitted = Morula::SplitByLabel::apply_pass(std::move(labeled));

    auto prefix = std::move(splitted->prefix);
    auto cpu = std::move(splitted->cpu);
    auto suffix = std::move(splitted->suffix);

    if (dot_filename != "") {
        auto const_white = [](InstID id) -> std::string { return "white"; };        
        std::ofstream dot_file;
        
        dot_file.open(dot_filename + "_prefix.dot");
        Target::generate_dot_file(dot_file, prefix->blocks, const_white);
        dot_file.close();

        dot_file.open(dot_filename + "_cpu.dot");
        Target::generate_dot_file(dot_file, cpu->blocks, const_white);
        dot_file.close();

        dot_file.open(dot_filename + "_suffix.dot");
        Target::generate_dot_file(dot_file, suffix->blocks, const_white);
        dot_file.close();
    }

    using P4CodeGen = Morula::PassSeq<Morula::RemoveUnusedInst,
                                      Morula::P4ExtendCtx,
                                      Morula::P4Alloca,
                                      Morula::P4Map,
                                      Morula::P4EntryAlloc,
                                      Morula::P4SplitAction,
                                      Morula::P4AssignMeta,
                                      Morula::P4CodeGen>;

    auto prefix_code = P4CodeGen::apply_pass(std::move(prefix));
    auto suffix_code = P4CodeGen::apply_pass(std::move(suffix));

    // print metadata for prefix
    // std::cerr << "prefix entries:" << std::endl;
    // for (auto &kv : prefix_code->metadata_entries) {
    //     std::cerr << kv.first << " : {";
    //     for (auto sz : kv.second) {
    //         std::cerr << "i" << sz * 8 << ", ";
    //     }
    //     std::cerr << "}" << std::endl;
    // }

    // for (auto &kv : prefix_code->tables) {
    //     std::cerr << "Table " << kv.first << " : ";
    //     kv.second.print(std::cerr);
    //     std::cerr << std::endl;
    // }


    Target::P4::PrintConf conf;
    conf.metadata_name = "ig_intr_md_for_tm";
    
    auto code = prefix_code->prog.code(conf);
    std::cout << code << std::endl;
    
    return 0;
}
