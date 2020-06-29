#include <iostream>
#include <fstream>
#include <unordered_map>
#include <unordered_set>
#include <queue>
#include "llvm-incl.hpp"
#include "click-state.hpp"
#include "target-lang.hpp"
#include "target-codegen.hpp"
#include "target-partition.hpp"
#include "pass-llvm.hpp"
#include "pass-preprocess.hpp"
#include "pass-pipeline.hpp"
#include "pass-llvm2pipe.hpp"
#include "pass-pipe-oprw.hpp"
#include "pass-pipe-common.hpp"
#include "pass-pipe-label.hpp"
#include "utils.hpp"
#include <cxxabi.h>


int main(int argc, char *argv[]) {
    llvm::LLVMContext llvm_ctx;
    llvm::SMDiagnostic err;
    if (argc < 3) {
        printf("Usage: %s <ir-file> <element-name> [-dot dot-file]\n", argv[0]);
        return -1;
    }

    const std::string ir_filename = std::string(argv[1]);
    const std::string element_name = std::string(argv[2]);
    //const std::string function_name = std::string(argv[2]);
    std::string dot_filename = "";
    std::string output_file = "";
    for (int i = 3; i < argc; i++) {
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
            auto pos = demangled.find(element_name + "::push(int, Packet*)");
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

    llvm::StructType *element_t = nullptr;
    std::string element_class_name = "class." + element_name;
    auto structs = module->getIdentifiedStructTypes();
    for (auto &s : structs) {
        if (s->getName() == element_class_name) {
            element_t = s;
            break;
        }
    }
    assert(element_t != nullptr);

    auto ctx = std::make_unique<Morula::LLVMCtx>();
    ctx->module = std::move(module);
    ctx->name_gen = std::make_shared<NameFactory>("_");
    ctx->entry_func = func;

    auto element_state = Morula::Click::parse_click_state(ctx->module.get(), element_t);
    Morula::Click::assign_state_name(element_state, *(ctx->name_gen));
    ctx->element_state = element_state;

    using Passes = Morula::PassSeq<Morula::LLVM2PipeSeq, Morula::PipePktOpRw, Morula::PipeIRRemoveUnused, Morula::PipeIRLabel>;
    auto pipe_ctx = Passes::apply_pass(std::move(ctx));
    std::ofstream dot_file;
    dot_file.open(dot_filename + ".dot");
    generate_graphviz(dot_file, *pipe_ctx, 30);
    dot_file.close();

    // also print all state op name
    for (auto &f_kv : pipe_ctx->funcs) {
        for (auto &s_kv : f_kv.second->bbs_) {
            for (auto &op : s_kv.second->ops) {
                if (op->type == Morula::PipeIR::Operation::Type::STATE_OP) {
                    std::cout << op->state_op_name << std::endl;
                }
            }
        }
    }
    return 0;
}
