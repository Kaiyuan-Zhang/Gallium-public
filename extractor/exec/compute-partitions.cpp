#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include <queue>
#include <memory>
#include "llvm-incl.hpp"
#include "target-lang.hpp"
#include "utils.hpp"
#include <cxxabi.h>
#include "placer.hpp"
#include "opt-pass.hpp"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <ir-file> [-o cpp-file] [-dot dot-file]\n", argv[0]);
        return -1;
    }

    const std::string ir_filename = std::string(argv[1]);
    CompileCtx ctx(ir_filename);
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

    //auto func = module->getFunction(function_name);
    llvm::Function *func = nullptr;
    int num_entries = 0;
    std::string handler_func_name = "";
    for (auto iter = ctx.module->begin(); iter != ctx.module->end(); iter++) {
        auto func_name = iter->getName().str();
        std::string demangled;
        if (cxx_demangle(func_name, demangled)) {
            auto pos = demangled.find("::push(int, Packet*)");
            if (pos != std::string::npos) {
                handler_func_name = func_name;
                num_entries++;
            }
        }
    }

    if (num_entries > 1) {
        assert(false && "found multiple entries");
    } else if (num_entries == 0) {
        assert(false && "could not find entry");
    }

    ctx.load_blocks(handler_func_name);
}
