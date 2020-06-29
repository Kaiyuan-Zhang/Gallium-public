#include "llvm-load.hpp"

int main(int argc, char *argv[]) {
    LLVMStore ir_store;

    ir_store.load_directory(argv[1]);
    ir_store.print_all_elements();
    return 0;
}
