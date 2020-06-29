#include "click-state.hpp"

int main(int argc, char *argv[]) {
    llvm::LLVMContext llvm_ctx;
    llvm::SMDiagnostic err;
    if (argc < 3) {
        printf("Usage: %s <ir-file> <element-name>\n", argv[0]);
        return -1;
    }

    const std::string ir_filename = std::string(argv[1]);
    const std::string element_name = std::string(argv[2]);

    auto module = llvm::parseIRFile(ir_filename, err, llvm_ctx);

    if (module == nullptr) {
        std::cerr << "failed to parse IR file" << std::endl;
        return -1;
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
    auto s = Morula::Click::parse_click_state(module.get(), element_t);
    s->print(std::cout, 0);
    std::cout << std::endl;
    return 0;
}
