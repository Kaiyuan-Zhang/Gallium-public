#ifndef _OPT_PASS_HPP_
#define _OPT_PASS_HPP_

#include "llvm-incl.hpp"
#include "target-lang.hpp"
#include <memory>
#include <vector>
#include <unordered_map>

struct CompileCtx {
    llvm::LLVMContext llvm_ctx;
    llvm::SMDiagnostic err;
    std::unique_ptr<llvm::Module> module;
    std::unordered_map<std::string,
                       std::shared_ptr<Target::BasicBlock>> blocks;
    std::vector<std::string> entry_blocks;

    CompileCtx(const std::string &fn);
    void load_blocks(const std::string &func_name);
};


using PartitionT = std::set<InstID, InstIDCmp>;

struct PartitionTHasher : std::unary_function<PartitionT, std::size_t> {
    std::size_t operator()(const PartitionT &part) const;
};

std::vector<PartitionT>
find_partitions(const std::unordered_map<std::string, Target::BasicBlock *> &blocks,
                const std::vector<std::string> &entries);


#endif /* _OPT_PASS_HPP_ */
