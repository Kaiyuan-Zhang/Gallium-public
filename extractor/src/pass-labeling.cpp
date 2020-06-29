#include "pass-labeling.hpp"
#include <queue>

using namespace Target;

namespace Morula {

    bool P4Label::dev_compatible(Instruction &inst) {
        return can_be_p4(inst);
    }

    void peel_insts(LabelCtx &ctx, PassCtx &dst,
                    const std::function<bool(const LabelUset&)> &predicate) {
        dst.blocks.clear();
        for (auto &kv : ctx.blocks) {
            auto blk = kv.second;
            auto insts = blk->insts_mut();

            BasicBlock::InstList ns;
            for (int i = 0; i < insts.size(); i++) {
                InstID id{kv.first, i};
                auto labels = ctx.labels[id];
                if (predicate(labels)) {
                    ns.push_back(insts[i]);
                }
            }
            auto new_blk = std::make_shared<BasicBlock>(kv.first, ns);
            if (blk->is_conditional()) {
                new_blk->add_branch(blk->branch_cond(),
                                    blk->t_branch(),
                                    blk->f_branch());
            } else {
                new_blk->add_next(blk->next_bb());
            }
            // TODO: remove empty basic blocks
            
            dst.blocks.insert({kv.first, new_blk});
        }
    }
    
    PASS_IMPL(SplitByLabel, s) {
        auto result = std::make_unique<SplittedCtx>();
        result->prefix = std::make_unique<PassCtx>();
        result->cpu = std::make_unique<PassCtx>();
        result->suffix = std::make_unique<PassCtx>();
        
        result->prefix->llvm_module = s->llvm_module;
        result->cpu->llvm_module = s->llvm_module;
        result->suffix->llvm_module = s->llvm_module;

        result->prefix->name_gen = s->name_gen;
        result->cpu->name_gen = s->name_gen;
        result->suffix->name_gen = s->name_gen;

        peel_insts(*s, *result->prefix, [&](const LabelUset &labels) -> bool {
                                            return labels.find(PREFIX) != labels.end();
                                        });

        peel_insts(*s, *result->suffix, [&](const LabelUset &labels) -> bool {
                                            return labels.find(PREFIX) == labels.end()
                                                && labels.find(SUFFIX) != labels.end();
                                        });
        peel_insts(*s, *result->cpu, [&](const LabelUset &labels) -> bool {
                                         return labels.size() == 1
                                             && labels.find(CPU) != labels.end();
                                     });
        
        return result;
    }
}
