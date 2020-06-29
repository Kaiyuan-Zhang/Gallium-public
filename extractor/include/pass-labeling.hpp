#ifndef _MORULA_PASS_LABELING_HPP_
#define _MORULA_PASS_LABELING_HPP_

#include "target-lang.hpp"
#include "pass.hpp"

namespace Morula {
    enum Label {
        PREFIX,
        CPU,
        SUFFIX,
    };

    using LabelUset = std::unordered_set<Label>;

    struct LabelCtx : public PassCtx {
        InstIDUmap<LabelUset> labels;

        LabelCtx() {}
        LabelCtx(PassCtx &&ctx): PassCtx(std::move(ctx)) {
            labels.clear();
        }
    };

    struct SplittedCtx {
        std::unique_ptr<PassCtx> prefix, cpu, suffix;
    };

    template <typename T>
    class Labeling : public Pass<Labeling<T>, PassCtx, LabelCtx> {
        friend class Pass<Labeling<T>, PassCtx, LabelCtx>;
        static std::unique_ptr<LabelCtx> pass_impl(std::unique_ptr<PassCtx> s) {
            auto ctx = std::make_unique<LabelCtx>(std::move(*s));
            // the label removal algorithm
            // first put ALL label on all instructions
            std::unordered_set<Label> all_labels = {PREFIX, CPU, SUFFIX};
            
            InstIDUset set1, set2;
            InstIDUset *frontier = &set1;
            InstIDUset *next_front = &set2;
            for (auto &kv : ctx->blocks) {
                auto insts = kv.second->insts_mut();
                for (int i = 0; i < insts.size(); i++) {
                    InstID id{kv.first, i};
                    if (T::dev_compatible(*insts[i])) {
                        ctx->labels[id] = all_labels;
                    } else {
                        ctx->labels[id] = {CPU};
                        frontier->insert(id);
                    }
                }
            }
            
            while (!frontier->empty()) {
                int delta = 0;

                next_front->clear();

                for (auto &id : *frontier) {
                    auto inst = ctx->get_inst(id);
                    if (ctx->inst_pre_req.find(id) != ctx->inst_pre_req.end()) {
                        // All instructions that \cc{inst} depends on CANNOT be suffix
                        for (auto &dep_id : ctx->inst_pre_req[id]) {
                            if (ctx->labels[dep_id].find(SUFFIX) != ctx->labels[dep_id].end()) {
                                next_front->insert(dep_id);
                            }
                            ctx->labels[dep_id].erase(SUFFIX);
                        }
                    }

                    if (ctx->inst_rev_dep.find(id) != ctx->inst_rev_dep.end()) {
                        // All instructions that depends on \cc{inst} CANNOT be prefix
                        for (auto &dep_id : ctx->inst_rev_dep[id]) {
                            if (ctx->labels[dep_id].find(PREFIX) != ctx->labels[dep_id].end()) {
                                next_front->insert(dep_id);
                            }
                            ctx->labels[dep_id].erase(PREFIX);
                        }
                    }
                }

                if (delta == 0) {
                    break;
                }

                InstIDUset *tmp = frontier;
                frontier = next_front;
                next_front = tmp;
            }
            return ctx;
        }
    };

    struct P4Label {
        static bool dev_compatible(Target::Instruction &inst);
    };

    DECLARE_PASS(SplitByLabel, LabelCtx, SplittedCtx);
}

#endif /* _MORULA_PASS_LABELING_HPP_ */
