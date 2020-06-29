#include "pass-pipe-common.hpp"

namespace Morula {
    PASS_IMPL(PipeIRRemoveUnused, s) {
        int num_op_removed;
        auto ctx = std::move(s);
        do {
            ctx = PipeUpdateUseDef::apply_pass(std::move(ctx));
            num_op_removed = 0;
            for (auto &f_kv : ctx->funcs) {
                for (auto &stage_kv : f_kv.second->bbs_) {
                    auto bb_ptr = stage_kv.second.get();
                    std::vector<std::unique_ptr<PipeIR::Operation>> new_ops;
                    for (auto &op : bb_ptr->ops) {
                        bool should_remove = (op->dst_var.size() != 0);
                        for (auto &v : op->dst_var) {
                            if (v->branch_uses.size() > 0
                                || v->uses.size() > 0
                                || v->func_call_uses.size() > 0) {
                                should_remove = false;
                            }
                        }
                        if (!should_remove || op->has_side_effect()) {
                            new_ops.push_back(std::move(op));
                        } else {
                            std::cout << *op << "removed" << std::endl;
                            num_op_removed++;
                        }
                    }
                    bb_ptr->ops = std::move(new_ops);
                }
            }
        } while (num_op_removed > 0);
        return ctx;
    }
}
