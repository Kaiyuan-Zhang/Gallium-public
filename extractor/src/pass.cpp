#include "pass.hpp"
#include "target-lang.hpp"

using namespace Target;
namespace Morula {

    std::shared_ptr<Target::Instruction>
    PassCtx::get_inst(const InstID &id) const {
        auto &blk_name = std::get<0>(id);
        auto idx = std::get<1>(id);

        assert(blocks.find(blk_name) != blocks.end());
        auto blk = blocks.find(blk_name)->second;
        auto &insts = blk->insts_mut();
        assert(0 <= idx && idx < insts.size());
        return insts[idx];
    }

    void get_prev_blocks_aux(const std::string &curr,
                             std::unordered_set<std::string> &visited,
                             PassCtx &ctx) {
        if (visited.find(curr) != visited.end()) {
            return;
        }

        visited.insert(curr);
        if (ctx.rev_edges.find(curr) != ctx.rev_edges.end()) {
            for (auto &bb : ctx.rev_edges[curr]) {
                get_prev_blocks_aux(bb, visited, ctx);
            }
        }
    }


    void get_prev_blocks(const std::string &curr,
                         std::unordered_set<std::string> &result,
                         PassCtx &ctx) {
        if (ctx.rev_edges.find(curr) != ctx.rev_edges.end()) {
            for (auto &bb : ctx.rev_edges[curr]) {
                std::unordered_set<std::string> r;
                get_prev_blocks(bb, r, ctx);
                for (auto &b : r) {
                    result.insert(b);
                }
                result.insert(bb);
            }
        }
    }
    
    
    std::unique_ptr<PassCtx> UpdateDeps::pass_impl(std::unique_ptr<PassCtx> s) {
        s->inst_pre_req.clear();
        s->inst_rev_dep.clear();
        std::unordered_map<std::string, std::unordered_set<std::string>> prev_blocks;
        InstIDUmap<WriteSet> inst_writeset;

        for (auto &kv : s->blocks) {
            auto blk = kv.second;
            auto insts = blk->insts_mut();
            for (int i = 0; i < insts.size(); i++) {
                InstID id{kv.first, i};
                
                WriteSet ws;
                get_write_set(*insts[i], ws);
                
                inst_writeset[id] = ws;
            }
            prev_blocks[kv.first].clear();
            get_prev_blocks(kv.first, prev_blocks[kv.first], *s);
        }
        
        for (auto &kv : s->blocks) {
            auto blk = kv.second;
            auto insts = blk->insts_mut();
            for (int i = 0; i < insts.size(); i++) {
                InstID id{kv.first, i};
                InstDeps deps;
                get_deps(*insts[i], deps);

                bool log = false;
                if (insts[i]->is_header_set()) {
                    log = true;
                }
                
                // register deps
                for (auto &reg : deps.reg_dep) {
                    if (s->var_source.find(reg) != s->var_source.end()) {
                        s->inst_pre_req[id].insert(s->var_source[reg]);
                        if (log) {
                            std::cerr << id << " depends on " << s->var_source[reg]
                                      << " for reg " << reg << std::endl;
                        }
                    }
                }
                const WriteSet &ws = inst_writeset[id];
                // for states, we need to go backward and inspect the write sets
                for (auto &prev_bb : prev_blocks[kv.first]) {
                    auto prev_insts = s->blocks[prev_bb]->insts_mut();
                    for (int j = 0; j < prev_insts.size(); j++) {
                        InstID prev_id{prev_bb, j};
                        const WriteSet &prev_ws = inst_writeset[prev_id];

                        // check if there are any Write-Read or Write-Write dependency
                        bool have_dep = false;
                        std::string dep_reason;
                        for (auto &state : prev_ws.states) {
                            auto it_r = std::find(deps.state_dep.begin(), deps.state_dep.end(), state);
                            if (it_r != deps.state_dep.end()) {
                                have_dep = true;
                                dep_reason = "write-read";
                                break;
                            }
                            auto it_w = std::find(ws.states.begin(), ws.states.end(), state);
                            if (it_w != ws.states.end()) {
                                have_dep = true;
                                dep_reason = "write-write";
                                break;
                            }
                        }
                        if (have_dep) {
                            if (log) {
                                std::cerr << id << "depends on " << prev_id << " " << dep_reason << std::endl;
                            }
                            s->inst_pre_req[id].insert(prev_id);
                        }
                    }
                    if (s->blocks[prev_bb]->is_conditional()) {
                        auto cond = s->blocks[prev_bb]->branch_cond();
                        auto cond_inst_id = s->var_source.find(cond)->second;
                        s->inst_pre_req[id].insert(cond_inst_id);
                    }
                }
            }
        }

        // now fill in the reverse dependency
        for (auto &kv : s->inst_pre_req) {
            for (auto &pre_req : kv.second) {
                s->inst_rev_dep[pre_req].insert(kv.first);
            }
        }
        
        return s;
    }

    std::unique_ptr<PassCtx> UpdateEdges::pass_impl(std::unique_ptr<PassCtx> s) {
        s->fwd_edges.clear();
        s->rev_edges.clear();
        for (auto &kv : s->blocks) {
            auto blk = kv.second;
            auto nexts = blk->next_blocks();
            for (auto &n : nexts) {
                s->fwd_edges[kv.first].insert(n);
                s->rev_edges[n].insert(kv.first);
            }
        }
        return s;
    }

    PASS_IMPL(RemoveUnusedInst, ctx) {
        std::unordered_map<std::string, std::shared_ptr<BasicBlock>> new_blks;

        int num_removed;

        using UpdateMeta = PassSeq<UpdateVarSource<PassCtx>,
                                   UpdateEdges,
                                   UpdateDeps>;
        auto s = UpdateMeta::apply_pass(std::move(ctx));
        do {
            num_removed = 0;
            for (auto &kv : s->blocks) {
                auto blk = kv.second;
                auto insts = blk->insts_mut();
                BasicBlock::InstList ns;
                for (int i = 0; i < insts.size(); i++) {
                    InstID id{kv.first, i};
                    if (no_side_effect(*insts[i])
                        && (s->inst_rev_dep.find(id) == s->inst_rev_dep.end()
                            || s->inst_rev_dep.find(id)->second.size() == 0)) {
                        // this instruction should be removed
                        // here we remove instruction by NOT adding it to the new instruction list
                        num_removed++;
                    } else {
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
                new_blks.insert({kv.first, new_blk});
            }

            // remember to update var_source and dependencies
            // since they use InstID
            s->blocks = std::move(new_blks);
            s = UpdateMeta::apply_pass(std::move(s));
        } while (num_removed != 0);
        return s;
    }
}
