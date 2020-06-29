#include "target-partition.hpp"
#include <queue>
#include <unordered_set>
#include <unordered_map>

namespace Target {

    SplitResult peel(const BlockSet &blocks, const std::string &start_point,
                     const PlaceResult &p, bool reversed) {
        using EdgeRec = std::tuple<std::string, std::string>; // (c_var, t_bb, f_bb)
        std::unordered_map<std::string, std::vector<EdgeRec>> edges;
        std::function<bool(PlaceType)> place_predicate;
        std::unordered_set<std::string> contained_vars;

        SplitResult result;

        // create edges (or reverse edges)
        if (reversed) {
            for (auto &kv : blocks) {
                auto &blk_name = kv.first;
                auto &blk = *kv.second;
                std::string c_var = "";
                if (blk.is_conditional()) {
                    c_var = blk.branch_cond();
                }
                auto nexts = blk.next_blocks();
                for (auto &n : nexts) {
                    edges[n].push_back({c_var, blk_name});
                    //std::cerr << "edge: " << n << " -> " << blk_name << std::endl;
                }
            }
            place_predicate = [](PlaceType t) -> bool {
                if (t == PlaceType::P4_SUFFIX) {
                    return true;
                } else {
                    return false;
                }
            };
        } else {
            for (auto &kv : blocks) {
                auto &blk_name = kv.first;
                auto &blk = *kv.second;
                std::string c_var = "";
                if (blk.is_conditional()) {
                    c_var = blk.branch_cond();
                }
                auto nexts = blk.next_blocks();
                if (nexts.size() > 0) {
                    auto &rec = edges[blk_name];
                    for (auto &n : nexts) {
                        rec.push_back({c_var, n});
                    }
                }
            }
            place_predicate = [](PlaceType t) -> bool {
                if (t == PlaceType::P4_PREFIX || t == PlaceType::P4_BOTH) {
                    return true;
                } else {
                    return false;
                }
            };
        }

        struct QueueEle {
            std::string curr_block;
            bool skip_block;
        };

        std::queue<QueueEle> q;
        
        QueueEle first_ele;
        first_ele.curr_block = start_point;
        first_ele.skip_block = false;
        
        q.push(first_ele);

        std::string transit_blk_name = "!!transit_blk!!";
        BasicBlock *transit_blk = new BasicBlock(transit_blk_name, {});
        
        while (!q.empty()) {
            auto curr = q.front();
            q.pop();

            if (curr.skip_block) {
                continue;
            }

            BasicBlock::InstList ns;
            assert(blocks.find(curr.curr_block) != blocks.end());
            auto blk = blocks.find(curr.curr_block)->second;
            auto &insts = blk->insts_mut();
            if (!curr.skip_block) {
                for (int i = 0; i < insts.size(); i++) {
                    auto inst = insts[i];
                    InstID inst_id{curr.curr_block, i};
                    auto place_iter = p.fixed_inst.find(inst_id);
                    if (place_iter != p.fixed_inst.end()) {
                        auto t = place_iter->second;
                        if (place_predicate(t)) {
                            // InstID new_id{{curr.curr_block, ns.size()}};
                            ns.push_back(inst);
                            auto inst_dst = inst->get_dst_reg();
                            if (inst_dst != "") {
                                contained_vars.insert(inst_dst);
                            }
                        }
                    }
                }
            }
            
            BasicBlock *new_blk = new BasicBlock(blk->get_name(), ns);
            result.blocks.insert({new_blk->get_name(), new_blk});

            if (edges.find(curr.curr_block) != edges.end()) {
                auto dsts = edges.find(curr.curr_block)->second;
                for (auto &rec : dsts) {
                    auto c_var = std::get<0>(rec);
                    auto next_blk_name = std::get<1>(rec);
                    QueueEle next;
                    next.skip_block = false;
                    next.curr_block = next_blk_name;
                    if (c_var != "") {
                        if (!reversed &&
                            contained_vars.find(c_var) == contained_vars.end()) {
                            /* the next block can not be put on device
                             * since the jump condition variable can not be on device
                             */
                            next.skip_block = true;
                        } else  {
                        }
                    }
                    q.push(next);
                }
            }
        }

        if (!reversed) {
            /* we need to reconstruct edges,
             * for prefix, we also need to connect missing connections to the "transit block"
             */

            for (auto &kv : edges) {
                if (result.blocks.find(kv.first) != result.blocks.end()) {
                    BasicBlock *blk = result.blocks.find(kv.first)->second;
                    assert(kv.second.size() <= 2);
                    auto c_var = std::get<0>(kv.second[0]);
                    if (c_var == "") {
                        assert(kv.second.size() == 1);
                        blk->add_next(std::get<1>(kv.second[0]));
                    } else {
                        assert(std::get<0>(kv.second[1]) == c_var);
                        if (contained_vars.find(c_var) != contained_vars.end()) {
                            auto f_bb = std::get<1>(kv.second[1]);
                            blk->add_branch(c_var, std::get<1>(kv.second[0]), f_bb);
                        } else {
                            // need to send to transit block
                            blk->add_next(transit_blk_name);
                        }
                    }
                }
            }
        } else {
            /* reconstruct edges
             * in the **original** direction
             */
            for (auto &kv : blocks) {
                auto &blk_name = kv.first;
                auto &blk = *kv.second;
                if (result.blocks.find(blk_name) == result.blocks.end()) {
                    continue;
                }
                auto new_blk = result.blocks.find(blk_name)->second;
                std::string c_var = "";
                auto nexts = blk.next_blocks();
                if (blk.is_conditional()) {
                    c_var = blk.branch_cond();
                    new_blk->add_branch(c_var, nexts[0], nexts[1]);
                } else if (nexts.size() > 0) {
                    new_blk->add_next(nexts[0]);
                }
            }
        }
        
        return result;
    }
}
