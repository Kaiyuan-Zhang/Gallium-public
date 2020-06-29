#include "opt-pass.hpp"
#include "utils.hpp"
#include "placer.hpp"
#include <unordered_set>
#include <queue>

CompileCtx::CompileCtx(const std::string &fn) {
    module = llvm::parseIRFile(fn, err, llvm_ctx);
    if (module == nullptr) {
        err.print("prog", llvm::errs());
    }
}

void CompileCtx::load_blocks(const std::string &func_name) {
    auto func = module->getFunction(func_name);
    assert(func != nullptr);
    for (auto iter = func->begin(); iter != func->end(); iter++) {
        std::string bb_name = get_llvm_name(*iter);
        
    }
}

std::size_t PartitionTHasher::operator()(const PartitionT &part) const {
    std::size_t h = 0;
    for (auto iter = part.cbegin(); iter != part.cend(); iter++) {
        const InstID &id = *iter;
        h = h ^ InstIDHasher{}(id);
    }
    return h;
}


void find_state_dep_insts(const std::unordered_map<std::string, Target::BasicBlock *> &blocks,
                          const std::unordered_map<std::string, std::vector<std::string>> &prev_blk,
                          const std::unordered_map<InstID, Target::WriteSet, InstIDHasher, InstIDEqual> &write_sets,
                          std::unordered_set<std::string> &visited_blks,
                          InstIDUset &dep_insts,
                          const Target::InstDeps &deps,
                          const std::string &curr_blk,
                          int last_idx) {
    auto blk = blocks.find(curr_blk)->second;
    auto insts = blk->insts_mut();
    for (int i = last_idx; i >= 0; i--) {
        InstID id{curr_blk, i};
        const auto &ws = write_sets.find(id)->second;
        for (auto &reg : ws.regs) {
            auto p = std::find(deps.reg_dep.begin(), deps.reg_dep.end(), reg);
            if (p != deps.reg_dep.end()) {
                // found inst
                dep_insts.insert(id);
            }
        }

        for (auto &s : ws.states) {
            auto p = std::find(deps.state_dep.begin(), deps.state_dep.end(), s);
            if (p != deps.state_dep.end()) {
                dep_insts.insert(id);
            }
        }
    }
    if (visited_blks.find(curr_blk) != visited_blks.end()) {
        return;
    }
    visited_blks.insert(curr_blk);
    // reached beginning of the basic block
    // jump to previous block(s)
    auto prev_iter = prev_blk.find(curr_blk);
    if (prev_iter != prev_blk.end()) {
        const auto &prev_blks = prev_iter->second;
        for (auto blk_name : prev_blks) {
            assert(blocks.find(blk_name) != blocks.end());
            auto n = blocks.find(blk_name)->second->insts_mut().size();
            find_state_dep_insts(blocks, prev_blk, write_sets, visited_blks,
                                 dep_insts, deps, blk_name, n - 1);
        }
    }
}


std::vector<PartitionT>
find_partitions(const std::unordered_map<std::string, Target::BasicBlock *> &blocks,
                const std::vector<std::string> &entries) {
    std::unordered_set<PartitionT, PartitionTHasher> visited_partitions;
    std::unordered_map<InstID, InstIDUset,
                       InstIDHasher, InstIDEqual> edges, rev_edges;

    std::unordered_map<std::string, InstID> dst_map;
    std::unordered_map<InstID, Target::WriteSet, InstIDHasher, InstIDEqual> write_set;
    std::unordered_map<std::string, std::vector<std::string>> prev_blk;
    std::vector<InstID> all_ids;
    for (auto &kv : blocks) {
        auto blk_name = kv.first;
        auto blk = kv.second;
        auto insts = blk->insts_mut();
        for (int i = 0; i < insts.size(); i++) {
            auto inst = insts[i];
            InstID id{blk_name, i};
            all_ids.push_back(id);
            auto dst_reg = inst->get_dst_reg();
            if (dst_reg != "") {
                dst_map[dst_reg] = id;
            }
            Target::WriteSet ws;
            Target::get_write_set(*inst, ws);
            write_set[id] = ws;

            if (i != 0) {
                InstID prev_id{blk_name, i-1};
                rev_edges[id].insert(prev_id);
            }
        }

        auto nexts = blk->next_blocks();
        for (auto &n : nexts) {
            prev_blk[n].push_back(blk_name);
        }
    }

    {
        struct BFSEle {
            std::string blk;
            std::vector<std::string> cond_regs;
        };
        std::queue<BFSEle> bfs_q;
        for (auto &e : entries) {
            BFSEle ele;
            ele.blk = e;
            ele.cond_regs.clear();
            bfs_q.push(ele);
        }
        while (!bfs_q.empty()) {
            auto curr = bfs_q.front();
            bfs_q.pop();
            auto blk = blocks.find(curr.blk)->second;
            auto insts = blk->insts_mut();
            for (int i = 0; i < insts.size(); i++) {
                InstID id{curr.blk, i};
                for (auto &c : curr.cond_regs) {
                    rev_edges[id].insert(dst_map[c]);
                }
            }

            auto nexts = blk->next_blocks();
            for (auto n : nexts) {
                BFSEle new_ele;
                new_ele.blk = n;
                new_ele.cond_regs = curr.cond_regs;
                if (blk->branch_cond() != "") {
                    new_ele.cond_regs.push_back(blk->branch_cond());
                }
                bfs_q.push(new_ele);
            }
        }
    }

    for (auto &kv : blocks) {
        auto blk_name = kv.first;
        auto blk = kv.second;
        auto insts = blk->insts_mut();
        for (int i = 0; i < insts.size(); i++) {
            auto inst = insts[i];
            InstID id{blk_name, i};
            Target::InstDeps deps;
            Target::get_deps(*inst, deps);
            auto &dep_set = rev_edges[id];
            for (auto &reg : deps.reg_dep) {
                if (dst_map.find(reg) != dst_map.end()) {
                    dep_set.insert(dst_map[reg]);
                }
            }

            std::unordered_set<std::string> state_dep;
            for (auto &s : deps.state_dep) {
                state_dep.insert(s);
            }

            // TODO: construct edges for state dep
            std::unordered_set<std::string> visited;
            InstIDUset state_deps;
            find_state_dep_insts(blocks, prev_blk, write_set,
                                 visited, state_deps, deps, blk_name, i - 1);
            for (auto &id : state_deps) {
                dep_set.insert(id);
            }
        }
    }

    for (auto &kv : rev_edges) {
        auto dst = kv.first;
        for (auto &src : kv.second) {
            edges[src].insert(dst);
        }
    }

    struct QueueEle {
        PartitionT partition;
        std::unordered_map<InstID, int,
                           InstIDHasher, InstIDEqual> in_degrees;
    };

    std::queue<QueueEle> q;
    // TODO: merge strongly connected components

    QueueEle ele;
    ele.partition.clear();
    ele.in_degrees.clear();
    for (auto &id : all_ids) {
        ele.in_degrees[id] = 0;
    }
    for (auto &kv : rev_edges) {
        ele.in_degrees[kv.first] = kv.second.size();
    }

    q.push(ele);

    while (!q.empty()) {
        QueueEle curr = q.front();
        q.pop();

        for (auto &kv : curr.in_degrees) {
            if (kv.second == 0) {
                PartitionT new_part = curr.partition;
                new_part.insert(kv.first);
                if (visited_partitions.find(new_part) == visited_partitions.end()) {
                    visited_partitions.insert(new_part);
                    QueueEle new_ele;
                    new_ele.partition = new_part;
                    new_ele.in_degrees = curr.in_degrees;
                    if (edges.find(kv.first) != edges.end()) {
                        for (auto &dst : edges[kv.first]) {
                            assert(new_ele.in_degrees[dst] > 0);
                            new_ele.in_degrees[dst]--;
                        }
                    }
                    q.push(new_ele);
                }
            }
        }
    }

    std::vector<PartitionT> result;

    int largest = -1;
    int max_size = 0;
    for (auto &part : visited_partitions) {
        result.push_back(part);
        if (part.size() > max_size) {
            largest = result.size() - 1;
        }
        std::cerr << result.size() << " th partition:: ";
        for (auto &id : part) {
            std::cerr << std::get<0>(id) << " " << std::get<1>(id) << ", ";
        }
        std::cerr << std::endl;
    }
    std::cerr << "Found " << result.size() << " partitions" << std::endl;
    std::cerr << "largest: " << largest << " : ";
    for (auto &id : result[largest]) {
        std::cerr << std::get<0>(id) << " " << std::get<1>(id) << ", ";
    }
    std::cerr << std::endl;
    return result;
}
