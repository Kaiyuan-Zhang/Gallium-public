#include "hir-common-pass.hpp"
#include "graph.hpp"
#include "utils.hpp"
#include "llvm-helpers.hpp"
#include <queue>

namespace HIR {
void remove_all_meta(Function& f) {
    for (auto &bb : f.bbs) {
        for (auto &op : bb->ops) {
            op->set_meta<void>(nullptr);
        }
    }
}

void remove_all_meta(Element &ele) {
    for (auto &f : ele.funcs) {
        for (auto &bb : f->bbs) {
            for (auto &op : bb->ops) {
                op->set_meta<void>(nullptr);
            }
        }
    }
}

void update_uses(Function& f) {
    for (auto& bb : f.bbs) {
        for (auto &op : bb->ops) {
            for (auto &d : op->dst_vars) {
                d->src_op = op;
                d->uses.clear();
            }
            for (auto &a : op->args) {
                a->uses.clear();
            }
        }
    }
    for (auto& bb : f.bbs) {
        for (auto &op : bb->ops) {
            op->update_uses();
        }
        bb->parent = &f;
        bb->update_uses();
    }
}

void update_uses(Element &ele) {
    for (auto &f : ele.funcs) {
        update_uses(*f);
    }
}

bool func_has_side_effect(const Operation &op) {
    bool ret = true;
    auto &func = op.call_info.called_function;
    auto &fn = op.call_info.func_name;
    std::string demangled_fn;
    bool could_demangle = cxx_demangle(fn, demangled_fn);

    if (could_demangle) {
        if (demangled_fn == "WritablePacket::ip_header() const"
            || demangled_fn == "Packet::ip_header() const") {
            ret = false;
        } else if (demangled_fn == "Packet::transport_header() const") {
            ret = false;
        } else if (demangled_fn == "Packet::uniqueify()") {
            ret = false;
        }
    }
    return ret;
}

bool has_side_effect(const Operation &op) {
    bool ret = true;
    switch (op.type) {
    case Operation::T::ARITH:
    case Operation::T::BITCAST:
    case Operation::T::GEP:
    case Operation::T::LOAD:
    case Operation::T::STRUCT_GET:
    case Operation::T::PHINODE:
    case Operation::T::PKT_HDR_LOAD:
    case Operation::T::SELECT:
        ret = false;
        break;
    case Operation::T::FUNC_CALL:
        ret = func_has_side_effect(op);
        break;
    default:
        break;
    }
    return ret;
}

void remove_unused_ops(Function &func) {
    for (auto &bb : func.bbs) {
        std::vector<std::shared_ptr<Operation>> new_ops;
        for (auto &op : bb->ops) {
            op->set_meta(std::make_shared<bool>(false));
        }
    }
    for (auto &bb : func.bbs) {
        std::vector<std::shared_ptr<Operation>> new_ops;
        for (auto &op : bb->ops) {
            if (has_side_effect(*op)) {
                op->meta_ref<bool>() = true;
            }
        }
        if (bb->is_return && bb->return_val != nullptr) {
            auto ret_val = bb->return_val;
            auto ret_val_op = ret_val->src_op.lock();
            assert(ret_val_op != nullptr);
            ret_val_op->meta_ref<bool>() = true;
        }
    }

    bool have_delta = false;

    do {
        have_delta = false;
        for (auto &bb : func.bbs) {
            for (auto &op : bb->ops) {
                if (!op->meta_ref<bool>()) {
                    continue;
                }
                for (auto &a : op->args) {
                    if (a->is_constant || a->is_param || a->is_global) {
                        continue;
                    }
                    auto src_op = a->src_op.lock();
                    assert(src_op != nullptr);
                    bool &r = src_op->meta_ref<bool>();
                    if (!r) {
                        have_delta = true;
                        r = true;
                    }
                }
            }
            for (auto& e : bb->branches) {
                auto& c = e.cond_var;
                auto src_op = c->src_op.lock();
                assert(src_op != nullptr);
                bool &r = src_op->meta_ref<bool>();
                if (!r) {
                    have_delta = true;
                    r = true;
                }
            }
        }
    } while (have_delta);

    for (auto &bb : func.bbs) {
        std::vector<std::shared_ptr<Operation>> new_ops;
        for (auto &op : bb->ops) {
            if (op->meta_ref<bool>()) {
                new_ops.emplace_back(op);
            }
            op->set_meta<bool>(nullptr);
        }
        bb->ops = std::move(new_ops);
    }
}

void remove_empty_bb(Function& f) {
    std::unordered_map<
        std::shared_ptr<BasicBlock>,
        std::unordered_set<std::shared_ptr<BasicBlock>>
    > from;
    auto entry_bb = f.bbs[f.entry_bb_idx()];
    for (auto& bb : f.bbs) {
        auto n_bb = bb->default_next_bb.lock();
        if (n_bb != nullptr) {
            from[n_bb].insert(bb);
        }
        for (auto& e : bb->branches) {
            auto n_bb = e.next_bb.lock();
            if (n_bb != nullptr) {
                from[n_bb].insert(bb);
            }
        }
    }
    std::unordered_map<
        std::shared_ptr<BasicBlock>,
        std::shared_ptr<BasicBlock>> from_bb_mapping;
    std::unordered_set<std::shared_ptr<BasicBlock>> bb_removed;
    bool delta;
    do {
        delta = false;
        for (auto& bb : f.bbs) {
            if (bb_removed.find(bb) != bb_removed.end()) {
                continue;
            }
            if (from.find(bb) != from.end() && bb->ops.size() == 0) {
                if (from[bb].size() == 1 && bb->branches.empty()) {
                    if (!bb->is_return && !bb->is_err) {
                        auto n_bb = bb->default_next_bb.lock();
                        assert(n_bb != nullptr);
                        for (auto& from_bb : from[bb]) {
                            delta = true;
                            replace_next_bb(from_bb, bb, n_bb);
                            for (auto& op : n_bb->ops) {
                                if (op->type == Operation::T::PHINODE) {
                                    for (auto& f_bb : op->phi_info.from) {
                                        if (f_bb.lock() == bb) {
                                            f_bb = from_bb;
                                        }
                                    }
                                }
                            }
                            from_bb_mapping[bb] = from_bb;
                            from[n_bb].erase(bb);
                            from[n_bb].insert(from_bb);
                        }
                        bb_removed.insert(bb);
                    }
                }
            }
            auto n_bb = bb->default_next_bb.lock();
            if (n_bb == nullptr) {
                continue;
            }
            bool same_dst = true;
            for (auto& e : bb->branches) {
                auto n = e.next_bb.lock();
                if (n != n_bb) {
                    same_dst = false;
                    break;
                }
            }
            if (same_dst) {
                if (!bb->branches.empty()) {
                    delta = true;
                }
                bb->branches.clear();
            }
        }
    } while (delta);

    auto iter = f.bbs.begin();
    while (iter != f.bbs.end()) {
        auto& bb = *iter;
        if (bb_removed.find(bb) != bb_removed.end()) {
            assert(entry_bb != bb);
            iter = f.bbs.erase(iter);
        } else {
            ++iter;
        }
    }
    bool found = false;
    for (int i = 0; i < f.bbs.size(); i++) {
        if (f.bbs[i] == entry_bb) {
            found = true;
            f.set_entry_idx(i);
        }
    }
    assert(found);
}

void remove_unused_ops(Element &ele) {
    update_uses(ele);
    for (auto &f : ele.funcs) {
        remove_unused_ops(*f);
    }
    update_uses(ele);
}

bool should_try_inline(const Operation &op) {
    if (op.type != Operation::T::FUNC_CALL) {
        return false;
    } else if (op.call_info.called_function.lock()->is_built_in) {
        return false;
    }
    return true;
}

bool reachable(
        const Graph<
            std::shared_ptr<Function>,
            std::monostate,
            AdjacencyList<std::monostate>> &call_graph,
        size_t v,
        size_t dst,
        std::vector<bool> &visited) {
    if (visited[v]) {
        return false;
    }
    if (v == dst) {
        return true;
    }

    visited[v] = true;
    for (auto iter = call_graph.edges().out_edge_begin(v); iter != iter.end(); iter++) {
        auto n = *iter;
        if (reachable(call_graph, n, dst, visited)) {
            return true;
        }
    }
    return false;
}

bool is_recursive(
        const Graph<
            std::shared_ptr<Function>,
            std::monostate,
            AdjacencyList<std::monostate>> &call_graph,
        std::shared_ptr<Function> f) {
    auto vid = 0;
    bool found = false;
    for (size_t i = 0; i < call_graph.n_vertex(); i++) {
        if (call_graph.vertex_ref(i).get() == f.get()) {
            found = true;
            vid = i;
            break;
        }
    }
    assert(found);
    std::vector<bool> visited(call_graph.n_vertex(), false);
    for (auto iter = call_graph.edges().out_edge_begin(vid); iter != iter.end(); iter++) {
        auto n = *iter;
        if (reachable(call_graph, n, vid, visited)) {
            return true;
        }
    }
    return false;
}

std::vector<std::shared_ptr<BasicBlock>>
generate_inline_bbs(
        const Graph<
            std::shared_ptr<Function>,
            std::monostate,
            AdjacencyList<std::monostate>> &call_graph,
        const Function &func,
        const std::vector<std::shared_ptr<Var>> &args) {
    std::vector<std::shared_ptr<BasicBlock>> bbs;
    int num_return_bb = 0;
    int return_bb_idx = 0;
    for (int i = 0; i < func.bbs.size(); i++) {
        auto &bb = func.bbs[i];
        if (bb->is_return) {
            num_return_bb++;
            return_bb_idx = i;
        }
    }
    assert(num_return_bb == 1);
    std::unordered_map<BasicBlock *, std::shared_ptr<BasicBlock>> bb_mapping;
    std::unordered_map<Var *, std::shared_ptr<Var>> var_mapping;
    assert(args.size() == func.args.size());
    for (int i = 0; i < args.size(); i++) {
        var_mapping[func.args[i].get()] = args[i];
    }
    std::vector<std::shared_ptr<BasicBlock>> new_bbs;
    for (int i = 0; i < func.bbs.size(); i++) {
        auto new_bb = std::make_shared<BasicBlock>();
        assert(bb_mapping.find(func.bbs[i].get()) == bb_mapping.end());
        bb_mapping[func.bbs[i].get()] = new_bb;
    }
    for (auto &bb : func.bbs) {
        for (auto &op : bb->ops) {
            for (auto &dst : op->dst_vars) {
                auto new_dst = std::make_shared<Var>(*dst);
                assert(var_mapping.find(dst.get()) == var_mapping.end());
                var_mapping[dst.get()] = new_dst;
            }
        }
    }
    for (int i = 0; i < func.bbs.size(); i++) {
        auto &bb = func.bbs[i];
        // copy the basic block
        assert(bb_mapping.find(func.bbs[i].get()) != bb_mapping.end());
        auto new_bb = bb_mapping[func.bbs[i].get()];
        new_bb->name = NameFactory::get()(NameFactory::get().base(bb->name));
        for (int j = 0; j < bb->ops.size(); j++) {
            auto &op = bb->ops[j];
            if (!should_try_inline(*op) || is_recursive(call_graph, op->call_info.called_function.lock())) {
                auto new_op = std::make_shared<Operation>(*op);
                //  create new dst arg
                std::vector<std::shared_ptr<Var>> new_dst_vars;
                new_op->dst_vars.clear();
                for (auto &dst : op->dst_vars) {
                    assert(var_mapping.find(dst.get()) != var_mapping.end());
                    auto new_dst = var_mapping[dst.get()];
                    new_dst->src_op = new_op;
                    new_dst->uses.clear();
                    new_op->dst_vars.emplace_back(new_dst);
                    new_dst->src_op = new_op;
                }
                if (op->type == Operation::T::PHINODE) {
                    new_op->phi_info.from.clear();
                    for (int k = 0; k < op->phi_info.from.size(); k++) {
                        auto n_bb = op->phi_info.from[k].lock().get();
                        new_op->phi_info.from.emplace_back(bb_mapping[n_bb]);
                    }
                }
                new_op->args.clear();
                for (auto &a : op->args) {
                    if (a->is_constant) {
                        new_op->args.emplace_back(a);
                    } else {
                        assert(var_mapping.find(a.get()) != var_mapping.end());
                        new_op->args.emplace_back(var_mapping[a.get()]);
                    }
                }
                new_bb->append_operation(new_op);
            } else {
                auto inline_f = op->call_info.called_function.lock();
                assert(inline_f->args.size() == op->args.size());
                std::vector<std::shared_ptr<Var>> new_args;
                for (auto &a : op->args) {
                    if (a->is_constant) {
                        new_args.emplace_back(a);
                    } else {
                        assert(var_mapping.find(a.get()) != var_mapping.end());
                        new_args.emplace_back(var_mapping[a.get()]);
                    }
                }
                auto inlined_bbs = generate_inline_bbs(call_graph, *inline_f, new_args);
                // create two basic blocks for this bb
                // insert all but the last block
                assert(inlined_bbs.size() >= 1);
                for (int k = 0; k < inlined_bbs.size() - 1; k++) {
                    new_bbs.emplace_back(inlined_bbs[k]);
                }
                assert(inlined_bbs.size() > 0);
                auto entry = inlined_bbs[0];
                auto next_new_bb = inlined_bbs[inlined_bbs.size() - 1];
                new_bb->default_next_bb = entry;
                new_bb->branches.clear();
                auto inline_last_bb = inlined_bbs.back();
                inline_last_bb->default_next_bb = next_new_bb;
                inline_last_bb->branches.clear();
                new_bbs.emplace_back(new_bb);
                new_bb = next_new_bb;
            }
        }
        // copy branching info
        new_bb->branches.clear();
        for (int j = 0; j < func.bbs[i]->branches.size(); j++) {
            const BasicBlock::BranchEntry &e = func.bbs[i]->branches[j];
            BasicBlock::BranchEntry ne;
            assert(var_mapping.find(e.cond_var.get()) != var_mapping.end());
            ne.cond_var = var_mapping[e.cond_var.get()];
            ne.is_conditional = e.is_conditional;
            ne.next_bb = bb_mapping[e.next_bb.lock().get()];
            new_bb->branches.emplace_back(ne);
        }
        new_bb->is_return = bb->is_return;
        new_bb->is_err = bb->is_err;
        if (bb->default_next_bb.lock() != nullptr) {
            auto n_bb = bb->default_next_bb.lock().get();
            assert(bb_mapping.find(n_bb) != bb_mapping.end());
            new_bb->default_next_bb = bb_mapping[n_bb];
        }
        new_bbs.emplace_back(new_bb);
    }

    std::unordered_map<BasicBlock *, int> in_degree;
    num_return_bb = 0;
    return_bb_idx = 0;
    for (auto &bb : new_bbs) {
        in_degree[bb.get()] = 0;
    }
    for (int i = 0; i < new_bbs.size(); i++) {
        auto &bb = new_bbs[i];
        if (bb->is_return) {
            num_return_bb++;
            return_bb_idx = i;
        } else if (!bb->is_err) {
            in_degree[bb->default_next_bb.lock().get()]++;
            for (auto &e : bb->branches) {
                in_degree[e.next_bb.lock().get()]++;
            }
        }
    }
    int num_start = 0;
    BasicBlock *start_bb = nullptr;
    for (auto &kv : in_degree) {
        if (kv.second == 0) {
            start_bb = kv.first;
            num_start++;
        }
    }
    assert(num_start == 1);
    assert(num_return_bb == 1);
    std::shared_ptr<BasicBlock> start_bb_shared = nullptr;
    for (auto &bb : new_bbs) {
        if (bb.get() == start_bb) {
            start_bb_shared = bb;
        }
    }
    assert(start_bb_shared != nullptr);
    bbs.emplace_back(start_bb_shared);
    for (int i = 0; i < new_bbs.size(); i++) {
        if (i != return_bb_idx && new_bbs[i].get() != start_bb) {
            bbs.emplace_back(new_bbs[i]);
        }
    }
    bbs.emplace_back(new_bbs[return_bb_idx]);
    return bbs;
}

std::unordered_map<std::shared_ptr<BasicBlock>, size_t>
get_bb_idx_mapping(const Function& f) {
    std::unordered_map<std::shared_ptr<BasicBlock>, size_t> result;
    for (size_t i = 0; i < f.bbs.size(); i++) {
        result[f.bbs[i]] = i;
    }
    return result;
}

std::unordered_map<std::shared_ptr<BasicBlock>, std::shared_ptr<BasicBlock>>
duplicate_bbs(std::shared_ptr<BasicBlock> start) {
    std::unordered_map<std::shared_ptr<BasicBlock>, std::shared_ptr<BasicBlock>> result;
    // do a breadth first search to discover all basic blocks
    std::queue<std::shared_ptr<BasicBlock>> q;
    std::unordered_set<std::shared_ptr<BasicBlock>> to_copy;
    q.push(start);

    auto add_to_queue = [&q, &to_copy] (std::shared_ptr<BasicBlock> bb) {
        if (to_copy.find(bb) == to_copy.end()) {
            q.push(bb);
        }
    };

    while (!q.empty()) {
        auto bb = q.front();
        q.pop();
        to_copy.insert(bb);

        if (bb->is_return || bb->is_err) {
            continue;
        }
        auto n_bb = bb->default_next_bb.lock();
        assert(n_bb != nullptr);
        add_to_queue(n_bb);
        for (auto& e : bb->branches) {
            auto n_bb = e.next_bb.lock();
            assert(n_bb != nullptr);
            add_to_queue(n_bb);
        }
    }

    for (auto& bb : to_copy) {
        result.insert({bb, std::make_shared<BasicBlock>(*bb)});
        auto& bb_copy = result[bb];
        bb_copy->name = NameFactory::get()(NameFactory::get().base(bb->name));
        for (int i = 0; i < bb->ops.size(); i++) {
            bb_copy->ops[i] = std::make_shared<Operation>(*bb->ops[i]);
        }
    }

    std::unordered_map<std::shared_ptr<Var>, std::shared_ptr<Var>> var_mapping;
    for (auto& bb : to_copy) {
        auto& bb_dup = result[bb];
        for (int op_idx = 0; op_idx < bb->ops.size(); op_idx++) {
            auto& op = bb->ops[op_idx];
            auto& op_dup = bb_dup->ops[op_idx];
            op_dup->dst_vars.clear();
            for (auto& d : op->dst_vars) {
                auto nd = std::make_shared<Var>(*d);
                nd->name = NameFactory::get()(NameFactory::get().base(d->name));
                var_mapping[d] = nd;
                op_dup->dst_vars.emplace_back(nd);
            }
        }
    }
    for (auto& bb : to_copy) {
        auto& bb_dup = result[bb];
        for (int i = 0; i < bb->ops.size(); i++) {
            auto& op = bb->ops[i];
            auto& op_dup = bb_dup->ops[i];
            op_dup->args.clear();
            for (auto& a : op->args) {
                if (var_mapping.find(a) != var_mapping.end()) {
                    op_dup->args.emplace_back(var_mapping[a]);
                } else {
                    op_dup->args.emplace_back(a);
                }
            }
            if (op->type == Operation::T::PHINODE) {
                op_dup->phi_info.from.clear();
                for (auto& from : op->phi_info.from) {
                    auto bb_ptr = from.lock();
                    if (result.find(bb_ptr) != result.end()) {
                        op_dup->phi_info.from.emplace_back(result[bb_ptr]);
                    } else {
                        op_dup->phi_info.from.emplace_back(bb_ptr);
                    }
                }
            }
        }
        auto n_bb = bb->default_next_bb.lock();
        if (n_bb != nullptr && result.find(n_bb) != result.end()) {
            bb_dup->default_next_bb = result[n_bb];
        }
        for (int i = 0; i < bb->branches.size(); i++) {
            auto& e = bb->branches[i];
            auto n_bb = e.next_bb.lock();
            if (result.find(n_bb) != result.end()) {
                bb_dup->branches[i].next_bb = result[n_bb];
            } else {
                assert(bb_dup->branches[i].next_bb.lock().get() == n_bb.get());
            }
        }
    }

    return result;
}

void replace_next_bb(
        std::shared_ptr<BasicBlock> from,
        std::shared_ptr<BasicBlock> old_bb,
        std::shared_ptr<BasicBlock> new_bb) {
    bool found = false;
    auto n_bb = from->default_next_bb.lock();
    assert(n_bb != nullptr);
    if (n_bb == old_bb) {
        from->default_next_bb = new_bb;
        found = true;
    }
    for (auto& e : from->branches) {
        auto n_bb = e.next_bb.lock();
        assert(n_bb != nullptr);
        if (n_bb == old_bb) {
            e.next_bb = new_bb;
            found = true;
        }
    }
    assert(found);
}


void fork_from_bb(Function& f, int bb_idx) {
    assert(0 <= bb_idx && bb_idx < f.bbs.size());
    auto& start_bb = f.bbs[bb_idx];
    std::unordered_set<std::shared_ptr<BasicBlock>> from;
    for (auto& bb : f.bbs) {
        if (bb == start_bb) {
            continue;
        }
        auto n_bb = bb->default_next_bb.lock();
        if (n_bb == start_bb) {
            from.insert(bb);
        }
        for (auto& e : bb->branches) {
            auto n_bb = e.next_bb.lock();
            if (n_bb == start_bb) {
                from.insert(bb);
            }
        }
    }

    // very unlikely : no need to dup
    if (from.size() <= 1) {
        return;
    }

    for (auto& prev_bb : from) {
        auto copied_bbs = duplicate_bbs(start_bb);
        assert(copied_bbs.find(start_bb) != copied_bbs.end());
        replace_next_bb(prev_bb, start_bb, copied_bbs[start_bb]);
        for (auto& kv : copied_bbs) {
            f.bbs.emplace_back(kv.second);
        }
    }

    update_uses(f);
    remove_unused_phi_entry(f);
}

void remove_unused_phi_entry(Function& f) {
    std::unordered_map<
        std::shared_ptr<BasicBlock>,
        std::unordered_set<std::shared_ptr<BasicBlock>>
    > from;
    auto entry_bb = f.bbs[f.entry_bb_idx()];
    for (auto& bb : f.bbs) {
        auto n_bb = bb->default_next_bb.lock();
        if (n_bb != nullptr) {
            from[n_bb].insert(bb);
        }
        for (auto& e : bb->branches) {
            auto n_bb = e.next_bb.lock();
            if (n_bb != nullptr) {
                from[n_bb].insert(bb);
            }
        }
    }

    auto iter = f.bbs.begin();
    while (iter != f.bbs.end()) {
        auto bb = *iter;
        if (*iter != entry_bb && (from.find(*iter) == from.end() || from[*iter].size() == 0)) {
            iter = f.bbs.erase(iter);
        } else if (bb->ops.size() == 0 && bb->branches.size() == 0 && !bb->is_return && !bb->is_err) {
            auto prev_bbs = from[bb];
            auto n_bb = bb->default_next_bb.lock();
            assert(n_bb != nullptr);
            for (auto& p : prev_bbs) {
                replace_next_bb(p, bb, n_bb);
            }
            iter = f.bbs.erase(iter);
        } else {
            iter++;
        }
    }
    for (int i = 0; i < f.bbs.size(); i++) {
        if (f.bbs[i] == entry_bb) {
            f.set_entry_idx(i);
            break;
        }
    }

    std::unordered_map<std::shared_ptr<Var>, std::shared_ptr<Var>> var_replace;
    for (auto& bb : f.bbs) {
        if (bb == entry_bb) {
            continue;
        }
        assert(from.find(bb) != from.end());
        auto& prev_bb_set = from[bb];
        assert(prev_bb_set.size() > 0);
        auto op_iter = bb->ops.begin();
        while (op_iter != bb->ops.end()) {
            auto& op = *op_iter;
            if (op->type == Operation::T::PHINODE) {
                assert(op->phi_info.from.size() == op->args.size());
                auto from_iter = op->phi_info.from.begin();
                auto arg_iter = op->args.begin();
                while (arg_iter != op->args.end()) {
                    auto prev_bb = from_iter->lock();
                    if (prev_bb_set.find(prev_bb) == prev_bb_set.end()) {
                        from_iter = op->phi_info.from.erase(from_iter);
                        arg_iter = op->args.erase(arg_iter);
                    } else {
                        ++from_iter;
                        ++arg_iter;
                    }
                }
                assert(op->args.size() > 0);
                if (op->args.size() == 1) {
                    var_replace[op->dst_vars[0]] = op->args[0];
                    op_iter = bb->ops.erase(op_iter);
                } else {
                    ++op_iter;
                }
            } else {
                ++op_iter;
            }
        }
        assert(bb->ops.size() > 0 || bb->branches.size() > 0 || bb->is_return || bb->is_err);
    }

    bool have_delta = false;
    int num_iter = 0;
    do {
        if (num_iter > var_replace.size() * 2) {
            assert(false && "potential cycle");
        }
        have_delta = false;
        for (auto& kv : var_replace) {
            if (var_replace.find(kv.second) != var_replace.end()) {
                kv.second = var_replace[kv.second];
                have_delta = true;
            }
        }
        num_iter++;
    } while (have_delta);

    for (auto& bb : f.bbs) {
        for (auto& op : bb->ops) {
            for (auto& a : op->args) {
                if (var_replace.find(a) != var_replace.end()) {
                    a = var_replace[a];
                }
            }
        }
    }
}

void break_select_op(Function& f, std::shared_ptr<Operation> op) {
    std::shared_ptr<BasicBlock> parent_bb = nullptr;
    OpLoc loc;
    loc.bb = nullptr;
    loc.op_idx = -1;
    for (auto& bb : f.bbs) {
        for (int i = 0; i < bb->ops.size(); i++) {
            if (bb->ops[i] == op) {
                parent_bb = bb;
                loc.bb = bb.get();
                loc.op_idx = i;
            }
        }
    }
    assert(parent_bb != nullptr);

    std::shared_ptr<Operation> select_op = parent_bb->ops[loc.op_idx];
    assert(select_op->type == Operation::T::SELECT);
    std::shared_ptr<BasicBlock> next_bb = nullptr;
    if (loc.op_idx == parent_bb->ops.size() - 1 && !parent_bb->is_return) {
        assert(parent_bb->branches.size() == 0);
        next_bb = parent_bb->default_next_bb.lock();
        assert(next_bb != nullptr);
    } else {
        next_bb = std::make_shared<BasicBlock>(*parent_bb);
        next_bb->name = NameFactory::get()(NameFactory::get().base(parent_bb->name));
        next_bb->ops.clear();
        for (int i = loc.op_idx + 1; i < parent_bb->ops.size(); i++) {
            next_bb->ops.emplace_back(parent_bb->ops[i]);
        }
        f.bbs.emplace_back(next_bb);
        // update PHINODE from
        for (auto& bb : f.bbs) {
            for (auto& op : bb->ops) {
                if (op->type == Operation::T::PHINODE) {
                    for (auto& from : op->phi_info.from) {
                        auto n_bb = from.lock();
                        if (n_bb == parent_bb) {
                            from = next_bb;
                        }
                    }
                }
            }
        }
    }
    parent_bb->ops.resize(loc.op_idx);

    auto t_branch = next_bb;
    auto f_branch_bbs = duplicate_bbs(next_bb);
    auto f_branch = f_branch_bbs[next_bb];

    BasicBlock::BranchEntry branch_entry;
    branch_entry.is_conditional = true;
    branch_entry.cond_var = select_op->args[0];
    branch_entry.next_bb = t_branch;

    parent_bb->branches = {branch_entry};
    parent_bb->default_next_bb = f_branch;

    for (auto& bb : f.bbs) {
        for (auto& op : bb->ops) {
            for (auto& a : op->args) {
                if (a == select_op->dst_vars[0]) {
                    a = select_op->args[1];
                }
            }
        }
    }
    for (auto& kv : f_branch_bbs) {
        f.bbs.emplace_back(kv.second);
        for (auto& op : kv.second->ops) {
            for (auto& a : op->args) {
                if (a == select_op->dst_vars[0]) {
                    a = select_op->args[2];
                }
            }
        }
    }

    remove_unused_phi_entry(f);
    update_uses(f);
}

Graph<
    std::shared_ptr<Function>,
    std::monostate,
    AdjacencyList<std::monostate>
> call_graph_of_ele(const Element &ele) {
    AdjacencyList<std::monostate> call_edges(ele.funcs.size());
    std::unordered_map<Function *, int> func_idx_mapping;
    for (int i = 0; i < ele.funcs.size(); i++) {
        auto f_ptr = ele.funcs[i].get();
        assert(func_idx_mapping.find(f_ptr) == func_idx_mapping.end());
        func_idx_mapping[f_ptr] = i;
    }
    for (int i = 0; i < ele.funcs.size(); i++) {
        auto &f = ele.funcs[i];
        for (auto &bb : f->bbs) {
            for (auto &op : bb->ops) {
                if (op->type == Operation::T::FUNC_CALL) {
                    auto callee = op->call_info.called_function.lock();
                    if (callee != nullptr && !callee->is_built_in) {
                        assert(func_idx_mapping.find(callee.get()) != func_idx_mapping.end());
                        auto dst = func_idx_mapping[callee.get()];
                        call_edges.set_edge(i, dst, std::monostate());
                    }
                }
            }
        }
    }

    Graph<
        std::shared_ptr<Function>,
        std::monostate,
        AdjacencyList<std::monostate>
    > call_graph(ele.funcs, std::move(call_edges));

    return std::move(call_graph);
}

void element_function_inline(Element &ele) {
    // we only need to inline the entry function
    auto entry_func = ele.entry();
    auto call_graph = call_graph_of_ele(ele);
    auto bbs = generate_inline_bbs(call_graph, *entry_func, entry_func->args);

    entry_func->bbs.swap(bbs);

    auto entry_func_ptr = entry_func.get();

    for (auto &bb : entry_func->bbs) {
        bb->parent = entry_func.get();
    }

    auto new_call_graph = call_graph_of_ele(ele);

    std::unordered_set<Function *> to_remove;
    for (int i = 0; i < new_call_graph.n_vertex(); i++) {
        if (i == ele.entry_func_idx()) {
            continue;
        }
        std::vector<bool> visited(new_call_graph.n_vertex(), false);
        if (!reachable(new_call_graph, ele.entry_func_idx(), i, visited)) {
            to_remove.insert(ele.funcs[i].get());
        }
    }

    auto iter = ele.funcs.begin();
    while (iter != ele.funcs.end()) {
        if (to_remove.find(iter->get()) != to_remove.end()) {
            iter = ele.funcs.erase(iter);
        } else {
            iter++;
        }
    }

    for (int i = 0; i < ele.funcs.size(); i++) {
        if (ele.funcs[i].get() == entry_func_ptr) {
            ele.set_entry_func_idx(i);
            break;
        }
    }
}

Graph<
    std::shared_ptr<BasicBlock>,
    std::monostate,
    AdjacencyList<std::monostate>
> control_graph_of_func(const Function& f) {
    AdjacencyList<std::monostate> edges(f.bbs.size());

    std::unordered_map<std::shared_ptr<BasicBlock>, size_t> idx_mapping;

    for (size_t i = 0; i < f.bbs.size(); i++) {
        idx_mapping[f.bbs[i]] = i;
    }

    for (size_t i = 0; i < f.bbs.size(); i++) {
        auto n_bb = f.bbs[i]->default_next_bb.lock();
        if (n_bb == nullptr) {
            assert(f.bbs[i]->is_err || f.bbs[i]->is_return);
            continue;
        }
        assert(idx_mapping.find(n_bb) != idx_mapping.end());
        edges.set_edge(i, idx_mapping[n_bb], std::monostate());
        for (auto& e : f.bbs[i]->branches) {
            auto n_bb = e.next_bb.lock();
            assert(idx_mapping.find(n_bb) != idx_mapping.end());
            edges.set_edge(i, idx_mapping[n_bb], std::monostate());
        }
    }

    Graph<
        std::shared_ptr<BasicBlock>,
        std::monostate,
        AdjacencyList<std::monostate>
    > graph(f.bbs, std::move(edges));
    return graph;
}

Graph<
    std::monostate,
    std::monostate,
    AdjacencyList<std::monostate>
> scc_graph_from_scc(
        const std::vector<std::vector<size_t>>& scc_list,
        const Graph<
            std::shared_ptr<BasicBlock>,
            std::monostate,
            AdjacencyList<std::monostate>>& ctl_graph) {
    std::vector<std::monostate> scc_graph_vertices(scc_list.size(), std::monostate());
    AdjacencyList<std::monostate> scc_edges(scc_list.size());
    std::unordered_map<int, int> idx2sccidx;
    for (int i = 0; i < scc_list.size(); i++) {
        for (auto j : scc_list[i]) {
            idx2sccidx[j] = i;
        }
    }
    for (int i = 0; i < scc_list.size(); i++) {
        auto &scc = scc_list[i];
        auto &edges = ctl_graph.edges();
        for (auto &v : scc) {
            for (auto it = edges.out_edge_begin(v); it != it.end(); ++it) {
                scc_edges.set_edge(i, idx2sccidx[*it], std::monostate());
            }
        }
    }

    Graph<
        std::monostate,
        std::monostate,
        AdjacencyList<std::monostate>
    > scc_graph(std::move(scc_graph_vertices), std::move(scc_edges));
    return scc_graph;
}

}
