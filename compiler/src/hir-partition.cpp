#include "hir-partition.hpp"
#include "llvm-helpers.hpp"
#include "utils.hpp"

namespace HIR {
bool is_constant_op(const HIR::Operation& op) {
    using T = HIR::Operation::T;
    switch (op.type) {
    case T::FUNC_CALL:
        {
            auto fn = remove_template(cxx_try_demangle(op.call_info.func_name));
            if (fn == "Packet::transport_header() const"
                || fn == "WritablePacket::ip_header() const"
                || fn == "Packet::ip_header() const") {
                return true;
            }
        }
    default:
        return false;
    }
}
std::unordered_set<std::shared_ptr<Var>> side_effect_set(const HIR::Operation& op) {
    std::unordered_set<std::shared_ptr<Var>> result = {};
    using T = HIR::Operation::T;
    switch (op.type) {
    case T::STRUCT_SET:
        result.insert(op.args[0]);
        break;
    case T::PKT_HDR_STORE:
        result.insert(op.args[0]);
        break;
    case T::FUNC_CALL:
        {
            auto fn = remove_template(cxx_try_demangle(op.call_info.func_name));
            if (fn == "HashMap::insert") {
                result.insert(op.args[0]);
            }
        }
    default:
        break;
    }
    return result;
}

bool is_pkt_field_access(const Operation& op) {
    return (op.type == Operation::T::PKT_HDR_LOAD
            || op.type == Operation::T::PKT_HDR_STORE);
}

bool have_dep(const Operation& o1, const Operation& o2) {
    std::unordered_set<std::shared_ptr<Var>> rs1(o1.args.begin(), o1.args.end());
    std::unordered_set<std::shared_ptr<Var>> rs2(o2.args.begin(), o2.args.end());

    if (is_constant_op(o1)) {
        rs1 = {};
    }
    if (is_constant_op(o2)) {
        rs2 = {};
    }

    auto ws1 = side_effect_set(o1);
    auto ws2 = side_effect_set(o2);

    if (is_pkt_field_access(o1) && is_pkt_field_access(o2)) {
        if (o1.args[0] == o2.args[0]
            && o1.pkt_op_info.header == o2.pkt_op_info.header
            && o1.pkt_op_info.field == o2.pkt_op_info.field) {
            return true;
        }
        if (o1.type == Operation::T::PKT_HDR_STORE
            && o2.type == Operation::T::PKT_HDR_LOAD) {
            if (o1.args[1] == o2.dst_vars[0]) {
                return true;
            }
        }
        if (o2.type == Operation::T::PKT_HDR_STORE
            && o1.type == Operation::T::PKT_HDR_LOAD) {
            if (o2.args[1] == o1.dst_vars[0]) {
                return true;
            }
        }
        return false;
    }

    // read-write dep
    for (auto& d : o1.dst_vars) {
        for (auto& a : rs2) {
            if (d == a) {
                return true;
            }
        }
    }
    for (auto& d : o2.dst_vars) {
        for (auto& a : rs1) {
            if (d == a) {
                return true;
            }
        }
    }

    // read-write dep
    for (auto& a : rs1) {
        if (ws2.find(a) != ws2.end()) {
            return true;
        }
    }
    for (auto& a : rs2) {
        if (ws1.find(a) != ws1.end()) {
            return true;
        }
    }

    // write-write dep (no need to check dst_vars as they are always unique)
    for (auto& v : ws1) {
        if (ws2.find(v) != ws2.end()) {
            return true;
        }
    }
    return false;
}

void remove_pre(
        const Operation& o,
        std::unordered_set<std::shared_ptr<BasicBlock>>& visited,
        std::shared_ptr<BasicBlock> curr,
        int& delta) {
    if (visited.find(curr) != visited.end()) {
        return;
    }
    for (auto& op : curr->ops) {
        auto& l = op->meta_ref<LabelSet>();
        if (have_dep(o, *op)) {
            auto it = l.find(Label::PRE);
            if (it != l.end()) {
                l.erase(Label::PRE);
                delta++;
                break;
            }
        }
    }

    visited.insert(curr);
    for (auto& e : curr->branches) {
        auto n_bb = e.next_bb.lock();
        assert(n_bb != nullptr);
        remove_pre(o, visited, n_bb, delta);
    }
    if (!curr->is_return && !curr->is_err) {
        auto n_bb = curr->default_next_bb.lock();
        assert(n_bb != nullptr);
        remove_pre(o, visited, n_bb, delta);
    }
}

void remove_post(
        const Operation& o,
        const std::unordered_map<
            std::shared_ptr<BasicBlock>,
            std::unordered_set<std::shared_ptr<BasicBlock>>>& from,
        std::unordered_set<std::shared_ptr<BasicBlock>>& visited,
        std::shared_ptr<BasicBlock> curr,
        int& delta) {
    if (visited.find(curr) != visited.end()) {
        return;
    }

    for (auto& op : curr->ops) {
        auto& l = op->meta_ref<LabelSet>();
        if (have_dep(o, *op)) {
            auto it = l.find(Label::POST);
            if (it != l.end()) {
                l.erase(Label::POST);
                delta++;
                break;
            }
        }
    }

    visited.insert(curr);
    auto prev_bbs_iter = from.find(curr);
    if (prev_bbs_iter == from.end()) {
        return;
    }
    for (auto& prev_bb : prev_bbs_iter->second) {
        remove_post(o, from, visited, prev_bb, delta);
    }
}

void remove_label_if_conflict(
        const std::unordered_set<std::shared_ptr<Var>>& write_set,
        Operation& op,
        int& delta) {
    auto& l = op.meta_ref<LabelSet>();
    for (auto& a : op.args) {
        if (write_set.find(a) != write_set.end()) {
            auto it = l.find(Label::POST);
            if (it != l.end()) {
                l.erase(it);
                delta++;
                break;
            }
        }
    }
}

void label(Element &ele, LabelInitFn &init_fn) {
    update_uses(ele);
    auto entry_f = ele.entry();
    for (auto &bb : entry_f->bbs) {
        for (auto &op : bb->ops) {
            auto init_set = std::make_shared<LabelSet>();
            init_fn(*ele.module(), *op, *init_set);
            op->set_meta(init_set);
        }
    }

    std::unordered_map<
        std::shared_ptr<BasicBlock>,
        std::unordered_set<std::shared_ptr<BasicBlock>>> from;
    for (auto& bb : entry_f->bbs) {
        if (!bb->is_return && !bb->is_err) {
            auto n_bb = bb->default_next_bb.lock();
            assert(n_bb != nullptr);
            from[n_bb].insert(bb);
        }
        for (auto& e : bb->branches) {
            auto n_bb = e.next_bb.lock();
            from[n_bb].insert(bb);
        }
    }

    int delta = 0;
    std::unordered_set<std::shared_ptr<BasicBlock>> bb_set;
    for (auto& bb : entry_f->bbs) {
        bb_set.insert(bb);
    }
    do {
        delta = 0;
        for (auto& bb : entry_f->bbs) {
            for (int op_idx = 0; op_idx < bb->ops.size(); op_idx++) {
                auto& op = bb->ops[op_idx];
                auto &labels = op->meta_ref<LabelSet>();
                if (labels.find(Label::PRE) == labels.end()) {
                    // ops that depends on this one can not be PRE
                    if (op->dst_vars.size() > 0) {
                        for (auto& d : op->dst_vars) {
                            for (auto& u : d->uses) {
                                if (u.type == Var::Use::T::BB_COND) {
                                    auto dep_bb_ptr = u.u.bb_ptr;
                                    for (auto& o : dep_bb_ptr->ops) {
                                        auto& ol = o->meta_ref<LabelSet>();
                                        if (ol.find(Label::PRE) != ol.end()) {
                                            ol.erase(Label::PRE);
                                            delta++;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    for (int i = op_idx + 1; i < bb->ops.size(); i++) {
                        auto& l = bb->ops[i]->meta_ref<LabelSet>();
                        if (have_dep(*op, *bb->ops[i])) {
                            auto it = l.find(Label::PRE);
                            if (it != l.end()) {
                                l.erase(Label::PRE);
                                delta++;
                            }
                        }
                    }
                    std::unordered_set<std::shared_ptr<BasicBlock>> visited = {};
                    for (auto& e : bb->branches) {
                        auto n_bb = e.next_bb.lock();
                        remove_pre(*op, visited, n_bb, delta);
                    }
                    if (!bb->is_return && !bb->is_err) {
                        auto n_bb = bb->default_next_bb.lock();
                        assert(n_bb != nullptr);
                        remove_pre(*op, visited, n_bb, delta);
                    }
                }
                if (labels.find(Label::POST) == labels.end()) {
                    // ops that this one deponds on can not be POST
                    for (int i = 0; i < op_idx; i++) {
                        auto& l = bb->ops[i]->meta_ref<LabelSet>();
                        if (have_dep(*op, *bb->ops[i])) {
                            auto it = l.find(Label::POST);
                            if (it != l.end()) {
                                l.erase(Label::POST);
                                delta++;
                            }
                        }
                    }
                    std::unordered_set<std::shared_ptr<BasicBlock>> visited;
                    for (auto& prev_bb : from[bb]) {
                        remove_post(*op, from, visited, prev_bb, delta);
                    }
                }
            }
        }
    } while (delta > 0);
}

void detect_short_circuit(
        Function& func,
        const std::unordered_set<std::shared_ptr<BasicBlock>>& unchanged,
        std::weak_ptr<BasicBlock>& prev_bb,
        std::shared_ptr<BasicBlock> curr) {
    if (unchanged.find(curr) == unchanged.end()) {
        return;
    }

    if (curr->is_return) {
        // found one short_circuit
        auto new_ret_bb = std::make_shared<BasicBlock>(*curr);
        new_ret_bb->name = NameFactory::get()(NameFactory::get().base(curr->name) + "_direct_ret");
        new_ret_bb->is_short_circuit = true;
        new_ret_bb->ops.clear();
        std::unordered_map<std::shared_ptr<Var>, std::shared_ptr<Var>> var_mapping;
        for (auto& op : curr->ops) {
            auto new_op = std::make_shared<Operation>(*op);
            new_op->parent = new_ret_bb.get();
            new_op->dst_vars.clear();
            for (auto& d : op->dst_vars) {
                auto nd = std::make_shared<Var>(*d);
                nd->name = NameFactory::get()(NameFactory::get().base(d->name));
                var_mapping[d] = nd;
            }
            new_ret_bb->ops.emplace_back(new_op);

            for (auto& a : new_op->args) {
                if (var_mapping.find(a) != var_mapping.end()) {
                    a = var_mapping[a];
                }
            }
        }
        prev_bb = new_ret_bb;
        func.bbs.emplace_back(new_ret_bb);
    }

    for (auto& e : curr->branches) {
        detect_short_circuit(func, unchanged, e.next_bb, e.next_bb.lock());
    }
    if (!curr->is_return && !curr->is_err) {
        detect_short_circuit(func, unchanged, curr->default_next_bb, curr->default_next_bb.lock());
    }
}

template <typename T1, typename T2>
void remove_by_label(
        Function &func,
        T1 should_filter,
        T2 in_next_dev,
        bool discover_short_circuit = false) {
    // store removed ops here so that the weak_ptr "src_op" still works
    auto next_dev_bb = std::make_shared<BasicBlock>();
    next_dev_bb->name = "to_next_dev";
    next_dev_bb->is_err = true;
    bool next_dev_bb_used = false;
    std::vector<std::shared_ptr<Operation>> removed_ops;
    std::unordered_set<std::shared_ptr<BasicBlock>> unchanged_bbs;
    for (auto &bb : func.bbs) {
        auto iter = bb->ops.begin();
        int num_deleted = 0;
        while (iter != bb->ops.end()) {
            auto &op = *iter;
            auto &l = op->meta_ref<LabelSet>();
            if (should_filter(l)) {
                removed_ops.emplace_back(*iter);
                iter = bb->ops.erase(iter);
                num_deleted++;
            } else {
                iter++;
            }
        }
        if (num_deleted == 0) {
            unchanged_bbs.insert(bb);
        }
        auto branch_iter = bb->branches.begin();
        bool removed = false;
        while (branch_iter != bb->branches.end()) {
            auto &e = *branch_iter;
            if (e.is_conditional && !e.cond_var->is_param) {
                auto v = e.cond_var;
                auto src_op = v->src_op.lock();
                assert(src_op != nullptr);
                auto &l = src_op->meta_ref<LabelSet>();
                if (in_next_dev(l)) {
                    branch_iter = bb->branches.erase(branch_iter);
                    removed = true;
                    continue;
                }
            }
            branch_iter++;
        }
        if (removed) {
            bb->default_next_bb = next_dev_bb;
            next_dev_bb_used = true;
        }
    }

    if (next_dev_bb_used) {
        next_dev_bb->is_err = false;
        next_dev_bb->is_return = true;
        next_dev_bb->is_short_circuit = false;
        func.bbs.emplace_back(next_dev_bb);
    }

    if (discover_short_circuit) {
        std::weak_ptr<BasicBlock> entry_bb = func.bbs[func.entry_bb_idx()];
        detect_short_circuit(func, unchanged_bbs, entry_bb, entry_bb.lock());
    }
}

void find_transferred_vars(
        std::shared_ptr<Function> fst,
        std::shared_ptr<Function> snd,
        std::unordered_set<std::shared_ptr<Var>>& var_set) {
    std::unordered_set<std::shared_ptr<Var>> defined_in_fst;

    for (auto& bb : fst->bbs) {
        for (auto& op : bb->ops) {
            for (auto& dst : op->dst_vars) {
                defined_in_fst.emplace(dst);
            }
        }
    }

    for (auto& bb : snd->bbs) {
        for (auto& op : bb->ops) {
            for (auto& a : op->args) {
                if (a->is_constant || a->is_param
                    || a->is_global || a->is_undef
                    || a->is_constant_name) {
                    continue;
                }
                if (defined_in_fst.find(a) != defined_in_fst.end()) {
                    var_set.emplace(a);
                }
            }
        }
    }
}

PartitionResult partition(const Function& func) {
    PartitionResult result;

    // first copy the function into three
    result.pre = std::make_shared<Function>(func);
    result.cpu = std::make_shared<Function>(func);
    result.post = std::make_shared<Function>(func);

    // now delete from each of the copies according to labels
    remove_by_label(
        *result.pre,
        [](const std::unordered_set<Label>& ls) -> bool {
            return ls.find(Label::PRE) == ls.end();
        },
        [](const std::unordered_set<Label>& ls) -> bool {
            return ls.find(Label::PRE) == ls.end();
        },
        true);

    std::unordered_set<std::string> bb_names;
    std::unordered_set<std::shared_ptr<BasicBlock>> bb_ptrs;
    for (auto& bb : result.pre->bbs) {
        assert(bb_ptrs.find(bb) == bb_ptrs.end());
        assert(bb_names.find(bb->name) == bb_names.end());
        bb_names.insert(bb->name);
        bb_ptrs.insert(bb);
    }

    remove_by_label(
        *result.cpu,
        [](const std::unordered_set<Label>& ls) -> bool {
            auto have_pre = ls.find(Label::PRE) != ls.end();
            auto have_post = ls.find(Label::POST) != ls.end();
            return have_pre || have_post;
        },
        [](const std::unordered_set<Label>& ls) -> bool {
            auto have_pre = ls.find(Label::PRE) != ls.end();
            auto have_post = ls.find(Label::POST) != ls.end();
            return !have_pre && have_post;
        });

    remove_by_label(
        *result.post,
        [](const std::unordered_set<Label>& ls) -> bool {
            auto have_pre = ls.find(Label::PRE) != ls.end();
            auto not_post = ls.find(Label::POST) == ls.end();
            return have_pre || not_post;
        },
        [](const std::unordered_set<Label>& ls) -> bool {
            return false;
        });

    remove_empty_bb(*result.pre);
    remove_empty_bb(*result.cpu);
    remove_empty_bb(*result.post);

    // now find all the transfered vars
    find_transferred_vars(result.pre, result.cpu, result.pre_to_cpu_vars);
    find_transferred_vars(result.pre, result.post, result.cpu_to_post_vars);
    find_transferred_vars(result.cpu, result.post, result.cpu_to_post_vars);
    return result;
}
}
