#include "hir-stateop.hpp"
#include "hir-common-pass.hpp"
#include "llvm-helpers.hpp"
#include "utils.hpp"

namespace HIR {

struct StatePtrInfo {
    bool is_state_ptr;
    bool analyzing;

    std::string state_name;
    uint64_t state_offset;
    std::shared_ptr<Var> offset_var;

    StatePtrInfo()
        : is_state_ptr(false),
          state_name(""),
          state_offset(0),
          offset_var(nullptr),
          analyzing(false) {}
};

using InfoCacheT = std::unordered_map<std::shared_ptr<Var>, StatePtrInfo>;

StatePtrInfo stateptr_trace(InfoCacheT& info_cache, std::shared_ptr<Var> v);

class StatePtrTraceVisitor : public OperationConstVisitor<StatePtrTraceVisitor, StatePtrInfo> {
public:
    InfoCacheT& info_cache;

    StatePtrTraceVisitor(
        std::unordered_map<std::shared_ptr<Var>, StatePtrInfo>& c)
        : info_cache(c) {}

    StatePtrInfo visitDefault(const Operation& op) {
        return StatePtrInfo();
    }

    StatePtrInfo visitGep(const Operation& op) {
        StatePtrInfo result;
        auto base_info = stateptr_trace(info_cache, op.args[0]);
        if (base_info.analyzing) {
            return result;
        }
        if (base_info.is_state_ptr) {
            result = base_info;
            auto gep_ptr_type = op.args[0]->type;
            assert(gep_ptr_type->type == Type::T::POINTER);
            for (int i = 1; i < op.args.size(); i++) {
                // only last offset could be pointer
                auto &a = op.args[i];
                if (a->is_constant) {
                    auto idx = op.args[i]->constant;
                    auto off = 0;
                    if (gep_ptr_type->type == Type::T::POINTER) {
                        assert(i == 1);
                        assert(gep_ptr_type->pointee_type->sized());
                        off = gep_ptr_type->pointee_type->num_bytes() * idx;
                        gep_ptr_type = gep_ptr_type->pointee_type;
                    } else if (gep_ptr_type->type == Type::T::STRUCT) {
                        assert(0 <= idx && idx < gep_ptr_type->struct_info.fields.size());
                        off = gep_ptr_type->struct_info.offsets[idx];
                        gep_ptr_type = gep_ptr_type->struct_info.fields[idx];
                    } else if (gep_ptr_type->type == Type::T::ARRAY) {
                        assert(0 <= idx && idx < gep_ptr_type->array_info.num_element);
                        off = gep_ptr_type->array_info.element_type->num_bytes() * idx;
                        gep_ptr_type = gep_ptr_type->array_info.element_type;
                    } else {
                        assert(false && "unknown type");
                    }
                    result.state_offset += off;
                } else {
                    assert(i == op.args.size() - 1);
                    assert(gep_ptr_type->type == Type::T::ARRAY);
                    assert(result.offset_var == nullptr);
                    result.offset_var = a;
                }
            }
        }
        return result;
    }
};

StatePtrInfo stateptr_trace(InfoCacheT& info_cache, std::shared_ptr<Var> v) {
    if (info_cache.find(v) != info_cache.end()) {
        return info_cache[v];
    }

    if (v->is_constant) {
        return StatePtrInfo();
    }

    StatePtrTraceVisitor visitor(info_cache);
    auto src_op = v->src_op.lock();
    assert(src_op != nullptr);
    info_cache[v].analyzing = true;
    StatePtrInfo info = visitor.visit(*src_op);
    info_cache[v] = info;
    return info;
}

Type* find_state_by_off(Element& ele, size_t off) {
    auto state_t = ele.element_type;
    assert(state_t->type == Type::T::STRUCT);
    Type* ret = nullptr;
    for (int i = 0; i < state_t->struct_info.fields.size(); i++) {
        if (off == state_t->struct_info.offsets[i]) {
            return state_t->struct_info.fields[i];
        }
    }
    return ret;
}

void init_stateptr_info_cache(Element& ele, InfoCacheT& cache) {
    auto entry_f = ele.entry();
    cache[entry_f->args[0]] = StatePtrInfo();
    cache[entry_f->args[1]] = StatePtrInfo();
    cache[entry_f->args[2]] = StatePtrInfo();

    cache[entry_f->args[0]].is_state_ptr = true;
}

void split_stateptr_branch(Element &ele) {
    auto entry_f = ele.entry();
    auto ctl_graph = control_graph_of_func(*entry_f);
    auto scc_list = ctl_graph.StronglyConnectedComponents();
    auto scc_graph = scc_graph_from_scc(scc_list, ctl_graph);
    auto topo_order = scc_graph.TopologicalSort();

    InfoCacheT info_cache;
    init_stateptr_info_cache(ele, info_cache);

    struct SplitPoint {
        std::shared_ptr<BasicBlock> bb = nullptr;
        std::shared_ptr<Operation> op = nullptr;
    };
    std::vector<SplitPoint> to_split;
    for (int i = 0; i < topo_order.size(); i++) {
        auto& scc = scc_list[topo_order[i]];
        assert(scc.size() > 0);
        if (scc.size() > 1) {
            continue;
        }
        auto& bb = ctl_graph.vertex_ref(scc[0]);
        assert(bb == entry_f->bbs[scc[0]]);
        bool should_split = false;
        for (int j = 0; j < bb->ops.size(); j++) {
            auto& op = bb->ops[j];
            if (op->type == Operation::T::SELECT) {
                auto t_val_info = stateptr_trace(info_cache, op->args[1]);
                auto f_val_info = stateptr_trace(info_cache, op->args[2]);
                if (t_val_info.is_state_ptr || f_val_info.is_state_ptr) {
                    SplitPoint pt;
                    pt.op = op;
                    to_split.emplace_back(pt);
                }
            } else if (op->type == Operation::T::PHINODE) {
                std::vector<StatePtrInfo> info_list;
                for (auto& a : op->args) {
                    info_list.emplace_back(stateptr_trace(info_cache, op->dst_vars[0]));
                }
                for (auto& info : info_list) {
                    if (info.is_state_ptr) {
                        should_split = true;
                        break;
                    }
                }
            }
        }
        if (should_split) {
            SplitPoint pt;
            pt.bb = bb;
            to_split.emplace_back(pt);
        }
    }

    for (auto& loc : to_split) {
        if (loc.op == nullptr) {
            // split basic block
            // find bb idx
            int idx = -1;
            for (int i = 0; i < entry_f->bbs.size(); i++) {
                if (entry_f->bbs[i] == loc.bb) {
                    idx = i;
                }
            }
            assert(idx >= 0);
            fork_from_bb(*entry_f, idx);
        } else {
            break_select_op(*entry_f, loc.op);
        }
    }

    remove_unused_phi_entry(*entry_f);
    update_uses(ele);
}

void replace_vector_ops(Element& ele) {
    auto entry_f = ele.entry();
    InfoCacheT info_cache;
    init_stateptr_info_cache(ele, info_cache);
    for (auto &bb : entry_f->bbs) {
        for (auto &op : bb->ops) {
            if (op->type != Operation::T::FUNC_CALL) {
                continue;
            }
            auto fn = op->call_info.called_function.lock();
            if (!fn->is_built_in) {
                continue;
            }
            if (fn->name == "VectorIdxOp") {
                auto base_info = stateptr_trace(info_cache, op->args[0]);
                assert(base_info.offset_var == nullptr);
                assert(ele.states.find(base_info.state_offset) != ele.states.end());
                auto state_var = ele.states[base_info.state_offset];
                assert(state_var->type->type == Type::T::VECTOR);
                op->args[0] = state_var;
            }
        }
    }
}

void replace_map_ops(Element &ele) {
    auto entry_f = ele.entry();
    InfoCacheT info_cache;
    init_stateptr_info_cache(ele, info_cache);
    for (auto &bb : entry_f->bbs) {
        for (auto &op : bb->ops) {
            if (op->type != Operation::T::FUNC_CALL) {
                continue;
            }
            auto fn = op->call_info.called_function.lock();
            if (!fn->is_built_in) {
                continue;
            }
            if (fn->name == "HashMapFindp") {
                auto base_info = stateptr_trace(info_cache, op->args[0]);
                assert(base_info.offset_var == nullptr);
                assert(ele.states.find(base_info.state_offset) != ele.states.end());
                auto state_var = ele.states[base_info.state_offset];
                assert(state_var->type->type == Type::T::MAP);
                op->args[0] = state_var;
            } else if (fn->name == "HashMapInsert") {
                auto base_info = stateptr_trace(info_cache, op->args[0]);
                assert(base_info.offset_var == nullptr);
                assert(ele.states.find(base_info.state_offset) != ele.states.end());
                auto state_var = ele.states[base_info.state_offset];
                assert(state_var->type->type == Type::T::MAP);
                op->args[0] = state_var;
            }
        }
    }
}

void replace_fixsized_array_ops(Element &ele) {
}

struct StructTraceInfo {
    bool is_struct_ptr = false;
    bool have_write_back = false;
    std::vector<int> offsets{};
    std::shared_ptr<Var> struct_obj;
};

StructTraceInfo trace_struct_info(
        std::unordered_map<std::shared_ptr<Var>, StructTraceInfo>& info_cache,
        std::shared_ptr<Var> v);

class StructInfoVisitor : public OperationConstVisitor<StructInfoVisitor> {
public:
    StructTraceInfo& info;
    std::unordered_map<std::shared_ptr<Var>, StructTraceInfo>* info_cache;

    StructInfoVisitor(StructTraceInfo& i_ref) : info(i_ref) {}

    void visitDefault(const Operation& op) {
        info.is_struct_ptr = false;
    }

    void visitAlloca(const Operation& op) {
        auto t = op.alloca_type;
        if (t->type == Type::T::STRUCT || t->type == Type::T::ARRAY) {
            info.is_struct_ptr = true;
            info.struct_obj = op.dst_vars[0];
        }
    }

    void visitGep(const Operation& op) {
        auto base_info = trace_struct_info(*info_cache, op.args[0]);
        if (base_info.is_struct_ptr) {
            info = base_info;
            for (int i = 1; i < op.args.size(); i++) {
                auto& off = op.args[i];
                if (off->is_constant) {
                    info.offsets.emplace_back(off->constant);
                } else {
                    info.is_struct_ptr = false;
                    return;
                }
            }
        }
    }

    void visitPhiNode(const Operation& op) {
        std::vector<StructTraceInfo> arg_infos;
        for (auto& a : op.args) {
            arg_infos.emplace_back(trace_struct_info(*info_cache, a));
        }
        assert(arg_infos.size() > 0);
        bool all_eq = true;
        StructTraceInfo base = arg_infos[0];
        for (int i = 1; i < arg_infos.size(); i++) {
            auto other = arg_infos[i];
            bool offsets_eq;
            if (other.offsets.size() != base.offsets.size()) {
                all_eq = false;
                break;
            }
            for (int j = 0; j < base.offsets.size(); j++) {
                if (base.offsets[j] != other.offsets[j]) {
                    all_eq = false;
                    break;
                }
            }
            if (other.is_struct_ptr != base.is_struct_ptr
                || other.have_write_back != base.have_write_back
                || other.struct_obj != base.struct_obj) {
                all_eq = false;
                break;
            }
        }
        if (all_eq) {
            info = base;
        } else {
            op.print(std::cout);
            std::cout << " :: not all eq" << std::endl;
            visitDefault(op);
        }
    }

    void visitFuncCall(const Operation& op) {
        auto fn = op.call_info.func_name;
        std::string func_name;
        auto demangled = cxx_demangle(fn, func_name);
        if (!demangled) {
            func_name = fn;
        }

        func_name = remove_template(func_name);
        if (str_begin_with(func_name, "Vector::operator[]")) {
            info.is_struct_ptr = true;
            info.have_write_back = true;
            info.struct_obj = op.dst_vars[0];
        } else if (str_begin_with(func_name, "HashMap::findp")) {
            info.is_struct_ptr = true;
            info.have_write_back = true;
            info.struct_obj = op.dst_vars[0];
        }
    }
};

StructTraceInfo trace_struct_info(
        std::unordered_map<std::shared_ptr<Var>, StructTraceInfo>& info_cache,
        std::shared_ptr<Var> v) {
    if (info_cache.find(v) == info_cache.end()) {
        StructTraceInfo& info_ref = info_cache[v];
        StructInfoVisitor visitor(info_ref);
        visitor.info_cache = &info_cache;
        if (!v->is_constant && !v->is_param && !v->is_global) {
            visitor.visit(*v->src_op.lock());
        }
    }
    return info_cache[v];
}

void replace_regular_struct_access(Function& func) {
    update_uses(func);
    std::unordered_map<std::shared_ptr<Var>, StructTraceInfo> info_cache;
    std::unordered_set<std::shared_ptr<Var>> struct_var;

    for (auto& bb : func.bbs) {
        for (auto& op : bb->ops) {
            if (op->type == Operation::T::LOAD || op->type == Operation::T::STORE) {
                auto ptr_info = trace_struct_info(info_cache, op->args[0]);
                if (ptr_info.is_struct_ptr) {
                    auto new_op = std::make_shared<Operation>();
                    new_op->args.clear();
                    new_op->args.emplace_back(ptr_info.struct_obj);
                    assert(ptr_info.offsets.size() > 1);
                    for (int i = 1; i < ptr_info.offsets.size(); i++) {
                        new_op->struct_ref_info.emplace_back(ptr_info.offsets[i]);
                    }
                    if (op->type == Operation::T::LOAD) {
                        new_op->type = Operation::T::STRUCT_GET;
                        new_op->dst_vars.emplace_back(op->dst_vars[0]);
                    } else {
                        new_op->type = Operation::T::STRUCT_SET;
                        new_op->args.emplace_back(op->args[1]);
                    }
                    new_op->struct_set_have_writeback = ptr_info.have_write_back;
                    op = new_op;
                }
            }
        }
    }
    update_uses(func);
}
}
