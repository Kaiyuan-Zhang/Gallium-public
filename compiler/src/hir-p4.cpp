#include <functional>
#include "hir-p4.hpp"
#include "hir-common-pass.hpp"
#include "llvm-helpers.hpp"

namespace P4IR {
using namespace HIR;

bool is_offloadable_func(const HIR::Operation& op) {
    static const std::vector<std::string> prefix_match = {
        "Vector::operator[]",
        "HashMap::findp",
    };
    static const std::unordered_set<std::string> exact_match = {
        "Packet::transport_length() const",
        "Packet::has_network_header() const",
        "Element::checked_output_push(int, Packet*) const",
        "Packet::kill()",
        "IPFlowID::IPFlowID(Packet const*, bool)",
    };

    assert(op.type == HIR::Operation::T::FUNC_CALL);
    auto fn = remove_template(cxx_try_demangle(op.call_info.func_name));
    if (exact_match.find(fn) != exact_match.end()) {
        return true;
    }

    for (auto& prefix : prefix_match) {
        if (str_begin_with(fn, prefix)) {
            return true;
        }
    }

    return false;
}

void p4_initial_label(const Module& m, const HIR::Operation& op, LabelSet& labels) {
    labels.clear();
    labels.insert(Label::CPU);
    using OpType = HIR::Operation::T;
    switch (op.type) {
    case OpType::ALLOCA:
    case OpType::PKT_HDR_LOAD:
    case OpType::PKT_HDR_STORE:
    case OpType::PHINODE:
    case OpType::SELECT:
    case OpType::STRUCT_GET:
        labels.insert(Label::PRE);
        labels.insert(Label::POST);
        break;
    case OpType::ARITH:
        if (op.arith_info.t == ArithType::INT_CMP) {
            labels.insert(Label::PRE);
            labels.insert(Label::POST);
        } else {
            switch (op.arith_info.u.iarith_t) {
            case IntArithType::INT_MUL:
            case IntArithType::INT_DIV:
            case IntArithType::INT_MOD:
            case IntArithType::INT_UDIV:
            case IntArithType::INT_UMOD:
                break;
            default:
                labels.insert(Label::PRE);
                labels.insert(Label::POST);
                break;
            }
        }
        break;
    case OpType::FUNC_CALL:
        if (is_offloadable_func(op)) {
            labels.insert(Label::PRE);
            labels.insert(Label::POST);
        }
        break;
    case OpType::STRUCT_SET:
        if (!op.struct_set_have_writeback) {
            labels.insert(Label::PRE);
            labels.insert(Label::POST);
        }
        break;
    default:
        break;
    }
}

void print_labelset(std::ostream& os, const LabelSet& l) {
    std::vector<std::string> s_vec;
    if (l.find(Label::PRE) != l.end()) {
        s_vec.emplace_back("PRE");
    }
    if (l.find(Label::CPU) != l.end()) {
        s_vec.emplace_back("CPU");
    }
    if (l.find(Label::POST) != l.end()) {
        s_vec.emplace_back("POST");
    }

    os << "{";
    for (int i = 0; i < s_vec.size(); i++) {
        if (i != 0) {
            os << ", ";
        }
        os << s_vec[i];
    }
    os << "}";
}

void print_element_with_label(std::ostream& os, const HIR::Element& ele) {
    // only print entry_f
    HIR::Function::OpPrinterT printer = [](std::ostream& os, const HIR::Operation& op) -> void {
        op.print(os);
        auto meta_ptr = op.meta<LabelSet>();
        if (meta_ptr != nullptr) {
            os << " @ ";
            print_labelset(os, *meta_ptr);
        }
    };
    for (auto& f : ele.funcs) {
        f->print(os, printer);
    }
}

void print_function_with_label(std::ostream& os, const Function& func) {
    // only print entry_f
    HIR::Function::OpPrinterT printer = [](std::ostream& os, const HIR::Operation& op) -> void {
        op.print(os);
        auto meta_ptr = op.meta<LabelSet>();
        if (meta_ptr != nullptr) {
            os << " @ ";
            print_labelset(os, *meta_ptr);
        }
    };
    func.print(os, printer);
}

P4OffloadResult partition_hir(std::shared_ptr<Element> ele) {
    P4OffloadResult result;
    LabelInitFn init_fn = p4_initial_label;
    HIR::label(*ele, init_fn);
    auto partition_result = partition(*ele->entry());
    result.ingress_prog = p4_program_from_function(ele, partition_result.pre, false);
    result.egress_prog = p4_program_from_function(ele, partition_result.post, true);
    result.ele = std::make_shared<Element>(*ele);
    result.ele->funcs[ele->entry_func_idx()] = partition_result.cpu;
    return result;
}

void split_bb_for_p4(Function& func) {
    std::vector<std::shared_ptr<BasicBlock>> to_add;
    for (auto& bb : func.bbs) {
        // first create data dependency
        std::shared_ptr<BasicBlock> curr_bb = bb;
        std::vector<std::shared_ptr<HIR::Operation>> curr_ops = {};
        std::vector<std::vector<std::shared_ptr<HIR::Operation>>> bb_ops_list;
        std::unordered_map<int, std::unordered_set<int>> deps;
        for (int i = 1; i < bb->ops.size(); i++) {
            auto& s = deps[i];
            for (int j = 0; j < i; j++) {
                if (have_dep(*bb->ops[i], *bb->ops[j])) {
                    deps[i].insert(j);
                }
            }
        }
        int num_processed = 0;
        std::vector<bool> visited(bb->ops.size(), false);
        do {
            std::vector<int> idx_list = {};
            for (int i = 0; i < bb->ops.size(); i++) {
                if (visited[i]) {
                    continue;
                }
                if (deps[i].size() == 0) {
                    idx_list.emplace_back(i);
                    curr_ops.emplace_back(bb->ops[i]);
                    visited[i] = true;
                    num_processed++;
                }
            }
            for (auto& idx : idx_list) {
                for (int j = 0; j < bb->ops.size(); j++) {
                    deps[j].erase(idx);
                }
            }
            bb_ops_list.emplace_back(curr_ops);
            curr_ops.clear();
        } while (num_processed < bb->ops.size());
        std::vector<BasicBlock::BranchEntry> branches = bb->branches;
        std::weak_ptr<BasicBlock> default_next = bb->default_next_bb;
        bool is_return = bb->is_return;
        bool is_err = bb->is_err;
        bool is_short_circuit = bb->is_short_circuit;
        for (int i = 0; i < bb_ops_list.size(); i++) {
            auto& ops = bb_ops_list[i];
            curr_bb->ops = ops;
            if (i != bb_ops_list.size() - 1) {
                auto next_bb = std::make_shared<BasicBlock>();
                curr_bb->branches.clear();
                curr_bb->default_next_bb = next_bb;
                curr_bb->is_return  = false;
                curr_bb->is_err = false;
                curr_bb->is_short_circuit = false;
                next_bb->name = NameFactory::get()(NameFactory::get().base(bb->name));
                next_bb->parent = &func;
                if (curr_bb != bb) {
                    to_add.emplace_back(curr_bb);
                }
                curr_bb = next_bb;
            }
        }
        if (curr_bb != bb) {
            curr_bb->branches = branches;
            curr_bb->default_next_bb = default_next;
            curr_bb->is_return = is_return;
            curr_bb->is_err = is_err;
            curr_bb->is_short_circuit = is_short_circuit;
            to_add.emplace_back(curr_bb);
        }
    }
    for (auto& bb : to_add) {
        func.bbs.emplace_back(bb);
    }
    update_uses(func);
}

using TraceT = std::vector<std::shared_ptr<BasicBlock>>;

void collect_trace(
        std::shared_ptr<BasicBlock> curr_bb,
        TraceT& curr_trace,
        std::vector<TraceT>& traces) {
    curr_trace.emplace_back(curr_bb);
    if (curr_bb->is_return || curr_bb->is_err) {
        traces.emplace_back(curr_trace);
        return;
    }

    size_t sz = curr_trace.size();
    for (auto& e : curr_bb->branches) {
        collect_trace(e.next_bb.lock(), curr_trace, traces);
        assert(curr_trace.size() >= sz);
        curr_trace.resize(sz);
    }
    auto n_bb = curr_bb->default_next_bb.lock();
    assert(n_bb != nullptr);
    collect_trace(n_bb, curr_trace, traces);
    curr_trace.resize(sz);
}

struct StructMetaMapping {
    struct Entry {
        std::string var_name;
        int bw;
    };
    std::vector<StructMetaMapping> fields;
    Entry unit;

    bool is_unit() const { return fields.size() == 0; }
    std::vector<Entry> get_flattened_metas() const {
        std::vector<Entry> r;
        if (is_unit()) {
            r.emplace_back(unit);
        } else {
            for (auto& f : fields) {
                auto vs = f.get_flattened_metas();
                r.insert(r.end(), vs.begin(), vs.end());
            }
        }
        return r;
    }
};

StructMetaMapping flatten_struct(HIR::Type* t, const std::string& name_prefix="meta_sf") {
    StructMetaMapping mapping;
    if (t->type == HIR::Type::T::ARRAY) {
        auto et = t->array_info.element_type;
        auto etm = flatten_struct(et);
        for (int i = 0; i < t->array_info.num_element; i++) {
            mapping.fields.emplace_back(etm);
        }
    } else if (t->type == HIR::Type::T::STRUCT) {
        int i = 0;
        for (auto& ft : t->struct_info.fields) {
            auto fm = flatten_struct(ft);
            mapping.fields.emplace_back(fm);
        }
    } else if (t->type == HIR::Type::T::INT) {
        auto var_name = NameFactory::get()(name_prefix);
        auto bw = t->bitwidth;
        mapping.fields.clear();
        mapping.unit = {var_name, bw};
    } else {
        assert(false && "unsupported struct type");
    }
    return mapping;
}

struct OpTranslateCtx {
    std::unordered_map<std::shared_ptr<Var>, std::string> transferred_vars;
    std::unordered_map<std::shared_ptr<Var>, std::string> meta_mapping;
    std::unordered_map<std::shared_ptr<Var>, StructMetaMapping> struct_mapping;
    std::unordered_map<std::shared_ptr<Var>, std::string> map_is_null;
    std::unordered_map<std::shared_ptr<Var>, StructMetaMapping> global_result_mapping;
    std::unordered_map<std::string, int> meta_var_bw;
};

class Op2P4Visitor : public OperationConstVisitor<Op2P4Visitor> {
public:
    std::shared_ptr<Action> act;
    OpTranslateCtx* ctx;
    bool is_egress = false;

    HeaderRef var_to_headerref(std::shared_ptr<Var> v) {
        if (v->is_constant) {
            return HeaderRef(std::to_string(v->constant));
        }
        if (is_egress) {
            if (ctx->meta_mapping.find(v) != ctx->meta_mapping.end()) {
                auto meta = ctx->meta_mapping[v];
                return HeaderRef(true, meta);
            } else {
                assert(ctx->transferred_vars.find(v) != ctx->transferred_vars.end());
                auto meta = ctx->transferred_vars[v];
                return HeaderRef("transfer", meta);
            }
        } else {
            assert(ctx->meta_mapping.find(v) != ctx->meta_mapping.end());
            auto meta = ctx->meta_mapping[v];
            return HeaderRef(true, meta);
        }
    }

    HeaderRef struct_var_to_headerref(std::shared_ptr<Var> v, const std::vector<int>& offsets) {
        if (ctx->struct_mapping.find(v) != ctx->struct_mapping.end()) {
            auto s_info = ctx->struct_mapping[v];
            for (auto& o : offsets) {
                assert(!s_info.is_unit());
                s_info = s_info.fields[o];
            }
            assert(s_info.is_unit());
            auto meta = s_info.unit.var_name;
            return HeaderRef(true, meta);
        } else {
            assert(is_egress);
            return HeaderRef("transfer", "from_prev_struct");
        }
    }

    void visitDefault(const HIR::Operation& op) {
        assert(false && "unknown op");
    }
    void visitAlloca(const HIR::Operation& op) {
    }

    void visitArith(const HIR::Operation& op) {
        auto dst = op.dst_vars[0];
        auto p4op = std::make_shared<P4IR::Operation>();
        p4op->dst = var_to_headerref(dst);
        for (auto& a : op.args) {
            if (a->type->type == HIR::Type::T::POINTER) {
                assert(op.arith_info.t == ArithType::INT_CMP);
                assert(op.arith_info.u.icmp_t == IntCmpType::EQ
                       || op.arith_info.u.icmp_t == IntCmpType::NE);
                continue;
            }
            p4op->args.emplace_back(var_to_headerref(a));
        }
        if (op.arith_info.t == ArithType::INT_ARITH) {
            switch (op.arith_info.u.iarith_t) {
            case IntArithType::INT_ADD:
                p4op->alu_op = "add";
                break;
            case IntArithType::INT_SUB:
                p4op->alu_op = "subtract";
                break;
            case IntArithType::INT_AND:
                p4op->alu_op = "bit_and";
                break;
            case IntArithType::INT_OR:
                p4op->alu_op = "bit_or";
                break;
            case IntArithType::INT_XOR:
                p4op->alu_op = "bit_xor";
                break;
            case IntArithType::INT_SHL:
                p4op->alu_op = "shift_left";
                break;
            case IntArithType::INT_LSHR:
            case IntArithType::INT_ASHR:
                p4op->alu_op = "shift_right";
                break;
            case IntArithType::INT_SEXT:
            case IntArithType::INT_ZEXT:
            case IntArithType::INT_TRUNC:
                p4op->alu_op = "modify_field";
                break;
            default:
                assert(false && "unknown arith op");
                break;
            }
        } else if (op.arith_info.t == ArithType::INT_CMP) {
            if (op.args[0]->type->type == HIR::Type::T::POINTER) {
                auto map_op = op.args[0]->src_op.lock();
                assert(map_op != nullptr);
                assert(ctx->map_is_null.find(map_op->args[0]) != ctx->map_is_null.end());
                p4op->alu_op = "modify_field";
                p4op->args = {HeaderRef(true, ctx->map_is_null[map_op->args[0]])};
            } else {
                p4op->alu_op = "subtract";
            }
        }
        act->ops.emplace_back(p4op);
    }

    void visitStructSet(const HIR::Operation& op) {
        auto struct_meta = struct_var_to_headerref(op.args[0], op.struct_ref_info);
        auto val_meta = var_to_headerref(op.args[1]);
        auto p4op = std::make_shared<P4IR::Operation>();
        p4op->alu_op = "modify_field";
        p4op->dst = struct_meta;
        p4op->args.emplace_back(val_meta);
        act->ops.emplace_back(p4op);
    }

    void visitStructGet(const HIR::Operation& op) {
        auto struct_meta = struct_var_to_headerref(op.args[0], op.struct_ref_info);
        auto dst_meta = var_to_headerref(op.dst_vars[0]);
        auto p4op = std::make_shared<P4IR::Operation>();
        p4op->alu_op = "modify_field";
        p4op->dst = dst_meta;
        p4op->args.emplace_back(struct_meta);
        act->ops.emplace_back(p4op);
    }

    void visitPhiNode(const HIR::Operation& op) {
        assert(false);
    }

    void visitSelect(const HIR::Operation& op) {
        assert(false);
    }

    void visitFuncCall(const HIR::Operation& op) {
        auto fn = remove_template(cxx_try_demangle(op.call_info.func_name));
        if (fn == "Packet::transport_length() const") {
            auto p4op = std::make_shared<P4IR::Operation>();
            auto dst_meta = var_to_headerref(op.dst_vars[0]);
            p4op->alu_op = "modify_field";
            p4op->dst = dst_meta;
            p4op->args.emplace_back(HeaderRef("ipv4", "tot_len"));
            act->ops.emplace_back(p4op);
        } else if (fn == "Packet::has_network_header() const") {
            auto p4op = std::make_shared<P4IR::Operation>();
            auto dst_meta = var_to_headerref(op.dst_vars[0]);
            p4op->alu_op = "modify_field";
            p4op->dst = dst_meta;
            p4op->args.emplace_back(HeaderRef("ipv4", "valid()"));
            act->ops.emplace_back(p4op);
        } else if (fn == "Element::checked_output_push(int, Packet*) const") {
            auto p4op = std::make_shared<P4IR::Operation>();
            p4op->alu_op = "modify_field";
            p4op->dst = HeaderRef(true, "output_port");
            p4op->args.emplace_back(var_to_headerref(op.args[1]));
            act->ops.emplace_back(p4op);
        } else if (fn == "Packet::kill()") {
            auto p4op = std::make_shared<P4IR::Operation>();
            p4op->alu_op = "modify_field";
            p4op->dst = HeaderRef(true, "should_drop");
            p4op->args.emplace_back(HeaderRef("1"));
            act->ops.emplace_back(p4op);
        } else if (fn == "IPFlowID::IPFlowID(Packet const*, bool)") {
            auto obj = op.args[0];
            assert(ctx->struct_mapping.find(obj) != ctx->struct_mapping.end());
            auto flattened = ctx->struct_mapping[obj];
            auto entries = flattened.get_flattened_metas();
            assert(entries.size() == 4);
            std::vector<HeaderRef> args;
            args = {HeaderRef("ipv4", "saddr")};
            act->ops.emplace_back(
                    std::make_shared<P4IR::Operation>(
                        HeaderRef(true, entries[0].var_name),
                        "modify_field",
                        args));
            args = {HeaderRef("ipv4", "daddr")};
            act->ops.emplace_back(
                    std::make_shared<P4IR::Operation>(
                        HeaderRef(true, entries[1].var_name),
                        "modify_field",
                        args));
            args = {HeaderRef("tcp", "source")};
            act->ops.emplace_back(
                    std::make_shared<P4IR::Operation>(
                        HeaderRef(true, entries[2].var_name),
                        "modify_field",
                        args));
            args = {HeaderRef("tcp", "dest")};
            act->ops.emplace_back(
                    std::make_shared<P4IR::Operation>(
                        HeaderRef(true, entries[3].var_name),
                        "modify_field",
                        args));
        } else {
            assert(false && "unknown function");
        }
    }

    void visitPktLoad(const HIR::Operation& op) {
        auto pkt_meta = HeaderRef(op.pkt_op_info.header, op.pkt_op_info.field);
        auto dst_meta = var_to_headerref(op.dst_vars[0]);
        auto p4op = std::make_shared<P4IR::Operation>();
        p4op->alu_op = "modify_field";
        p4op->dst = dst_meta;
        p4op->args.emplace_back(pkt_meta);
        act->ops.emplace_back(p4op);
    }

    void visitPktStore(const HIR::Operation& op) {
        auto pkt_meta = HeaderRef(op.pkt_op_info.header, op.pkt_op_info.field);
        auto val_meta = var_to_headerref(op.args[1]);
        auto p4op = std::make_shared<P4IR::Operation>();
        p4op->alu_op = "modify_field";
        p4op->dst = pkt_meta;
        p4op->args.emplace_back(val_meta);
        act->ops.emplace_back(p4op);
    }
};

std::shared_ptr<P4IR::Operation> hir_op_to_p4op(const OpTranslateCtx& ctx, const Operation& op) {
    auto p4op = std::make_shared<P4IR::Operation>();
    return p4op;
}

std::vector<std::shared_ptr<Action>> create_table_acts(HIR::Type* t) {
    return {};
}

struct StageCond {
    struct CondEntry {
        std::shared_ptr<Var> v;
        bool is_neg = false;
    };
    using AndList = std::vector<CondEntry>;
    std::vector<AndList> or_list;
};

void update_exec_cond(
        std::shared_ptr<BasicBlock> curr_bb,
        std::vector<StageCond::CondEntry> conds,
        std::unordered_map<std::shared_ptr<BasicBlock>, StageCond>& bb_conds) {
    auto& pre_cond = bb_conds[curr_bb];
    if (conds.size() > 0) {
        pre_cond.or_list.emplace_back(conds);
    }

    std::vector<StageCond::CondEntry> default_bb_cond = conds;
    for (auto& e : curr_bb->branches) {
        auto sz = conds.size();
        auto n_bb = e.next_bb.lock();
        assert(n_bb != nullptr);
        StageCond::CondEntry cond_entry;
        cond_entry.v = e.cond_var;
        assert(e.cond_var != nullptr);
        cond_entry.is_neg = false;
        conds.emplace_back(cond_entry);
        update_exec_cond(n_bb, conds, bb_conds);
        conds.resize(sz);

        StageCond::CondEntry neg_entry;
        neg_entry.v = e.cond_var;
        neg_entry.is_neg = true;
        default_bb_cond.emplace_back(neg_entry);
    }
    if (!curr_bb->is_return && !curr_bb->is_err) {
        auto n_bb = curr_bb->default_next_bb.lock();
        update_exec_cond(n_bb, default_bb_cond, bb_conds);
    }
}

std::string rev_cmp_op(const std::string& cmp_op) {
    if (cmp_op == "==") {
        return "!=";
    } else if (cmp_op == "!=") {
        return "==";
    } else if (cmp_op == "<=") {
        return ">";
    } else if (cmp_op == ">=") {
        return "<";
    } else if (cmp_op == "<") {
        return ">=";
    } else if (cmp_op == ">") {
        return "<=";
    } else {
        assert(false && "unknown cmp op");
    }
}

Stage::CondList::Entry cond_v_to_entry(const OpTranslateCtx& ctx, std::shared_ptr<Var> v, bool is_egress) {
    HeaderRef cond_v("0");
    if (ctx.meta_mapping.find(v) != ctx.meta_mapping.end()) {
        cond_v = HeaderRef(true, ctx.meta_mapping.find(v)->second);
    } else {
        assert(is_egress);
        assert(ctx.transferred_vars.find(v) != ctx.transferred_vars.end());
        cond_v = HeaderRef("transfer", ctx.transferred_vars.find(v)->second);
    }
    HeaderRef arg2("0");
    std::string cmp_op = "==";
    auto src_op = v->src_op.lock();
    if (src_op != nullptr) {
        switch (src_op->arith_info.u.icmp_t) {
        case IntCmpType::EQ:
            cmp_op = "==";
            break;
        case IntCmpType::NE:
            cmp_op = "!=";
            break;
        case IntCmpType::SLE:
        case IntCmpType::ULE:
            cmp_op = "<=";
            break;
        case IntCmpType::SLT:
        case IntCmpType::ULT:
            cmp_op = "<";
            break;
        }
        if (src_op->args[0]->type->type == HIR::Type::T::POINTER) {
            cmp_op = rev_cmp_op(cmp_op);
        }
    }

    return Stage::CondList::Entry{cond_v, arg2, cmp_op};
}

std::shared_ptr<Program> p4_program_from_function(
        std::shared_ptr<Element> ele,
        std::shared_ptr<HIR::Function> func,
        bool is_egress) {
    auto prog = std::make_shared<Program>();
    auto nop_act = std::make_shared<Action>();
    nop_act->name = "nop_bb";
    prog->actions.insert({nop_act->name, nop_act});
    // first a topological sort of all basic block

    split_bb_for_p4(*func);
    auto ctl_graph = control_graph_of_func(*func);
    assert(ctl_graph.IsAcyclic());
    auto topo_order = ctl_graph.TopologicalSort();

    OpTranslateCtx ctx;
    std::unordered_set<std::shared_ptr<Var>> used_globals;
    std::unordered_map<std::shared_ptr<Var>, std::shared_ptr<Stage>> table_stages;

    std::unordered_map<int, std::unordered_set<std::string>> available_meta_var;
    std::unordered_map<std::shared_ptr<Var>, std::string>& meta_mapping = ctx.meta_mapping;
    std::unordered_map<std::string, int>& meta_var_bw = ctx.meta_var_bw;

    std::unordered_map<std::shared_ptr<Var>, StructMetaMapping>& struct_mapping = ctx.struct_mapping;
    std::unordered_map<std::shared_ptr<Var>, std::string>& map_is_null = ctx.map_is_null;
    std::unordered_map<std::shared_ptr<Var>, StructMetaMapping>& global_result_mapping = ctx.global_result_mapping;

    // first allocate variable for each of the state opeartions
    for (int i = topo_order.size() - 1; i >= 0; i--) {
        auto& bb = ctl_graph.vertex_ref(topo_order[i]);
        for (auto& op : bb->ops) {
            if (op->type == HIR::Operation::T::FUNC_CALL) {
                auto fn = remove_template(cxx_try_demangle(op->call_info.func_name));
                if (str_begin_with(fn, "Vector::operator[]")) {
                    auto global_v = op->args[0];
                    assert(global_v->is_global);
                    assert(global_v->type->type == HIR::Type::T::VECTOR);
                    global_v->type->vector_info.element_type = op->dst_vars[0]->type->pointee_type;
                    used_globals.insert(global_v);
                } else if (str_begin_with(fn, "HashMap::findp")) {
                    auto global_v = op->args[0];
                    assert(global_v->is_global);
                    assert(global_v->type->type == HIR::Type::T::MAP);
                    used_globals.insert(global_v);
                }
            }
        }
    }

    for (auto& g : used_globals) {
        auto stage = std::make_shared<Stage>();
        stage->name = NameFactory::get()("table_stage");
        stage->type = Stage::T::TABLE;
        std::vector<std::shared_ptr<Action>> acts;
        if (g->type->type == HIR::Type::T::VECTOR) {
            auto meta = NameFactory::get()("vec_idx");
            meta_var_bw[meta] = 32;
            stage->table_info.keys = {meta};
            auto vt = g->type->vector_info.element_type;
            auto val_flattened = flatten_struct(vt, "vec_result");
            global_result_mapping[g] = val_flattened;

            auto act = std::make_shared<Action>();
            act->name = g->name + "_lkup";
            for (auto& e : val_flattened.get_flattened_metas()) {
                act->args.emplace_back(e.var_name);
                act->ops.emplace_back(
                    std::make_shared<P4IR::Operation>(
                        HeaderRef(true, e.var_name),
                        "modify_field",
                        std::vector<HeaderRef>{HeaderRef(false, e.var_name)}));
            }
            acts.emplace_back(act);
        } else if (g->type->type == HIR::Type::T::MAP) {
            auto kt = g->type->map_info.key_t;
            auto vt = g->type->map_info.val_t;
            StructMetaMapping flattened = flatten_struct(kt, "map_key");
            auto keys = flattened.get_flattened_metas();
            for (auto& k : keys) {
                stage->table_info.keys.emplace_back(HeaderRef(true, k.var_name));
            }
            auto val_flattened = flatten_struct(vt, "map_result");
            global_result_mapping[g] = val_flattened;
            auto is_null = NameFactory::get()("map_null");
            map_is_null[g] = is_null;
            meta_var_bw[is_null] = 1;

            auto act = std::make_shared<Action>();
            act->name = g->name + "_lkup";
            for (auto& e : val_flattened.get_flattened_metas()) {
                act->args.emplace_back(e.var_name);
                act->ops.emplace_back(
                    std::make_shared<P4IR::Operation>(
                        HeaderRef(true, e.var_name),
                        "modify_field",
                        std::vector<HeaderRef>{HeaderRef(false, e.var_name)}));
            }
            act->ops.emplace_back(
                std::make_shared<P4IR::Operation>(
                    HeaderRef(true, is_null),
                    "modify_field",
                    std::vector<HeaderRef>{HeaderRef("1")}));
            acts.emplace_back(act);
        } else {
            assert(false && "unknown global type");
        }
        for (auto& act : acts) {
            prog->actions.insert({act->name, act});
            stage->table_info.actions.emplace_back(act->name);
        }
        stage->act = nop_act->name;
        table_stages.insert({g, stage});
    }

    for (int i = topo_order.size() - 1; i >= 0; i--) {
        auto& bb = ctl_graph.vertex_ref(topo_order[i]);
        for (auto& op : bb->ops) {
            if (op->type == HIR::Operation::T::FUNC_CALL) {
                auto fn = remove_template(cxx_try_demangle(op->call_info.func_name));
                if (str_begin_with(fn, "Vector::operator[]")) {
                    auto dst = op->dst_vars[0];
                    assert(global_result_mapping.find(op->args[0]) != global_result_mapping.end());
                    struct_mapping[dst] = global_result_mapping[op->args[0]];
                } else if (str_begin_with(fn, "HashMap::findp")) {
                    auto dst = op->dst_vars[0];
                    assert(global_result_mapping.find(op->args[0]) != global_result_mapping.end());
                    struct_mapping[dst] = global_result_mapping[op->args[0]];
                }
            }
        }
    }

    std::unordered_map<std::shared_ptr<Var>, std::shared_ptr<BasicBlock>> last_used;
    std::unordered_map<std::shared_ptr<BasicBlock>, int> bb_topo_idx;
    for (int i = topo_order.size() - 1; i >= 0; i--) {
        auto& bb = ctl_graph.vertex_ref(topo_order[i]);
        bb_topo_idx[bb] = i;
    }

    for (int i = topo_order.size() - 1; i >= 0; i--) {
        auto& bb = ctl_graph.vertex_ref(topo_order[i]);
        for (auto& op : bb->ops) {
            for (auto& a : op->args) {
                if (!a->is_constant && !a->is_undef && !a->is_global && !a->is_param) {
                    last_used[a] = bb;
                }
            }
        }

        for (auto& e : bb->branches) {
            auto n_bb = e.next_bb.lock();
            assert(n_bb != nullptr);
            if (last_used.find(e.cond_var) != last_used.end()) {
                auto old_bb = last_used[e.cond_var];
                if (bb_topo_idx[old_bb] > bb_topo_idx[n_bb]) {
                    last_used[e.cond_var] = n_bb;
                }
            } else {
                last_used[e.cond_var] = n_bb;
            }
        }
        if (!bb->is_return && !bb->is_err) {
            for (auto& e : bb->branches) {
                auto n_bb = bb->default_next_bb.lock();
                assert(n_bb != nullptr);
                if (last_used.find(e.cond_var) != last_used.end()) {
                    auto old_bb = last_used[e.cond_var];
                    if (bb_topo_idx[old_bb] > bb_topo_idx[n_bb]) {
                        last_used[e.cond_var] = n_bb;
                    }
                } else {
                    last_used[e.cond_var] = n_bb;
                }
            }
        }
    }

    std::unordered_map<
        std::shared_ptr<BasicBlock>,
        std::vector<std::shared_ptr<Var>>> last_used_rev;
    for (auto& kv : last_used) {
        last_used_rev[kv.second].emplace_back(kv.first);
    }

    for (int i = topo_order.size() - 1; i >= 0; i--) {
        auto& bb = ctl_graph.vertex_ref(topo_order[i]);
        for (auto& op : bb->ops) {
            for (auto& d : op->dst_vars) {
                if (d->type->type == HIR::Type::T::INT) {
                    auto sz = d->type->bitwidth;
                    if (op->type == HIR::Operation::T::ARITH
                        && op->arith_info.t == ArithType::INT_CMP
                        && op->args[0]->type->type == HIR::Type::T::INT) {
                        sz = op->args[0]->type->bitwidth;
                    }
                    if (available_meta_var[sz].size() == 0) {
                        auto nv = NameFactory::get()("meta_v");
                        available_meta_var[sz].insert(nv);
                        assert(meta_var_bw.find(nv) == meta_var_bw.end());
                        meta_var_bw[nv] = sz;
                    }
                    auto fst = available_meta_var[sz].begin();
                    std::string var_name = *fst;
                    available_meta_var[sz].erase(var_name);
                    meta_mapping.insert({d, var_name});
                }
            }
        }
        auto lifetime_ended = last_used_rev[bb];
        for (auto& v : lifetime_ended) {
            if (v->type->type == HIR::Type::T::INT) {
                if (meta_mapping.find(v) != meta_mapping.end()) {
                    auto meta_var = meta_mapping[v];
                    auto sz = v->type->bitwidth;
                    auto& s = available_meta_var[sz];
                    assert(s.find(meta_var) == s.end());
                    s.insert(meta_var);
                } else {
                    assert(is_egress);
                }
            }
        }
    }

    std::unordered_set<std::shared_ptr<Var>> local_vars;
    for (auto& bb : func->bbs) {
        for (auto& op : bb->ops) {
            for (auto& d : op->dst_vars) {
                local_vars.insert(d);
            }
        }
    }
    for (auto& kv : last_used) {
        if (local_vars.find(kv.first) == local_vars.end()) {
            auto v = NameFactory::get()("from_prev");
            ctx.transferred_vars[kv.first] = v;
        }
    }

    // allocate meta for structs
    for (auto& bb : func->bbs) {
        for (auto& op : bb->ops) {
            if (op->type == HIR::Operation::T::ALLOCA) {
                auto struct_t = op->alloca_type;
                struct_mapping[op->dst_vars[0]] = flatten_struct(struct_t);
            }
        }
    }

    // compute conditions
    std::unordered_map<std::shared_ptr<BasicBlock>, StageCond> bb_conds;
    update_exec_cond(func->bbs[func->entry_bb_idx()], {}, bb_conds);

    std::unordered_map<
        std::shared_ptr<BasicBlock>,
        std::unordered_set<std::shared_ptr<BasicBlock>>> from;
    for (auto& bb : func->bbs) {
        for (auto& e : bb->branches) {
            auto n_bb = e.next_bb.lock();
            from[n_bb].insert(bb);
        }
        if (!bb->is_return && !bb->is_err) {
            auto n_bb = bb->default_next_bb.lock();
            from[n_bb].insert(bb);
        }
    }

    int delta = 0;
    do {
        delta = 0;
        for (auto& bb : func->bbs) {
            if (from[bb].size() == 1) {
                auto prev_bb = *from[bb].begin();
                if (from[prev_bb].size() == 1) {
                    from[bb].clear();
                    from[bb].insert(*from[prev_bb].begin());
                    delta++;
                }
            }
        }
    } while (delta > 0);

    // calcutate how many "from" do we need
    std::unordered_set<std::shared_ptr<BasicBlock>> from_bbs;
    for (auto& kv : from) {
        for (auto& bb : kv.second) {
            from_bbs.insert(bb);
        }
    }
    for (auto& bb : func->bbs) {
        if (from[bb].size() > 1) {
            from_bbs.insert(bb);
        }
    }
    for (auto& bb : from_bbs) {
        meta_var_bw["from_" + bb->name] = 1;
    }

    // create stages for each basic block, need to split vector and map lookup
    std::unordered_map<std::shared_ptr<BasicBlock>, std::string> bb_stage_mapping;
    std::shared_ptr<Stage> init_stage = nullptr;
    std::shared_ptr<Stage> prev_stage = nullptr;
    for (int i = topo_order.size() - 1; i >= 0; i--) {
        auto& bb = ctl_graph.vertex_ref(topo_order[i]);
        auto act = std::make_shared<Action>();
        act->name = bb->name;
        Op2P4Visitor visitor;
        visitor.is_egress = is_egress;
        visitor.act = act;
        visitor.ctx = &ctx;

        auto& prev_bbs = from[bb];
        Stage::CondList stage_pre_cond;
        stage_pre_cond.or_list.clear();
        if (prev_bbs.size() == 0) {
        } else if (prev_bbs.size() == 1) {
            auto prev_bb = *prev_bbs.begin();
            Stage::CondList::AndList stage_and_list;
            HeaderRef from_var(true, "from_" + prev_bb->name);
            Stage::CondList::Entry entry { from_var, HeaderRef("1"), "==" };
            stage_and_list.emplace_back(entry);
            stage_pre_cond.or_list = {stage_and_list};
        } else {
            for (auto& prev_bb : prev_bbs) {
                auto& prev_prev = from[prev_bb];
                if (prev_prev.size() > 0) {
                    HeaderRef from_var(true, "from_" + prev_bb->name);
                }
                for (auto& e : prev_bb->branches) {
                    auto n_bb = e.next_bb.lock();
                    if (n_bb == bb) {
                        auto v = e.cond_var;
                        auto cond_entry = cond_v_to_entry(ctx, v, is_egress);
                        Stage::CondList::AndList and_list;
                        and_list.emplace_back(cond_entry);
                        if (prev_prev.size() > 0) {
                            HeaderRef from_var(true, "from_" + prev_bb->name);
                            Stage::CondList::Entry from_e{from_var, HeaderRef("1"), "=="};
                            and_list.emplace_back(from_e);
                        }
                        stage_pre_cond.or_list.emplace_back(and_list);
                    }
                }
                if (!bb->is_return && !bb->is_err) {
                    auto n_bb = bb->default_next_bb.lock();
                    assert(n_bb != nullptr);
                    if (n_bb == bb) {
                        Stage::CondList::AndList and_list;
                        for (auto& e : prev_bb->branches) {
                            auto v = e.cond_var;
                            auto cond_entry = cond_v_to_entry(ctx, v, is_egress);
                            cond_entry.cmp_op = rev_cmp_op(cond_entry.cmp_op);
                            and_list.emplace_back(cond_entry);
                        }
                        if (prev_prev.size() > 0) {
                            HeaderRef from_var(true, "from_" + prev_bb->name);
                            Stage::CondList::Entry from_e{from_var, HeaderRef("1"), "=="};
                            and_list.emplace_back(from_e);
                        }
                        stage_pre_cond.or_list.emplace_back(and_list);
                    }
                }
            }
        }

        for (auto& op : bb->ops) {
            if (op->type == HIR::Operation::T::FUNC_CALL) {
                auto fn = remove_template(cxx_try_demangle(op->call_info.func_name));
                if (str_begin_with(fn, "Vector::operator[]")
                    || str_begin_with(fn, "HashMap::findp")) {
                    assert(table_stages.find(op->args[0]) != table_stages.end());
                    auto stage = std::make_shared<Stage>(*table_stages[op->args[0]]);
                    stage->conds = stage_pre_cond;
                    if (prev_stage != nullptr) {
                        prev_stage->default_next_stage = stage->name;
                    }
                    prev_stage = stage;
                    prog->add_stage(stage);
                    if (init_stage == nullptr) {
                        init_stage = stage;
                    }
                    continue;
                }
            }
            visitor.visit(*op);
        }

        if (from_bbs.find(bb) != from_bbs.end()) {
            act->ops.emplace_back(
                std::make_shared<P4IR::Operation>(
                    HeaderRef(true, "from_" + bb->name),
                    "modify_field",
                    std::vector<HeaderRef>{HeaderRef("1")}));
        }
        if (act->ops.size() == 0) {
            act = nop_act;
        }
        auto stage = std::make_shared<Stage>();
        stage->conds = stage_pre_cond;
        stage->name = "stage_" + bb->name;
        stage->type = Stage::T::DIRECT_ACTION;
        if (prev_stage != nullptr) {
            prev_stage->default_next_stage = stage->name;
        }
        stage->act = act->name;
        if (act != nop_act) {
            prog->add_action(act);
        }
        prev_stage = stage;
        if (init_stage == nullptr) {
            init_stage = stage;
        }
        prog->add_stage(stage);
    }
    assert(init_stage != nullptr);
    prog->init_stage = init_stage->name;

    std::vector<std::string> hdrs;
    std::unordered_map<std::string, size_t> vmap;
    for (auto& kv : CommonHdr::default_layout.headers) {
        vmap[kv.first] = hdrs.size();
        hdrs.push_back(kv.first);
    }

    AdjacencyList<PktParser::ParsingEdge> edges(hdrs.size());
    edges.set_edge(vmap["ether"], vmap["ipv4"], PktParser::ParsingEdge{"ether", "ethertype", 0x0800});
    edges.set_edge(vmap["ipv4"], vmap["udp"], PktParser::ParsingEdge{"ipv4", "protocol", 0x11});
    edges.set_edge(vmap["ipv4"], vmap["tcp"], PktParser::ParsingEdge{"ipv4", "protocol", 6});
    Graph<std::string, PktParser::ParsingEdge, AdjacencyList<PktParser::ParsingEdge>>
        parse_graph(std::move(hdrs), std::move(edges));

    auto parser = std::make_shared<PktParser>(CommonHdr::default_layout, parse_graph);
    parser->layout = CommonHdr::default_layout;
    prog->parser = parser;
    prog->meta = std::make_shared<Metadata>();
    prog->meta->fields = {
        {"__always_1", 1},
        {"should_drop", 1},
        {"output_port", 1},
    };
    for (auto& kv : meta_var_bw) {
        prog->meta->fields.insert({kv.first, kv.second});
    }
    int num_stage;

    return prog;
}
}
