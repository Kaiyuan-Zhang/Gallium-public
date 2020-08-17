#include <functional>
#include <queue>
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
    result.ingress_prog = p4_program_from_function_v2(ele, partition_result.pre, false);
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

std::vector<StructMetaMapping::Entry> StructMetaMapping::get_flattened_metas() const {
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

StructMetaMapping::Entry StructMetaMapping::struct_get(const std::vector<int>& indices) const {
    if (indices.size() == 0) {
        assert(is_unit());
        return unit;
    } else {
        assert(!is_unit());
        auto idx = indices[0];
        assert(0 <= idx && idx < fields.size());
        auto& f = fields[idx];
        return f.struct_get(std::vector<int>(indices.cbegin() + 1, indices.end()));
    }
}

StructMetaMapping flatten_struct(HIR::Type* t, const std::string& name_prefix="meta_sf") {
    StructMetaMapping mapping;
    if (t->type == HIR::Type::T::ARRAY) {
        auto et = t->array_info.element_type;
        for (int i = 0; i < t->array_info.num_element; i++) {
            auto etm = flatten_struct(et);
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
                return HeaderRef::Meta(meta);
            } else {
                assert(ctx->transferred_vars.find(v) != ctx->transferred_vars.end());
                auto meta = ctx->transferred_vars[v];
                return HeaderRef("transfer", meta);
            }
        } else {
            assert(ctx->meta_mapping.find(v) != ctx->meta_mapping.end());
            auto meta = ctx->meta_mapping[v];
            return HeaderRef::Meta(meta);
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
            return HeaderRef::Meta(meta);
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
                p4op->args = {HeaderRef::Meta(ctx->map_is_null[map_op->args[0]])};
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
            p4op->args.emplace_back(HeaderRef(std::string("ipv4"), "valid()"));
            act->ops.emplace_back(p4op);
        } else if (fn == "Element::checked_output_push(int, Packet*) const") {
            auto p4op = std::make_shared<P4IR::Operation>();
            p4op->alu_op = "modify_field";
            p4op->dst = HeaderRef::Meta("output_port");
            p4op->args.emplace_back(var_to_headerref(op.args[1]));
            act->ops.emplace_back(p4op);
        } else if (fn == "Packet::kill()") {
            auto p4op = std::make_shared<P4IR::Operation>();
            p4op->alu_op = "modify_field";
            p4op->dst = HeaderRef::Meta("should_drop");
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
                        HeaderRef::Meta(entries[0].var_name),
                        "modify_field",
                        args));
            args = {HeaderRef("ipv4", "daddr")};
            act->ops.emplace_back(
                    std::make_shared<P4IR::Operation>(
                        HeaderRef::Meta(entries[1].var_name),
                        "modify_field",
                        args));
            args = {HeaderRef("tcp", "source")};
            act->ops.emplace_back(
                    std::make_shared<P4IR::Operation>(
                        HeaderRef::Meta(entries[2].var_name),
                        "modify_field",
                        args));
            args = {HeaderRef("tcp", "dest")};
            act->ops.emplace_back(
                    std::make_shared<P4IR::Operation>(
                        HeaderRef::Meta(entries[3].var_name),
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

class Op2P4VisitorV2 : public OperationConstVisitor<Op2P4VisitorV2> {
public:
    std::shared_ptr<Action> act;
    TranslateCtx* ctx;

    HeaderRef var_to_headerref(std::shared_ptr<Var> v) {
        if (v->is_constant) {
            return HeaderRef(std::to_string(v->constant));
        }
        if (v->is_constant_name) {
            return HeaderRef(v->name);
        }
        if (ctx->is_egress) {
            if (ctx->meta_mapping.find(v.get()) != ctx->meta_mapping.end()) {
                auto meta = ctx->meta_mapping[v.get()];
                return HeaderRef::Meta(meta);
            } else {
                assert(ctx->transferred_vars.find(v.get()) != ctx->transferred_vars.end());
                auto meta = ctx->transferred_vars[v.get()];
                return HeaderRef("transfer", meta);
            }
        } else {
            assert(ctx->meta_mapping.find(v.get()) != ctx->meta_mapping.end());
            auto meta = ctx->meta_mapping[v.get()];
            return HeaderRef::Meta(meta);
        }
    }

    HeaderRef struct_var_to_headerref(std::shared_ptr<Var> v, const std::vector<int>& offsets) {
        if (ctx->alloca_meta_mapping.find(v.get()) != ctx->alloca_meta_mapping.end()) {
            auto s_info = ctx->alloca_meta_mapping[v.get()];
            for (auto& o : offsets) {
                assert(!s_info.is_unit());
                s_info = s_info.fields[o];
            }
            assert(s_info.is_unit());
            auto meta = s_info.unit.var_name;
            return HeaderRef::Meta(meta);
        } else {
            assert(ctx->is_egress);
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
            assert(op.args[0]->type->type != HIR::Type::T::POINTER);
            p4op->alu_op = "subtract";
            auto it = ctx->meta_mapping.find(op.dst_vars[0].get());
            assert(it != ctx->meta_mapping.end());
            ctx->meta_bw[it->second] = op.args[0]->type->bitwidth;
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
            p4op->args.emplace_back(HeaderRef(std::string("ipv4"), "valid()"));
            act->ops.emplace_back(p4op);
        } else if (fn == "Element::checked_output_push(int, Packet*) const") {
            auto p4op = std::make_shared<P4IR::Operation>();
            p4op->alu_op = "modify_field";
            p4op->dst = HeaderRef::Meta("output_port");
            p4op->args.emplace_back(var_to_headerref(op.args[1]));
            act->ops.emplace_back(p4op);
        } else if (fn == "Packet::kill()") {
            auto p4op = std::make_shared<P4IR::Operation>();
            p4op->alu_op = "modify_field";
            p4op->dst = HeaderRef::Meta("should_drop");
            p4op->args.emplace_back(HeaderRef("1"));
            act->ops.emplace_back(p4op);
        } else if (fn == "IPFlowID::IPFlowID(Packet const*, bool)") {
            auto obj = op.args[0];
            assert(ctx->alloca_meta_mapping.find(obj.get()) != ctx->alloca_meta_mapping.end());
            auto flattened = ctx->alloca_meta_mapping[obj.get()];
            auto entries = flattened.get_flattened_metas();
            assert(entries.size() == 4);
            std::vector<HeaderRef> args;
            args = {HeaderRef("ipv4", "saddr")};
            act->ops.emplace_back(
                    std::make_shared<P4IR::Operation>(
                        HeaderRef::Meta(entries[0].var_name),
                        "modify_field",
                        args));
            args = {HeaderRef("ipv4", "daddr")};
            act->ops.emplace_back(
                    std::make_shared<P4IR::Operation>(
                        HeaderRef::Meta(entries[1].var_name),
                        "modify_field",
                        args));
            args = {HeaderRef("tcp", "source")};
            act->ops.emplace_back(
                    std::make_shared<P4IR::Operation>(
                        HeaderRef::Meta(entries[2].var_name),
                        "modify_field",
                        args));
            args = {HeaderRef("tcp", "dest")};
            act->ops.emplace_back(
                    std::make_shared<P4IR::Operation>(
                        HeaderRef::Meta(entries[3].var_name),
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
    if (v->is_constant_name) {
        assert(false);
        return Stage::CondList::Entry{v->name, HeaderRef(""), ""};
    }
    if (ctx.meta_mapping.find(v) != ctx.meta_mapping.end()) {
        cond_v = HeaderRef::Meta(ctx.meta_mapping.find(v)->second);
    } else {
        assert(is_egress);
        assert(ctx.transferred_vars.find(v) != ctx.transferred_vars.end());
        cond_v = HeaderRef("transfer", ctx.transferred_vars.find(v)->second);
    }
    HeaderRef arg2("0");
    std::string cmp_op = "==";
    auto src_op = v->src_op.lock();
    if (src_op != nullptr) {
        assert(src_op->type == HIR::Operation::T::ARITH);
        if (src_op->arith_info.t == HIR::ArithType::INT_ARITH) {
            if (src_op->arith_info.u.iarith_t == HIR::IntArithType::INT_NOT) {
                return Stage::CondList::Entry{"!" + v->name, HeaderRef(""), ""};
            } else {
                assert(false && "unknown cond op");
            }
        } else {
            assert(src_op->arith_info.t == HIR::ArithType::INT_CMP);
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
    }

    return Stage::CondList::Entry{cond_v, arg2, cmp_op};
}

Stage::CondList::Entry cond_v_to_entry(const TranslateCtx& ctx, std::shared_ptr<Var> v, bool is_egress) {
    HeaderRef cond_v("0");
    if (v->is_constant_name) {
        return Stage::CondList::Entry{v->name, HeaderRef(""), ""};
    }
    if (ctx.meta_mapping.find(v.get()) != ctx.meta_mapping.end()) {
        cond_v = HeaderRef::Meta(ctx.meta_mapping.find(v.get())->second);
    } else {
        assert(is_egress);
        assert(ctx.transferred_vars.find(v.get()) != ctx.transferred_vars.end());
        cond_v = HeaderRef("transfer", ctx.transferred_vars.find(v.get())->second);
    }
    HeaderRef arg2("0");
    std::string cmp_op = "==";
    auto src_op = v->src_op.lock();
    if (src_op != nullptr) {
        if (src_op->type == HIR::Operation::T::ARITH) {
            if (src_op->arith_info.t == HIR::ArithType::INT_ARITH) {
                if (src_op->arith_info.u.iarith_t == HIR::IntArithType::INT_NOT) {
                    return Stage::CondList::Entry{"!" + v->name, HeaderRef(""), ""};
                } else {
                    assert(false && "unknown cond op");
                }
            } else {
                assert(src_op->arith_info.t == HIR::ArithType::INT_CMP);
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
        } else if (src_op->type == HIR::Operation::T::FUNC_CALL) {
            auto fn = remove_template(cxx_try_demangle(src_op->call_info.func_name));
            if (str_begin_with(fn, "HashMap::findp")) {
                auto it = ctx.meta_mapping.find(v.get());
                assert(it != ctx.meta_mapping.end());
                return Stage::CondList::Entry{HeaderRef::Meta(it->second), HeaderRef("1"), "=="};
            } else {
                assert(false && "cond_v : unknown function");
            }
        } else {
            assert(false && "unknown src_op type");
        }
    }

    return Stage::CondList::Entry{cond_v, arg2, cmp_op};
}

void p4_function_update_uses(HIRP4Function& ctx) {
    for (auto& bb : ctx.bbs) {
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

    for (auto& bb : ctx.bbs) {
        for (auto& op : bb->ops) {
            op->update_uses();
        }
        bb->update_uses();
    }
}

std::shared_ptr<HIRP4Function> pipeline_from_function(
        std::shared_ptr<Element> ele,
        std::shared_ptr<HIR::Function> func) {
    auto result = std::make_shared<HIRP4Function>();
    split_bb_for_p4(*func);
    auto ctl_graph = control_graph_of_func(*func);
    assert(ctl_graph.IsAcyclic());
    auto topo_order = ctl_graph.TopologicalSort();
    for (int i = topo_order.size() - 1; i >= 0; i--) {
        auto& bb = ctl_graph.vertex_ref(topo_order[i]);
        result->bbs.push_back(bb);
    }
    result->arg_types = func->arg_types;
    result->args = func->args;
    p4_function_update_uses(*result);
    return result;
}

void p4_remove_ops(HIRP4Function& ctx, const std::unordered_set<HIR::Operation *>& to_remove) {
    auto bb_it = ctx.bbs.begin();
    auto first_bb = *ctx.bbs.begin();
    while (bb_it != ctx.bbs.end()) {
        auto& bb = *bb_it;
        auto& ops = bb->ops;
        auto it = ops.begin();
        while (it != ops.end()) {
            auto& op = *it;
            if (to_remove.find(op.get()) != to_remove.end()) {
                it = ops.erase(it);
            } else {
                ++it;
            }
        }
        ++bb_it;
    }
}

/* replace map and vector lookup result with an alloca */
void p4_replace_table_result(HIRP4Function& func, TranslateCtx& ctx) {
    std::vector<std::shared_ptr<HIR::Operation>> new_allocas;
    std::unordered_set<HIR::Operation *> to_remove;
    auto bb_it = func.bbs.begin();
    auto first_bb = *func.bbs.begin();
    while (bb_it != func.bbs.end()) {
        auto& bb = *bb_it;
        auto& ops = bb->ops;
        auto it = ops.begin();
        while (it != ops.end()) {
            auto& op = *it;
            assert(op->type != HIR::Operation::T::ALLOCA || bb == first_bb);
            if (op->type == HIR::Operation::T::FUNC_CALL) {
                auto fn = remove_template(cxx_try_demangle(op->call_info.func_name));
                if (str_begin_with(fn, "HashMap::findp") ||
                    str_begin_with(fn, "Vector::operator[]")) {
                    assert(op->dst_vars.size() == 1);
                    auto val_ptr = op->dst_vars[0];
                    // get the value type
                    auto vt = val_ptr->type;
                    // find compare
                    std::vector<HIR::Operation *> cmp_ops;
                    for (auto& u : val_ptr->uses) {
                        assert(u.type == HIR::Var::Use::T::OP);
                        auto& using_op = u.u.op_ptr;
                        assert(using_op != nullptr);
                        assert(using_op->type == HIR::Operation::T::ARITH ||
                               using_op->type == HIR::Operation::T::STRUCT_GET ||
                               using_op->type == HIR::Operation::T::LOAD);
                        if (using_op->type == HIR::Operation::T::ARITH) {
                            assert(using_op->arith_info.t == HIR::ArithType::INT_CMP);
                            auto cmp_type = using_op->arith_info.u.icmp_t;
                            assert(cmp_type == HIR::IntCmpType::EQ ||
                                   cmp_type == HIR::IntCmpType::NE);
                            assert(using_op->args[0] == val_ptr);
                            assert(using_op->args[1]->is_constant &&
                                   using_op->args[1]->constant == 0);
                            cmp_ops.emplace_back(using_op);
                        }
                    }
                    if (str_begin_with(fn, "Vector::operator[]")) {
                        assert(cmp_ops.size() == 0);
                    }
                    // create var for found / not_found
                    auto map_obj = op->args[0];
                    std::shared_ptr<HIR::Var> map_hit_var = nullptr;
                    if (ctx.map_hit_var.find(map_obj.get()) == ctx.map_hit_var.end()) {
                        map_hit_var = std::make_shared<HIR::Var>();
                        ctx.map_hit_var[map_obj.get()] = map_hit_var;
                        map_hit_var->type = func.m->get_int_type(1).get();
                        map_hit_var->name = NameFactory::get()("map_hit");
                    } else {
                        map_hit_var = ctx.map_hit_var[map_obj.get()];
                    }
                    if (cmp_ops.size() > 0) {
                        assert(cmp_ops[0]->dst_vars[0]->type->type == HIR::Type::T::INT);
                        assert(cmp_ops[0]->dst_vars[0]->type->bitwidth == 1);
                        for (auto& cmp_op : cmp_ops) {
                            auto cmp_type = cmp_op->arith_info.u.icmp_t;
                            assert(cmp_type == HIR::IntCmpType::EQ ||
                                cmp_type == HIR::IntCmpType::NE);
                            if (cmp_type == HIR::IntCmpType::EQ) {
                                // EQ
                                auto old_var = cmp_op->dst_vars[0];
                                for (auto& u : old_var->uses) {
                                    if (u.type == Var::Use::T::BB_COND) {
                                        auto using_bb = u.u.bb_ptr;
                                        for (auto& branch_entry : using_bb->branches) {
                                            if (branch_entry.cond_var == old_var) {
                                                branch_entry.cond_var = map_hit_var;
                                            }
                                        }
                                    } else if (u.type == Var::Use::T::OP) {
                                        auto using_op = u.u.op_ptr;
                                        for (auto& a : using_op->args) {
                                            if (a == old_var) {
                                                a = map_hit_var;
                                            }
                                        }
                                    } else {
                                        assert(false && "unknown use type");
                                    }
                                }
                                to_remove.emplace(cmp_op);
                            } else {
                                // NE
                                // change this to an not
                                cmp_op->arith_info.t = HIR::ArithType::INT_ARITH;
                                cmp_op->arith_info.u.iarith_t = HIR::IntArithType::INT_NOT;
                                cmp_op->args.clear();
                                cmp_op->args.emplace_back(map_hit_var);
                                cmp_op->args.emplace_back(nullptr);
                                assert(false);
                            }
                        }
                    }
                    // create alloca
                    auto alloca = std::make_shared<HIR::Operation>();
                    alloca->type = HIR::Operation::T::ALLOCA;
                    assert(vt->type == HIR::Type::T::POINTER);
                    alloca->alloca_type = vt->pointee_type;
                    alloca->dst_vars = {val_ptr};
                    val_ptr->src_op = alloca;
                    new_allocas.emplace_back(alloca);
                    // put the val pointer from dst_vars to args
                    assert(op->args.size() == 2);
                    op->args.emplace_back(val_ptr);
                    op->dst_vars.clear();
                    if (map_hit_var != nullptr) {
                        op->dst_vars.emplace_back(map_hit_var);
                        map_hit_var->src_op = op;
                    }
                }
            }
            ++it;
        }
        ++bb_it;
    }
    for (auto& alloca : new_allocas) {
        first_bb->ops.insert(first_bb->ops.begin(), alloca);
        assert(alloca->dst_vars[0]->src_op.lock() == alloca);
    }
    p4_remove_ops(func, to_remove);
    p4_function_update_uses(func);
}

void p4_create_meta_mapping(HIRP4Function& func, TranslateCtx& ctx) {
    std::unordered_map<HIR::Var *, std::string> meta_mapping;
    std::vector<std::vector<std::unordered_set<HIR::Var *>>> live_vars;
    std::unordered_map<HIR::BasicBlock *, int> bb_idx_map;
    std::unordered_map<HIR::BasicBlock *, std::unordered_set<int>> rev_ctl_map;
    struct QueueEleT {
        std::shared_ptr<HIR::BasicBlock> bb;
        std::unordered_set<HIR::Var *> live_vars;
    };
    std::queue<QueueEleT> q;

    // create mapping for map hit
    std::unordered_set<HIR::Var *> map_hit_vars;
    for (int i = 0; i < func.bbs.size(); i++) {
        auto& bb = func.bbs[i];
        for (auto& op : bb->ops) {
            if (op->type != HIR::Operation::T::FUNC_CALL) {
                continue;
            }
            auto fn = remove_template(cxx_try_demangle(op->call_info.func_name));
            if (str_begin_with(fn, "HashMap::findp")) {
                auto map_obj = op->args[0];
                if (ctx.map_hit_var.find(map_obj.get()) != ctx.map_hit_var.end()) {
                    auto map_hit_var = ctx.map_hit_var[map_obj.get()];
                    map_hit_vars.emplace(map_hit_var.get());
                    if (ctx.meta_mapping.find(map_hit_var.get()) == ctx.meta_mapping.end()) {
                        auto var_name = NameFactory::get()("meta_map_hit");
                        ctx.meta_mapping[map_hit_var.get()] = var_name;
                        ctx.meta_bw[var_name] = 1;
                    }
                }
            }
        }
    }

    for (int i = 0; i < func.bbs.size(); i++) {
        auto& bb = func.bbs[i];
        std::vector<std::unordered_set<HIR::Var *>> bb_live_vars(
                bb->ops.size(),
                std::unordered_set<HIR::Var *>({}));
        live_vars.emplace_back(bb_live_vars);
        assert(bb_idx_map.find(bb.get()) == bb_idx_map.end());
        bb_idx_map[bb.get()] = i;
        if (bb->is_err || bb->is_return) {
            QueueEleT init_e;
            init_e.bb = bb;
            init_e.live_vars = {};
            q.push(init_e);
            continue;
        }
        for (auto& n : bb->branches) {
            auto next_bb = n.next_bb.lock();
            assert(next_bb != nullptr);
            rev_ctl_map[next_bb.get()].emplace(i);
        }
        auto default_next = bb->default_next_bb.lock();
        assert(default_next != nullptr);
        rev_ctl_map[default_next.get()].emplace(i);
    }
    while (!q.empty()) {
        auto e = q.front();
        q.pop();
        assert(bb_idx_map.find(e.bb.get()) != bb_idx_map.end());
        auto bb_idx = bb_idx_map[e.bb.get()];
        auto& bb_live_vars = live_vars[bb_idx];
        std::unordered_set<HIR::Var *> acc = e.live_vars;
        for (int i = e.bb->ops.size() - 1; i >= 0; i--) {
            auto& op = e.bb->ops[i];
            auto& op_live_vars = bb_live_vars[i];
            op_live_vars.insert(acc.begin(), acc.end());
            // add dst_vars to live
            for (auto& v : op->dst_vars) {
                acc.erase(v.get());
            }
            for (auto& a : op->args) {
                if (!a->is_constant && !a->is_constant_name && !a->is_global && !a->is_param) {
                    acc.emplace(a.get());
                }
            }
        }
        if (rev_ctl_map.find(e.bb.get()) != rev_ctl_map.end()) {
            auto& prev_bbs = rev_ctl_map[e.bb.get()];
            for (auto& prev_idx : prev_bbs) {
                auto prev_bb = func.bbs[prev_idx];
                QueueEleT e;
                e.bb = prev_bb;
                e.live_vars = acc;
                // add condition variables
                for (auto& branch_entry : prev_bb->branches) {
                    assert(branch_entry.cond_var != nullptr);
                    assert(branch_entry.is_conditional);
                    e.live_vars.emplace(branch_entry.cond_var.get());
                }
                q.push(e);
            }
        }
    }
    std::unordered_map<int /* bitwidth */, std::unordered_set<std::string>> available_meta_vars;
    // find all alloca, and assign meta field
    for (auto& bb : func.bbs) {
        for (auto& op : bb->ops) {
            if (op->type == HIR::Operation::T::ALLOCA) {
                auto flattened = flatten_struct(op->alloca_type);
                auto fields = flattened.get_flattened_metas();
                auto& dst = op->dst_vars[0];
                assert(ctx.alloca_meta_mapping.find(dst.get()) == ctx.alloca_meta_mapping.end());
                ctx.alloca_meta_mapping[dst.get()] = flattened;
            }
        }
    }
    for (auto& bb_live_vars : live_vars) {
        for (auto& op_live_vars : bb_live_vars) {
            auto it = op_live_vars.begin();
            while (it != op_live_vars.end()) {
                if ((*it)->is_constant_name
                    || map_hit_vars.find(*it) != map_hit_vars.end()){
                    it = op_live_vars.erase(it);
                } else {
                    it++;
                }
            }
        }
    }
    for (int bb_idx = 0; bb_idx < func.bbs.size(); bb_idx++) {
        auto& bb = func.bbs[bb_idx];
        auto& bb_live_vars = live_vars[bb_idx];
        for (int op_idx = 0; op_idx < bb->ops.size(); op_idx++) {
            auto& op_live_vars = bb_live_vars[op_idx];
            std::vector<std::pair<int, std::string>> used_meta;
            for (auto& v : op_live_vars) {
                if (v->type->type == HIR::Type::T::INT) {
                    auto bw = v->type->bitwidth;
                    if (ctx.meta_mapping.find(v) != ctx.meta_mapping.end()) {
                        auto meta_var_name = ctx.meta_mapping[v];
                        assert(available_meta_vars[bw].find(meta_var_name) != available_meta_vars[bw].end());
                        available_meta_vars[bw].erase(meta_var_name);
                        used_meta.emplace_back(std::pair<int, std::string>{bw, meta_var_name});
                    }
                }
            }
            for (auto& v : op_live_vars) {
                if (v->type->type == HIR::Type::T::INT) {
                    auto bw = v->type->bitwidth;
                    if (ctx.meta_mapping.find(v) != ctx.meta_mapping.end()) {
                        // do nothing this time
                    } else {
                        if (available_meta_vars[bw].size() == 0) {
                            std::string name_prefix = "meta_bv" + std::to_string(bw);
                            auto var_name = NameFactory::get()(name_prefix);
                            available_meta_vars[bw].emplace(var_name);
                            assert(ctx.meta_bw.find(var_name) == ctx.meta_bw.end());
                            ctx.meta_bw[var_name] = bw;
                        }
                        auto it = available_meta_vars[bw].begin();
                        std::string meta_var_name = *it;
                        available_meta_vars[bw].erase(it);
                        ctx.meta_mapping[v] = meta_var_name;
                        used_meta.emplace_back(std::pair<int, std::string>{bw, meta_var_name});
                    }
                } else {
                    assert(v->type->type == HIR::Type::T::POINTER);
                    auto src_op = v->src_op.lock();
                    assert(src_op != nullptr);
                    assert(src_op->type == HIR::Operation::T::ALLOCA);
                }
            }
            for (auto& p : used_meta) {
                int bw = p.first;
                auto& meta_var_name = p.second;
                assert(available_meta_vars[bw].find(meta_var_name) == available_meta_vars[bw].end());
                available_meta_vars[bw].emplace(meta_var_name);
            }
        }
    }
}

/* propagate constants such as valid(ipv4) */
void p4_const_propagation(HIRP4Function& ctx) {
    std::unordered_map<std::string, std::shared_ptr<HIR::Var>> header_valid_map;
    for (auto& bb : ctx.bbs) {
        auto& ops = bb->ops;
        auto it = ops.begin();
        while (it != ops.end()) {
            auto& op = *it;
            if (op->type == HIR::Operation::T::FUNC_CALL) {
                auto fn = remove_template(cxx_try_demangle(op->call_info.func_name));
                if (fn == "Packet::has_network_header() const") {
                    std::string header_name = "ipv4";
                    std::shared_ptr<HIR::Var> v = nullptr;
                    if (header_valid_map.find(header_name) != header_valid_map.end()) {
                        v = header_valid_map[header_name];
                    } else {
                        v = std::make_shared<HIR::Var>();
                        v->is_constant_name = true;
                        v->name = "valid(" + header_name + ")";
                        header_valid_map[header_name] = v;
                    }
                    assert(op->dst_vars.size() == 1);
                    auto old_dst = op->dst_vars[0];
                    for (auto& u : old_dst->uses) {
                        assert(u.type == HIR::Var::Use::T::BB_COND);
                        auto& bb_ptr = u.u.bb_ptr;
                        assert(bb_ptr->branches.size() > 0);
                        for (int i = 0; i < bb_ptr->branches.size(); i++) {
                            auto& be = bb_ptr->branches[i];
                            assert(be.is_conditional);
                            be.cond_var = v;
                        }
                    }
                    it = ops.erase(it);
                    continue;
                }
            }
            ++it;
        }
    }
    p4_function_update_uses(ctx);
}

void p4_prog_default_init(Program& prog) {
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
    prog.parser = parser;
    prog.meta = std::make_shared<Metadata>();
    prog.meta->fields = {
        {"__always_1", 1},
        {"should_drop", 1},
        {"output_port", 1},
    };
}

void p4_create_table_stages(
        Program& prog,
        std::shared_ptr<Action> nop_act,
        HIRP4Function& func,
        TranslateCtx& ctx,
        std::unordered_map<std::shared_ptr<Var>, std::shared_ptr<Stage>>& table_stages) {
    std::unordered_set<std::shared_ptr<Var>> used_globals;
    std::unordered_map<Var *, Var *> val_ptr_map;
    for (auto& bb : func.bbs) {
        for (auto& op : bb->ops) {
            if (op->type == HIR::Operation::T::FUNC_CALL) {
                auto fn = remove_template(cxx_try_demangle(op->call_info.func_name));
                if (str_begin_with(fn, "Vector::operator[]")) {
                    auto global_v = op->args[0];
                    assert(global_v->is_global);
                    assert(global_v->type->type == HIR::Type::T::VECTOR);
                    assert(used_globals.find(global_v) == used_globals.end());
                    global_v->type->vector_info.element_type = op->dst_vars[0]->type->pointee_type;
                    used_globals.insert(global_v);
                    val_ptr_map[global_v.get()] = op->args[2].get();
                } else if (str_begin_with(fn, "HashMap::findp")) {
                    auto global_v = op->args[0];
                    assert(global_v->is_global);
                    assert(global_v->type->type == HIR::Type::T::MAP);
                    assert(used_globals.find(global_v) == used_globals.end());
                    used_globals.insert(global_v);
                    val_ptr_map[global_v.get()] = op->args[2].get();
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
            ctx.meta_bw[meta] = 32;
            stage->table_info.keys = {HeaderRef::Meta(meta)};
            const auto& val_ptr = val_ptr_map[g.get()];
            assert(ctx.alloca_meta_mapping.find(val_ptr) != ctx.alloca_meta_mapping.end());
            auto val_flattened = ctx.alloca_meta_mapping[val_ptr];

            auto act = std::make_shared<Action>();
            act->name = g->name + "_lkup";
            for (auto& e : val_flattened.get_flattened_metas()) {
                act->args.emplace_back(e.var_name);
                act->ops.emplace_back(
                    std::make_shared<P4IR::Operation>(
                        HeaderRef::Meta(e.var_name),
                        "modify_field",
                        std::vector<HeaderRef>{HeaderRef::Arg(e.var_name)}));
            }
            acts.emplace_back(act);
        } else if (g->type->type == HIR::Type::T::MAP) {
            auto kt = g->type->map_info.key_t;
            auto vt = g->type->map_info.val_t;
            StructMetaMapping flattened = flatten_struct(kt, "map_key");
            auto keys = flattened.get_flattened_metas();
            for (auto& k : keys) {
                ctx.meta_bw[k.var_name] = k.bw;
                stage->table_info.keys.emplace_back(HeaderRef::Meta(k.var_name));
            }
            const auto& val_ptr = val_ptr_map[g.get()];
            assert(ctx.alloca_meta_mapping.find(val_ptr) != ctx.alloca_meta_mapping.end());
            auto val_flattened = ctx.alloca_meta_mapping[val_ptr];
            auto map_hit_it = ctx.map_hit_var.find(g.get());
            assert(map_hit_it != ctx.map_hit_var.end());
            auto map_hit_var = map_hit_it->second;
            auto meta_it = ctx.meta_mapping.find(map_hit_var.get());
            assert(meta_it != ctx.meta_mapping.end());

            auto act = std::make_shared<Action>();
            act->name = g->name + "_lkup";
            for (auto& e : val_flattened.get_flattened_metas()) {
                act->args.emplace_back(e.var_name);
                act->ops.emplace_back(
                    std::make_shared<P4IR::Operation>(
                        HeaderRef::Meta(e.var_name),
                        "modify_field",
                        std::vector<HeaderRef>{HeaderRef::Arg(e.var_name)}));
            }
            act->ops.emplace_back(
                std::make_shared<P4IR::Operation>(
                    HeaderRef::Meta(meta_it->second),
                    "modify_field",
                    std::vector<HeaderRef>{HeaderRef("1")}));
            acts.emplace_back(act);
        } else {
            assert(false && "unknown global type");
        }
        for (auto& act : acts) {
            prog.actions.insert({act->name, act});
            stage->table_info.actions.emplace_back(act->name);
        }
        stage->act = nop_act->name;
        table_stages.insert({g, stage});
    }
}


void p4_prog_add_stages(Program& prog, TranslateCtx& ctx, HIRP4Function& func) {
    // calcutate how many "from" do we need
    std::unordered_set<std::shared_ptr<BasicBlock>> from_bbs;
    for (auto& kv : ctx.from) {
        for (auto& bb : kv.second) {
            from_bbs.insert(bb);
        }
    }
    for (auto& bb : func.bbs) {
        if (ctx.from[bb].size() > 1) {
            from_bbs.insert(bb);
        }
    }
    for (auto& bb : from_bbs) {
        std::string var_name = "from_" + bb->name;
        assert(ctx.meta_bw.find(var_name) == ctx.meta_bw.end());
        ctx.meta_bw[var_name] = 1;
    }

    // create stages for each basic block, need to split vector and map lookup
    auto nop_act = std::make_shared<Action>();
    nop_act->name = "nop_bb";
    prog.actions.insert({nop_act->name, nop_act});

    std::unordered_map<std::shared_ptr<Var>, std::shared_ptr<Stage>> table_stages;
    p4_create_table_stages(prog, nop_act, func, ctx, table_stages);
    std::unordered_map<std::shared_ptr<BasicBlock>, std::string> bb_stage_mapping;
    std::shared_ptr<Stage> init_stage = nullptr;
    std::shared_ptr<Stage> prev_stage = nullptr;
    for (int i = 0; i < func.bbs.size(); i++) {
        auto& bb = func.bbs[i];
        auto act = std::make_shared<Action>();
        act->name = bb->name;
        Op2P4VisitorV2 visitor;
        visitor.act = act;
        visitor.ctx = &ctx;

        auto& prev_bbs = ctx.from[bb];
        Stage::CondList stage_pre_cond;
        stage_pre_cond.or_list.clear();
        if (prev_bbs.size() == 0) {
        } else {
            for (auto& prev_bb : prev_bbs) {
                bool found = false;
                for (auto& e : prev_bb->branches) {
                    auto n_bb = e.next_bb.lock();
                    if (n_bb == bb) {
                        auto v = e.cond_var;
                        auto cond_entry = cond_v_to_entry(ctx, v, ctx.is_egress);
                        Stage::CondList::AndList and_list;
                        and_list.emplace_back(cond_entry);
                        auto from_var = HeaderRef::Meta("from_" + prev_bb->name);
                        Stage::CondList::Entry from_e{from_var, HeaderRef("1"), "=="};
                        and_list.emplace_back(from_e);
                        stage_pre_cond.or_list.emplace_back(and_list);
                        found = true;
                    }
                }
                if (!prev_bb->is_return && !prev_bb->is_err) {
                    auto n_bb = prev_bb->default_next_bb.lock();
                    assert(n_bb != nullptr);
                    if (n_bb == bb) {
                        Stage::CondList::AndList and_list;
                        for (auto& e : prev_bb->branches) {
                            auto v = e.cond_var;
                            auto cond_entry = cond_v_to_entry(ctx, v, ctx.is_egress);
                            if (cond_entry.cmp_op == "") {
                                assert(cond_entry.arg2.is_constant);
                                assert(cond_entry.arg2.field == "");
                                assert(cond_entry.arg1.is_constant);
                                cond_entry.arg1.field = "!" + cond_entry.arg1.field;
                            } else {
                                cond_entry.cmp_op = rev_cmp_op(cond_entry.cmp_op);
                            }
                            and_list.emplace_back(cond_entry);
                        }
                        auto from_var = HeaderRef::Meta("from_" + prev_bb->name);
                        Stage::CondList::Entry from_e{from_var, HeaderRef("1"), "=="};
                        and_list.emplace_back(from_e);
                        stage_pre_cond.or_list.emplace_back(and_list);
                        found = true;
                    }
                }
                assert(found);
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
                    prog.add_stage(stage);
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
                    HeaderRef::Meta("from_" + bb->name),
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
            prog.add_action(act);
        }
        prev_stage = stage;
        if (init_stage == nullptr) {
            init_stage = stage;
        }
        prog.add_stage(stage);
    }
    assert(init_stage != nullptr);
    prog.init_stage = init_stage->name;
}

std::shared_ptr<Program> p4_program_from_function_v2(
        std::shared_ptr<HIR::Element> ele,
        std::shared_ptr<HIR::Function> func,
        bool is_egress) {
    TranslateCtx translate_ctx;
    auto prog = std::make_shared<Program>();
    p4_prog_default_init(*prog);
    auto ctx = pipeline_from_function(ele, func);
    ctx->m = ele->module();
    p4_const_propagation(*ctx);
    p4_replace_table_result(*ctx, translate_ctx);
    p4_create_meta_mapping(*ctx, translate_ctx);

    std::unordered_map<std::shared_ptr<BasicBlock>, StageCond> bb_conds;
    update_exec_cond(func->bbs[func->entry_bb_idx()], {}, bb_conds);

    for (auto& bb : ctx->bbs) {
        for (auto& e : bb->branches) {
            auto n_bb = e.next_bb.lock();
            translate_ctx.from[n_bb].insert(bb);
        }
        if (!bb->is_return && !bb->is_err) {
            auto n_bb = bb->default_next_bb.lock();
            translate_ctx.from[n_bb].insert(bb);
        }
    }

    p4_prog_add_stages(*prog, translate_ctx, *ctx);

    for (auto& kv : translate_ctx.meta_bw) {
        prog->meta->fields.insert({kv.first, kv.second});
    }
    for (auto& kv : translate_ctx.alloca_meta_mapping) {
        auto& m = kv.second;
        auto flattened = m.get_flattened_metas();
        for (auto& e : flattened) {
            prog->meta->fields.insert({e.var_name, e.bw});
        }
    }

    return prog;
}

void print_p4_func(std::ostream& os, const HIRP4Function& func) {
    for (auto& bb : func.bbs) {
        os << bb->name << " : " << std::endl;
        for (auto& op : bb->ops) {
            op->print(os);
            for (auto& dst : op->dst_vars) {
                os << " " << dst.get();
            }
            for (auto& a : op->args) {
                os << " " << a.get();
            }
            os << std::endl;
        }
        bb->print_branching(os);
        os << std::endl;
    }
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

    // first allocate variable for each of the state operations
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
                        HeaderRef::Meta(e.var_name),
                        "modify_field",
                        std::vector<HeaderRef>{HeaderRef::Arg(e.var_name)}));
            }
            acts.emplace_back(act);
        } else if (g->type->type == HIR::Type::T::MAP) {
            auto kt = g->type->map_info.key_t;
            auto vt = g->type->map_info.val_t;
            StructMetaMapping flattened = flatten_struct(kt, "map_key");
            auto keys = flattened.get_flattened_metas();
            for (auto& k : keys) {
                stage->table_info.keys.emplace_back(HeaderRef::Meta(k.var_name));
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
                        HeaderRef::Meta(e.var_name),
                        "modify_field",
                        std::vector<HeaderRef>{HeaderRef::Arg(e.var_name)}));
            }
            act->ops.emplace_back(
                std::make_shared<P4IR::Operation>(
                    HeaderRef::Meta(is_null),
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
            auto from_var = HeaderRef::Meta("from_" + prev_bb->name);
            Stage::CondList::Entry entry { from_var, HeaderRef("1"), "==" };
            stage_and_list.emplace_back(entry);
            stage_pre_cond.or_list = {stage_and_list};
        } else {
            for (auto& prev_bb : prev_bbs) {
                auto& prev_prev = from[prev_bb];
                if (prev_prev.size() > 0) {
                    auto from_var = HeaderRef::Meta("from_" + prev_bb->name);
                }
                for (auto& e : prev_bb->branches) {
                    auto n_bb = e.next_bb.lock();
                    if (n_bb == bb) {
                        auto v = e.cond_var;
                        auto cond_entry = cond_v_to_entry(ctx, v, is_egress);
                        Stage::CondList::AndList and_list;
                        and_list.emplace_back(cond_entry);
                        if (prev_prev.size() > 0) {
                            auto from_var = HeaderRef::Meta("from_" + prev_bb->name);
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
                            auto from_var = HeaderRef::Meta("from_" + prev_bb->name);
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
                    HeaderRef::Meta("from_" + bb->name),
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
