#include "hir-dpdkgen.hpp"
#include "utils.hpp"
#include "llvm-helpers.hpp"

CodePrinter::CodePrinter(std::ostream& os) : os_(os), indent_lvl_(0) {
}

void CodePrinter::PrintLine(const std::string& line, std::optional<char> eol, int indent_off) {
    indent_lvl_ += indent_off;
    PrintIndent();
    indent_lvl_ -= indent_off;
    os_ << line;
    if (eol.has_value()) {
        os_ << *eol;
    }
    os_ << std::endl;
}

void CodePrinter::OpenBlock(const std::string& line, const std::string& open_str) {
    PrintIndent();
    os_ << line << open_str << std::endl;
    indent_lvl_++;
}

void CodePrinter::CloseBlock(const std::string& s) {
    assert(indent_lvl_ > 0);
    indent_lvl_--;
    PrintIndent();
    os_ << s << std::endl;
}

void CodePrinter::PrintIndent() {
    for (int i = 0; i < indent_lvl_; i++) {
        os_ << "  ";
    }
}

using namespace HIR;

DpdkGen::DpdkGen(const std::string& name, std::ostream& header, std::ostream& source)
        : header_(header),
          source_(source) {
    header_.PrintLine("#pragma once", std::nullopt);
    header_.PrintLine("#include \"gallium-dpdk.h\"", std::nullopt);
    source_.PrintLine("#include \"" + name + ".h\"", std::nullopt);
}

std::string opaque_type_str(const std::string& s) {
    if (str_begin_with(s, "%class.Timer")) {
        return "struct Timer";
    } else if (str_begin_with(s, "%class.WritablePacket")) {
        return "struct packet";
    } else {
        assert(false && "unknown opaque type");
    }
}

std::string DpdkGen::TypeName(Type* t) {
    if (type_name_.find(t) != type_name_.end()) {
        return type_name_[t];
    }
    std::string result;
    switch (t->type) {
    case Type::T::UNDEF:
        result = "void *";
        break;
    case Type::T::VOID:
        result = "void";
        break;
    case Type::T::INT:
        result = "uint" + std::to_string(t->bitwidth) + "_t";
        break;
    case Type::T::FLOAT:
        assert(t->bitwidth == 32 || t->bitwidth == 64);
        result = "f" + std::to_string(t->bitwidth) + "_t";
        break;
    case Type::T::POINTER:
        result = TypeName(t->pointee_type) + "*";
        break;
    case Type::T::STATE_PTR:
        result = "void *";
        break;
    case Type::T::PACKET:
        result = "struct packet";
        break;
    case Type::T::STRUCT:
        assert(false);
    case Type::T::ARRAY:
        result = TypeName(t->array_info.element_type) + "*";
        break;
    case Type::T::ELEMENT_BASE:
        result = "struct base_state";
        break;
    case Type::T::VECTOR:
        result = "struct vector_t";
        break;
    case Type::T::MAP:
        result = "struct map_t";
        break;
    case Type::T::OPAQUE:
        result = opaque_type_str(t->opaque_type_name);
        break;
    }

    type_name_[t] = result;
    return result;
}

std::string DpdkGen::VarName(std::shared_ptr<Var> v) {
    if (v->is_constant) {
        return std::to_string(v->constant);
    }
    if (v->is_global) {
        return "&(gs->f" + std::to_string(v->global_state_idx) + ")";
    }
    if (var_name_.find(v) == var_name_.end()) {
        std::string n;
        for (int i = 0; i < v->name.length(); i++) {
            if (v->name[i] == '%') {
                n = n + "v_";
            } else {
                n = n + v->name[i];
            }
        }
        var_name_[v] = n;
    }
    return var_name_[v];
}

std::string DpdkGen::BBName(std::shared_ptr<HIR::BasicBlock> bb) {
    if (bb_name_.find(bb) == bb_name_.end()) {
        bb_name_[bb] = bb->name;
    }
    return bb_name_[bb];
}

std::string SignedTypeName(Type* t) {
    assert(t->type == Type::T::INT);
    return "int" + std::to_string(t->bitwidth) + "_t";
}

class DpdkOperationPrinter : public OperationConstVisitor<DpdkOperationPrinter> {
public:
    CodePrinter& p;
    DpdkGen& code_gen;
    DpdkOperationPrinter(CodePrinter& p_ref, DpdkGen& g_ref) : p(p_ref), code_gen(g_ref) {}

void visitAlloca(const Operation& op) {
}

void visitArith(const Operation& op) {
    if (op.arith_info.t == ArithType::INT_ARITH) {
        static std::unordered_map<IntArithType, std::string> aop = {
            {IntArithType::INT_ADD, "+"},
            {IntArithType::INT_SUB, "-"},
            {IntArithType::INT_MUL, "*"},
            {IntArithType::INT_DIV, "/"},
            {IntArithType::INT_MOD, "%"},
            {IntArithType::INT_UDIV, "/"},
            {IntArithType::INT_UMOD, "%"},
            {IntArithType::INT_AND, "&"},
            {IntArithType::INT_OR, "|"},
            {IntArithType::INT_XOR, "^"},
            {IntArithType::INT_SHL, "<<"},
            {IntArithType::INT_LSHR, ">>"},
            {IntArithType::INT_ASHR, ">>"},
        };
        static std::unordered_set<IntArithType> require_signed_cast = {
            IntArithType::INT_DIV,
            IntArithType::INT_MOD,
            IntArithType::INT_ASHR,
        };

        auto op_type = op.arith_info.u.iarith_t;
        if (op.args.size() == 1) {
            assert(op_type == IntArithType::INT_TRUNC
                   || op_type == IntArithType::INT_ZEXT
                   || op_type == IntArithType::INT_SEXT);
            auto& dst = op.dst_vars[0];
            auto arg_str = code_gen.VarName(op.args[0]);
            if (op_type == IntArithType::INT_SEXT) {
                arg_str = "(" + SignedTypeName(dst->type) + ")("
                          + SignedTypeName(op.args[0]->type) + ")" + arg_str;
            }
            p.PrintLine(code_gen.VarName(dst) + " = (" +
                        code_gen.TypeName(dst->type) + ")" +
                        arg_str);
        } else {
            assert(op.args.size() == 2);
            auto& dst = op.dst_vars[0];
            auto arg1_str = code_gen.VarName(op.args[0]);
            auto arg2_str = code_gen.VarName(op.args[1]);
            if (require_signed_cast.find(op_type) != require_signed_cast.end()) {
                arg1_str = "(" + SignedTypeName(op.args[0]->type) + ")" + arg1_str;
                arg2_str = "(" + SignedTypeName(op.args[1]->type) + ")" + arg2_str;
            }
            p.PrintLine(code_gen.VarName(dst) + " = " +
                        arg1_str + " " + aop[op_type] + " " + arg2_str);
        }
    } else if (op.arith_info.t == ArithType::INT_CMP) {
        static std::unordered_map<IntCmpType, std::string> aop = {
            {IntCmpType::EQ, "=="},
            {IntCmpType::NE, "!="},
            {IntCmpType::ULE, "<="},
            {IntCmpType::ULT, "<"},
            {IntCmpType::SLE, "<="},
            {IntCmpType::SLT, "<"},
        };
        static std::unordered_set<IntCmpType> require_signed_cast = {
            IntCmpType::SLE,
            IntCmpType::SLT,
        };
        auto op_type = op.arith_info.u.icmp_t;
        assert(op.args.size() == 2);
        auto& dst = op.dst_vars[0];
        auto arg1_str = code_gen.VarName(op.args[0]);
        auto arg2_str = code_gen.VarName(op.args[1]);
        if (require_signed_cast.find(op_type) != require_signed_cast.end()) {
            arg1_str = "(" + SignedTypeName(op.args[0]->type) + ")" + arg1_str;
            arg2_str = "(" + SignedTypeName(op.args[1]->type) + ")" + arg2_str;
        }
        p.PrintLine(code_gen.VarName(dst) + " = " +
                    arg1_str + " " + aop[op_type] + " " + arg2_str);
    } else {
        assert(false && "unknown arith");
    }
}

void visitStructSet(const Operation& op) {
    auto ptr_var = op.args[0];
    auto val = op.args[1];
    std::string field_acc = "";
    for (auto& off : op.struct_ref_info) {
        field_acc += ".f" + std::to_string(off);
    }
    p.PrintLine("(*" + code_gen.VarName(ptr_var) + ")" + field_acc +
                " = " + code_gen.VarName(val));
}

void visitStructGet(const Operation& op) {
    assert(op.dst_vars.size() == 1);
    auto dst = op.dst_vars[0];
    auto ptr_var = op.args[0];
    std::string field_acc = "";
    for (auto& off : op.struct_ref_info) {
        field_acc += ".f" + std::to_string(off);
    }
    p.PrintLine(code_gen.VarName(dst) + " = (*" +
                code_gen.VarName(ptr_var) + ")" + field_acc);
}

void visitLoad(const Operation& op) {
    auto ptr_var = op.args[0];
    auto dst = op.dst_vars[0];
    p.PrintLine(code_gen.VarName(dst) + " = *(" +
                code_gen.TypeName(dst->type) + "*)" +
                code_gen.VarName(ptr_var));
}

void visitStore(const Operation& op) {
    auto ptr_var = op.args[0];
    auto val_var = op.args[0];
    p.PrintLine("*(" + code_gen.TypeName(val_var->type) + "*)" +
                code_gen.VarName(ptr_var) +
                " = " + code_gen.VarName(ptr_var));
}

void visitGep(const Operation& op) {
    auto& dst = op.dst_vars[0];
    auto& ptr_base = op.args[0];
    auto curr_type = ptr_base->type;
    std::string s = code_gen.VarName(ptr_base);
    for (int i = 1; i < op.args.size(); i++) {
        auto off = op.args[i];
        if (curr_type->type == Type::T::POINTER) {
            s = s + "[" + code_gen.VarName(off) + "]";
            curr_type = curr_type->pointee_type;
        } else if (curr_type->type == Type::T::ARRAY) {
            s = s + "[" + code_gen.VarName(off) + "]";
            curr_type = curr_type->array_info.element_type;
        } else if (curr_type->type == Type::T::STRUCT) {
            s = s + ".f" + code_gen.VarName(off);
            assert(off->is_constant);
            curr_type = curr_type->struct_info.fields[off->constant];
        } else {
            assert(false && "GEP: unknown type");
        }
    }
}

void visitPhiNode(const Operation& op) {
    assert(op.phi_info.from.size() == op.args.size());
    auto& dst = op.dst_vars[0];
    for (int i = 0; i < op.phi_info.from.size(); i++) {
        auto from_bb = op.phi_info.from[i].lock();
        auto from_bb_var = "from_" + code_gen.BBName(from_bb);
        p.OpenBlock("if (" + from_bb_var + ") ");
        p.PrintLine(code_gen.VarName(dst) + " = " + code_gen.VarName(op.args[i]));
        p.CloseBlock();
    }
}

void visitBitCast(const Operation& op) {
    auto& dst = op.dst_vars[0];
    auto& val = op.args[0];
    p.PrintLine(code_gen.VarName(dst) + " = (" +
                code_gen.TypeName(dst->type) + ")" +
                code_gen.VarName(val));
}

void visitSelect(const Operation& op) {
    auto& dst = op.dst_vars[0];
    auto& cond = op.args[0];
    auto& t_val = op.args[1];
    auto& f_val = op.args[2];
    p.PrintLine(code_gen.VarName(dst) + " = " +
                code_gen.VarName(cond) + "?" +
                code_gen.VarName(t_val) + ":" +
                code_gen.VarName(f_val));
}

void visitFuncCall(const Operation& op) {
    auto f = op.call_info.called_function.lock();
    bool is_built_in = false;
    auto fn = code_gen.FuncName(op.call_info.func_name, &is_built_in);
    std::string stmt = "";
    if (op.dst_vars.size() > 0) {
        assert(op.dst_vars.size() == 1);
        stmt = stmt + code_gen.VarName(op.dst_vars[0]) + " = ";
    }

    if (is_built_in && op.dst_vars.size() > 0) {
        fn = "(" + code_gen.TypeName(op.dst_vars[0]->type) + ")" + fn;
    }
    std::string arg_list;
    for (int i = 0; i < op.args.size(); i++) {
        if (i != 0) {
            arg_list += ", ";
        }
        arg_list += code_gen.VarName(op.args[i]);
    }
    stmt += fn + "(" + arg_list + ")";
    p.PrintLine(stmt);
}

std::string header_name_to_idx(const std::string& header) {
    static std::unordered_map<std::string, std::string> hn = {
        {"ether", "ETH_HDR"},
        {"ipv4",  "IPV4_HDR"},
        {"tcp",   "TCP_HDR"},
        {"udp",   "UDP_HDR"},
    };
    if (hn.find(header) == hn.end()) {
        assert(false);
        return "";
    }
    return hn[header];
}

std::string header_name_to_header_type(const std::string& header) {
    static std::unordered_map<std::string, std::string> hn = {
        {"ether", "struct ether_hdr"},
        {"ipv4",  "struct ipv4_hdr"},
        {"tcp",   "struct tcp_hdr"},
        {"udp",   "struct udp_hdr"},
    };
    if (hn.find(header) == hn.end()) {
        assert(false);
        return "";
    }
    return hn[header];
}

void visitPktLoad(const Operation& op) {
    auto& dst = op.dst_vars[0];
    auto& pkt_obj = op.args[0];
    auto hdr_name = header_name_to_idx(op.pkt_op_info.header);
    auto hdr_type = header_name_to_header_type(op.pkt_op_info.header);
    p.PrintLine(code_gen.VarName(dst) + " = " +
                "GET_HDR_FIELD(" + code_gen.VarName(pkt_obj) + ", " +
                hdr_name + ", " + hdr_type + ", " + op.pkt_op_info.field + ")");
}

void visitPktStore(const Operation& op) {
    auto& pkt_obj = op.args[0];
    auto& val = op.args[1];
    auto hdr_name = header_name_to_idx(op.pkt_op_info.header);
    auto hdr_type = header_name_to_header_type(op.pkt_op_info.header);
    p.PrintLine("SET_HDR_FIELD(" + code_gen.VarName(pkt_obj) + ", " +
                hdr_name + ", " + hdr_type + ", " + op.pkt_op_info.field +
                ", " + code_gen.VarName(val) + ")");
}

void visitPktEncap(const Operation& op) {
    assert(false && "unsupported");
}

void visitPktDecap(const Operation& op) {
    assert(false && "unsupported");
}

void visitUnreachable(const Operation& op) {
    p.PrintLine("assert(false)");
}


};

void DpdkGen::PrintOperation(HIR::Operation* op, bool need_decl) {
    DpdkOperationPrinter printer(source_, *this);
    printer.visit(*op);
}

void DpdkGen::PrintFunction(HIR::Function* f, const Element* ele) {
    auto fn = FuncName(f->name);
    auto ret_t = TypeName(f->return_type);
    std::string arg_list = "";
    assert(f->arg_types.size() == f->args.size());
    for (int i = 0; i < f->arg_types.size(); i++) {
        if (i != 0) {
            arg_list += ", ";
        }
        arg_list += TypeName(f->arg_types[i].get()) + " ";
        arg_list += VarName(f->args[i]);
    }
    source_.OpenBlock(ret_t + " " + fn + "(" + arg_list + ") ");

    // find extra variable needed by phi
    std::unordered_set<std::shared_ptr<BasicBlock>> from_bbs;
    for (auto& bb : f->bbs) {
        for (auto& op : bb->ops) {
            if (op->type == Operation::T::PHINODE) {
                for (auto& from : op->phi_info.from) {
                    from_bbs.insert(from.lock());
                }
            }
        }
    }

    for (auto& bb : from_bbs) {
        source_.PrintLine("bool from_" + BBName(bb) + " = false");
    }

    for (auto& bb : f->bbs) {
        for (auto& op : bb->ops) {
            if (op->type == Operation::T::ALLOCA) {
                auto t = op->alloca_type;
                auto v = VarName(op->dst_vars[0]);
                if (t->type == Type::T::ARRAY) {
                    auto tn = TypeName(t->array_info.element_type);
                    auto n = t->array_info.num_element;
                    source_.PrintLine(tn + " " + v + "[" + std::to_string(n) + "]");
                } else if (t->type == Type::T::STRUCT) {
                    auto tn = TypeName(t);
                    source_.PrintLine(tn + " " + v + "[1]");
                } else if (t->type == Type::T::INT) {
                    auto tn = TypeName(t);
                    source_.PrintLine(tn + " " + v + "[1]");
                } else {
                    assert(false && "unknown alloca type");
                }
            }
        }
    }

    auto ctl_graph = control_graph_of_func(*f);
    auto scc_list = ctl_graph.StronglyConnectedComponents();
    auto scc_graph = scc_graph_from_scc(scc_list, ctl_graph);
    auto topo_order = scc_graph.TopologicalSort();

    std::unordered_set<std::shared_ptr<Var>> declared_vars;
    for (auto& bb : f->bbs) {
        for (auto& op : bb->ops) {
            if (op->type == Operation::T::ALLOCA) {
                continue;
            }
            for (auto& d : op->dst_vars) {
                declared_vars.insert(d);
            }
        }
    }

    for (auto& v : declared_vars) {
        auto tn = TypeName(v->type);
        source_.PrintLine(tn + " " + VarName(v));
    }
    for (int i = topo_order.size() - 1; i >= 0; i--) {
        auto& scc = scc_list[topo_order[i]];
        for (auto& bb_idx : scc) {
            auto& bb = ctl_graph.vertex_ref(bb_idx);
            source_.PrintLine(BBName(bb), ':', -1);
            for (auto& op : bb->ops) {
                assert(op->dst_vars.size() <= 1);
                if (op->dst_vars.size() == 1) {
                    auto d = op->dst_vars[0];
                    PrintOperation(op.get(), declared_vars.find(d) == declared_vars.end());
                } else {
                    PrintOperation(op.get());
                }
            }
            if (from_bbs.find(bb) != from_bbs.end()) {
                source_.PrintLine("from_" + BBName(bb) + " = true");
            }
            // print code for branching
            if (bb->is_return) {
                if (bb->return_val == nullptr) {
                    source_.PrintLine("return");
                } else {
                    source_.PrintLine("return " + VarName(bb->return_val));
                }
            } else if (bb->is_err) {
                source_.PrintLine("assert(false)");
            } else {
                for (auto& e : bb->branches) {
                    assert(e.is_conditional);
                    source_.OpenBlock("if (" + VarName(e.cond_var) + ") ");
                    source_.PrintLine("goto " + BBName(e.next_bb.lock()));
                    source_.CloseBlock();
                }
                source_.PrintLine("goto " + BBName(bb->default_next_bb.lock()));
            }
            source_.NewLine();
        }
    }
    source_.CloseBlock();
}

std::optional<std::string> rewrite_builtin_func(const std::string& fn) {
    if (str_begin_with(fn, "Packet::uniqueify")) {
        return "packet_uniqueify";
    } else if (str_begin_with(fn, "Vector::operator[]")) {
        return "vector_idx";
    } else if (str_begin_with(fn, "Packet::transport_length")) {
        return "packet_l4_length";
    } else if (str_begin_with(fn, "IPFlowID::IPFlowID")) {
        return "ipflowid_init";
    } else if (str_begin_with(fn, "HashMap::findp")) {
        return "hashmap_find";
    } else if (str_begin_with(fn, "HashMap::insert")) {
        return "hashmap_insert";
    } else if (str_begin_with(fn, "Element::checked_output_push")) {
        return "push_pkt_to_port";
    } else if (str_begin_with(fn, "Packet::has_network_header")) {
        return "packet_has_l3_header";
    } else if (str_begin_with(fn, "Packet::transport_header")) {
        return "packet_l4_header";
    } else if (str_begin_with(fn, "Packet::kill")) {
        return "packet_kill";
    } else if (str_begin_with(fn, "llvm.memcpy.")) {
        return "gallium_memcpy";
    } else if (str_begin_with(fn, "__assert_fail")) {
        return "assert_fail";
    }
    return std::nullopt;
}

std::string DpdkGen::FuncName(const std::string& fn, bool* is_built_in) {
    std::string func_name;
    bool demanged = cxx_demangle(fn, func_name);
    if (!demanged) {
        func_name = fn;
    }

    // ignore things in parenthesis and <>
    std::string result = func_name;
    auto start = result.find('(');
    if (start != std::string::npos) {
        auto end = result.find_last_of(')');
        assert(end != std::string::npos);
        assert(start < end);
        result.erase(start, end - start + 1);
    }

    start = result.find('<');
    if (start != std::string::npos) {
        auto end = result.find_last_of('>');
        assert(end != std::string::npos);
        assert(start < end);
        result.erase(start, end - start + 1);
    }

    // first try to match and rewrite
    auto maybe_builtin = rewrite_builtin_func(result);
    if (maybe_builtin.has_value()) {
        if (is_built_in != nullptr) {
            *is_built_in = true;
        }
        return *maybe_builtin;
    }

    auto pos = result.find(':');
    while (pos != std::string::npos) {
        result[pos] = '_';
        pos = result.find(':');
    }
    return result;
}

void DpdkGen::PrintStructDef(
        Type* t,
        std::unordered_map<Type *, bool>& printed
) {
    assert(printed.find(t) != printed.end());
    if (printed[t]) {
        return;
    }
    for (auto& ft : t->struct_info.fields) {
        if (ft->type == Type::T::STRUCT) {
            PrintStructDef(ft, printed);
        }
    }
    header_.OpenBlock(type_name_[t] + " ");
    assert(t->type == Type::T::STRUCT);
    for (int i = 0; i < t->struct_info.fields.size(); i++) {
        auto& ft = t->struct_info.fields[i];
        header_.PrintLine(TypeName(ft) + " f" + std::to_string(i));
    }
    header_.CloseBlock("};");
    header_.NewLine();
    printed[t] = true;
}

std::string struct_name(const std::string& n) {
    std::string result = n;
    auto pos = result.find("class.");
    if (pos != std::string::npos) {
        result.erase(pos, std::string("class.").length());
    }
    pos = result.find("struct.");
    if (pos != std::string::npos) {
        result.erase(pos, std::string("struct.").length());
    }

    pos = result.find_last_of('.');
    while (pos != std::string::npos) {
        result[pos] = '_';
        pos = result.find_last_of('.');
    }

    pos = result.find_last_of(':');
    while (pos != std::string::npos) {
        result[pos] = '_';
        pos = result.find_last_of(':');
    }
    return result;
}

void DpdkGen::PrintCode(const Module& m) {
    // Step 1 : print type definitions
    std::unordered_map<Type *, bool> printed;
    for (auto& t : m.types) {
        if (t->type == Type::T::STRUCT) {
            auto name_base = struct_name(t->struct_info.struct_name);
            type_name_[t.get()] = "struct " + name_base;
            header_.PrintLine("struct " + name_base);
            printed.insert({t.get(), false});
        }
    }
    header_.NewLine();
    for (auto& kv : printed) {
        PrintStructDef(kv.first, printed);
    }

    // Step 2 : print all functions
    for (auto& kv : m.elements) {
        auto entry_f = kv.second->entry();
        assert(entry_f->args.size() > 0);
        element_this_ = entry_f->args[0];
        element_this_->name = "gs";
        for (auto& f : kv.second->funcs) {
            PrintFunction(f.get(), kv.second.get());
        }
        element_this_ = nullptr;
    }
}
