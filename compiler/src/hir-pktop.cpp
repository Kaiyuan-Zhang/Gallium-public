#include "hir-common-pass.hpp"
#include "hir-pktop.hpp"
#include "llvm-helpers.hpp"
#include <unordered_set>

namespace HIR {
    struct PacketOpInfo {
        enum class T {
            OTHER,
            PKT_PTR,
            PKT_HEADER_PTR,
            PKT_FIELD_PTR,
            PKT_W_OFFSET,
        };

        PacketOpInfo() : type(T::OTHER) {}

        T type;

        bool type_match = false;
        bool is_orig = false;
        bool analyzing = false;
        std::shared_ptr<Var> pkt_obj;
        std::string header_name;
        std::string field_name;
        uint64_t offset;
        size_t field_size;

        bool operator==(const PacketOpInfo& o) {
            if (type != o.type) {
                return false;
            }
            switch (type) {
            case T::OTHER:
                return false;
            case T::PKT_PTR:
                return pkt_obj == o.pkt_obj;
            case T::PKT_HEADER_PTR:
                return pkt_obj == o.pkt_obj && header_name == o.header_name;
            case T::PKT_FIELD_PTR:
                return pkt_obj == o.pkt_obj
                    && header_name == o.header_name
                    && field_name == o.field_name;
            case T::PKT_W_OFFSET:
                return pkt_obj == o.pkt_obj && offset == o.offset;
            default:
                return false;
            }
            return false;
        }
        bool operator!=(const PacketOpInfo& o) {
            return !(*this == o);
        }
    };

    PacketOpInfo pkt_access_trace(
        const PacketLayout &layout,
        std::unordered_map<std::shared_ptr<Var>, PacketOpInfo> &info_cache,
        std::shared_ptr<Var> v);

    class PktAccOpTraceVisitor : public OperationConstVisitor<PktAccOpTraceVisitor> {
    public:
        std::unordered_map<std::shared_ptr<Var>, PacketOpInfo>& info_cache;
        const PacketLayout &layout;

        PacketOpInfo &result;

        PktAccOpTraceVisitor(
            const PacketLayout &l,
            std::unordered_map<std::shared_ptr<Var>, PacketOpInfo>& c,
            PacketOpInfo &i)
            : layout(l), info_cache(c), result(i) {}

        void visitDefault(const Operation& op) {
        }

        void visitPhiNode(const Operation& op) {
            std::vector<PacketOpInfo> incoming_infos;
            assert(op.phi_info.from.size() == op.args.size());
            for (int i = 0; i < op.phi_info.from.size(); i++) {
                incoming_infos.emplace_back(pkt_access_trace(layout, info_cache, op.args[i]));
            }
            auto fst = incoming_infos[0];
            for (int i = 1; i < incoming_infos.size(); i++) {
                if (fst != incoming_infos[i]) {
                    result.type = PacketOpInfo::T::OTHER;
                    return;
                }
            }
            result = fst;
        }

        void visitGep(const Operation& op) {
            assert(op.args.size() > 0);
            auto ptr_var = op.args[0];
            auto base_ptr_info = pkt_access_trace(layout, info_cache, ptr_var);

            // calculate offset
            auto const_off = 0;
            bool symbolic_offset = false;
            auto gep_ptr_type = ptr_var->type;
            assert(gep_ptr_type->type == Type::T::POINTER);
            for (int i = 1; i < op.args.size(); i++) {
                if (op.args[i]->is_constant) {
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
                    } else if (gep_ptr_type->type == Type::T::PACKET) {
                        assert(off == 0 && const_off == 0);
                    } else {
                        assert(false && "unknown type");
                    }
                    const_off += off;
                } else {
                    // symbolic offset
                    symbolic_offset = true;
                    break;
                }
            }
            if (symbolic_offset) {
                result.type = PacketOpInfo::T::OTHER;
            }
            switch (base_ptr_info.type) {
            case PacketOpInfo::T::PKT_PTR:
                if (const_off == 0) {
                    result = base_ptr_info;
                }
                break;
            case PacketOpInfo::T::PKT_W_OFFSET:
                {
                    result.type = PacketOpInfo::T::PKT_W_OFFSET;
                    result.offset = base_ptr_info.offset + const_off;
                }
                break;
            case PacketOpInfo::T::PKT_HEADER_PTR:
                {
                    assert(layout.headers.find(base_ptr_info.header_name) != layout.headers.end());
                    auto &hdr = layout.headers.find(base_ptr_info.header_name)->second;
                    auto maybe_field = hdr.FindFieldByOffset(const_off);
                    if (maybe_field.has_value()) {
                        auto &field = maybe_field.value();
                        result.type = PacketOpInfo::T::PKT_FIELD_PTR;
                        result.pkt_obj = base_ptr_info.pkt_obj;
                        result.header_name = base_ptr_info.header_name;
                        result.field_name = field.field_name;
                        result.field_size = maybe_field->field_n_bytes;
                    }
                }
                break;
            default:
                break;
            }
        }

        void visitBitCast(const Operation& op) {
            result = pkt_access_trace(layout, info_cache, op.args[0]);
        }

        void visitFuncCall(const Operation& op) {
            auto &func = op.call_info.called_function;
            auto &fn = op.call_info.func_name;
            std::string demangled_fn;
            bool could_demangle = cxx_demangle(fn, demangled_fn);

            if (could_demangle) {
                if (demangled_fn == "WritablePacket::ip_header() const"
                    || demangled_fn == "Packet::ip_header() const") {
                    auto base = pkt_access_trace(layout, info_cache, op.args[0]);
                    assert(base.type == PacketOpInfo::T::PKT_PTR);
                    result.pkt_obj = base.pkt_obj;
                    result.type = PacketOpInfo::T::PKT_HEADER_PTR;
                    result.header_name = "ipv4";
                } else if (demangled_fn == "Packet::transport_header() const") {
                    auto base = pkt_access_trace(layout, info_cache, op.args[0]);
                    assert(base.type == PacketOpInfo::T::PKT_PTR);
                    result.pkt_obj = base.pkt_obj;
                    result.type = PacketOpInfo::T::PKT_HEADER_PTR;
                    result.header_name = "tcp";
                } else if (demangled_fn == "Packet::uniqueify()") {
                    auto base = pkt_access_trace(layout, info_cache, op.args[0]);
                    assert(base.type == PacketOpInfo::T::PKT_PTR);
                    result = base;
                }
            }
        }
    };

    PacketOpInfo pkt_access_trace(
            const PacketLayout &layout,
            std::unordered_map<std::shared_ptr<Var>, PacketOpInfo> &info_cache,
            std::shared_ptr<Var> v) {
        if (info_cache.find(v) != info_cache.end()) {
            return info_cache[v];
        }
        if (v->is_param) {
            return PacketOpInfo();
        } else {
            auto src_op = v->src_op.lock();
            PacketOpInfo info;
            info_cache[v] = info;
            auto &info_ref = info_cache[v];
            info_ref.analyzing = true;
            PktAccOpTraceVisitor visitor(layout, info_cache, info_ref);
            info_ref.analyzing = false;
            visitor.visit(*src_op);
            return info_ref;
        }
    }

    void replace_packet_access_op(Element &ele, const PacketLayout &layout) {
        auto &f = *ele.entry();
        std::unordered_map<std::shared_ptr<Var>, PacketOpInfo> info_cache;
        /* we only need to do this on the very top level :
         * starting from the entry function, don't need to go into other functions
         * since that function must be either built-in or recursive
         */
        assert(f.args.size() == 3);
        PacketOpInfo other_info;
        info_cache[f.args[0]] = other_info;
        info_cache[f.args[1]] = other_info;
        PacketOpInfo input_pkt_info;
        input_pkt_info.type = PacketOpInfo::T::PKT_PTR;
        input_pkt_info.pkt_obj = f.args[2];
        info_cache[f.args[2]] = input_pkt_info;

        for (auto &bb : f.bbs) {
            for (auto &op : bb->ops) {
                if (op->type == Operation::T::LOAD || op->type == Operation::T::STORE) {
                    auto ptr_info = pkt_access_trace(layout, info_cache, op->args[0]);
                    if (ptr_info.type == PacketOpInfo::T::PKT_FIELD_PTR
                        || ptr_info.type == PacketOpInfo::T::PKT_HEADER_PTR) {
                        op->pkt_op_info.header = ptr_info.header_name;
                        if (ptr_info.type == PacketOpInfo::T::PKT_FIELD_PTR) {
                            op->pkt_op_info.field = ptr_info.field_name;
                        } else {
                            auto &hdr = layout.headers.find(ptr_info.header_name)->second;
                            auto maybe_field = hdr.FindFieldByOffset(0);
                            assert(maybe_field.has_value());
                            ptr_info.field_size = maybe_field->field_n_bytes;
                            op->pkt_op_info.field = maybe_field->field_name;
                        }

                        Type* t = nullptr;
                        if (op->type == Operation::T::LOAD) {
                            t = op->dst_vars[0]->type;
                        } else {
                            t = op->args[1]->type;
                        }
                        if (t->type != Type::T::INT) {
                            continue;
                        }
                        if (t->bitwidth != ptr_info.field_size * 8) {
                            continue;
                        }

                        op->args.clear();
                        op->args.emplace_back(ptr_info.pkt_obj);
                        if (op->type == Operation::T::LOAD) {
                            op->type = Operation::T::PKT_HDR_LOAD;
                        } else {
                            op->type = Operation::T::PKT_HDR_STORE;
                            op->args.emplace_back(op->args[1]);
                        }
                        assert(ptr_info.pkt_obj != nullptr);
                    }
                }
            }
        }

        for (auto& bb : f.bbs) {
            for (auto& op : bb->ops) {
                for (auto& a : op->args) {
                    if (a->is_constant || a->is_param || a->is_global) {
                        continue;
                    }
                    auto arg_info = pkt_access_trace(layout, info_cache, a);
                    if (arg_info.type == PacketOpInfo::T::PKT_PTR) {
                        assert(arg_info.pkt_obj != nullptr);
                        a = arg_info.pkt_obj;
                    }
                }
            }
        }
        update_uses(ele);
    }

    void replace_packet_meta_op(Element &ele) {
        auto entry_f = ele.entry();
        auto this_ptr = entry_f->args[0];
        for (auto& f : ele.funcs) {
            for (auto& bb : f->bbs) {
                for (auto& op : bb->ops) {
                    if (op->type == Operation::T::FUNC_CALL) {
                        auto fn = cxx_try_demangle(op->call_info.func_name);
                        if (fn == "Element::checked_output_push(int, Packet*) const") {
                            op->args[0] = this_ptr;
                        }
                    }
                }
            }
        }

        update_uses(ele);
    }

    void replace_packet_access_op(Module &m, const PacketLayout &layout) {
    }
}
