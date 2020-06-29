#include "pass-pipe-oprw.hpp"
#include "utils.hpp"

namespace Morula {
    PktPtrInfo find_pkt_ptr_info(PipeIR::Var *v, PktPtrTraceCtx &ctx) {
        if (ctx.cache.find(v) != ctx.cache.end()) {
            return ctx.cache[v];
        }
        PktPtrInfo result;

        auto op = v->from;
        using OpT = PipeIR::Operation::Type;
        if (op->type == OpT::PHI) {
            bool is_element_state = true;
            bool is_stack_ptr = true;
            for (auto &v : op->phi_incoming_vals) {
                auto info = find_pkt_ptr_info(v.get(), ctx);
                if (!info.is_element_state_ptr) {
                    is_element_state = false;
                }
                if (!info.is_stack_ptr) {
                    is_stack_ptr = false;
                }
            }

            if (is_element_state) {
                result.is_element_state_ptr = true;
            } else if (is_stack_ptr) {
                result.is_stack_ptr = true;
            }
        } else if (op->type == OpT::ARITH) {
            if (op->arith_op_name == "bitcast") {
                auto src_info = find_pkt_ptr_info(op->oprands[0].get(), ctx);
                result = src_info;
            } else if (op->arith_op_name == "ite") {
                auto l_info = find_pkt_ptr_info(op->oprands[1].get(), ctx);
                auto r_info = find_pkt_ptr_info(op->oprands[2].get(), ctx);
                if (l_info.is_element_state_ptr && r_info.is_element_state_ptr) {
                    result.is_element_state_ptr = true;
                }
            }
        } else if (op->type == OpT::POINTER_OFF) {
            auto ptr_base_info = find_pkt_ptr_info(op->oprands[0].get(), ctx);
            if (ptr_base_info.is_element_ptr) {
                // try to find the element
                auto element_base_var = ptr_base_info.element_obj;
                std::vector<int> idx_list = ptr_base_info.element_state_off;
                result.element_state_off = ptr_base_info.element_state_off;
                int start_idx = 1;
                bool early_ret = false;
                if (result.element_state_off.size() == 0) {
                    if (op->oprands[1]->is_const_val(0)) {
                        // ignore the first zero;
                        start_idx = 2;
                    } else {
                        // unknown state access
                        early_ret = true;
                    }
                }
                if (!early_ret) {
                    for (int i = start_idx; i < op->oprands.size(); i++) {
                        if (op->oprands[i]->is_constant) {
                            result.element_state_off.push_back(op->oprands[i]->const_val);
                        } else {
                            early_ret = true;
                        }
                    }
                }
                if (!early_ret) {
                    // try trace the idx
                    Click::ElementStateType *state_type = ctx.pass_ctx->element_state.get();
                    Click::StateEntry state_e;
                    bool is_state_ptr = false;
                    for (int i = 0; i < result.element_state_off.size(); i++) {
                        auto idx = result.element_state_off[i];
                        // TODO: handle array
                        if (state_type->field_type[idx].type == Click::StateEntry::T::STRUCT) {
                            state_type = state_type->field_type[idx].struct_rec.get();
                        } else {
                            assert(i == result.element_state_off.size() - 1);
                            is_state_ptr = true;
                            state_e = state_type->field_type[idx];
                        }
                    }

                    if (is_state_ptr) {
                        result.is_element_state_ptr = true;
                        result.is_element_ptr = false;
                        result.possible_state_entry.clear();
                        result.possible_state_entry.push_back(state_e);
                    } else {
                        result.is_element_ptr = true;
                    }
                } else {
                    result.is_element_ptr = false;
                }
            } else if (ptr_base_info.is_pkt_obj) {
                bool is_const_off = true;
                int const_off = 0;
                for (int i = 1; i < op->oprands.size(); i++) {
                    if (!op->oprands[i]->is_constant) {
                        is_const_off = false;
                        break;
                    } else {
                        const_off += op->oprands[i]->const_val;
                    }
                }
                if (is_const_off && const_off == 0) {
                    result.is_pkt_obj = true;
                    result.pkt_obj = ptr_base_info.pkt_obj;
                }
            } else if (ptr_base_info.is_pkt_hdr_ptr) {
                auto hdr_iter = NetHeader::header_defs.find(ptr_base_info.header_name);
                if (hdr_iter != NetHeader::header_defs.end()) {
                    std::vector<int> int_offs;
                    bool is_all_const = true;
                    for (int i = 1; i < op->oprands.size(); i++) {
                        auto &oprand = op->oprands[i];
                        if (oprand->is_constant) {
                            int_offs.push_back(oprand->const_val);
                        } else {
                            is_all_const = false;
                        }
                    }

                    if (is_all_const) {
                        PipeIR::VarType *result_t;
                        auto off = op->oprands[0]->type->offset_from_gep_offset(int_offs, &result_t);

                        auto hdr_num_bytes = NetHeader::get_hdr_total_bytes(hdr_iter->second);

                        auto f_entry = NetHeader::find_field_by_off(hdr_iter->second, off);
                        if (std::get<1>(f_entry) > 0) {
                            result = ptr_base_info;
                            result.field_name = std::get<0>(f_entry);
                        }
                    }
                }
            } else if (ptr_base_info.is_stack_ptr) {
                // only allow constant offset
                bool all_const = true;
                for (int i = 1; i < op->oprands.size(); i++) {
                    auto &off = op->oprands[i];
                    if (!off->is_constant) {
                        all_const = false;
                        break;
                    }
                }
                if (all_const) {
                    // we assume llvm will generate in bound access
                    result.is_stack_ptr = true;
                }
            }
        } else if (op->type == OpT::ALLOC_TMP) {
            result.is_stack_ptr = true;
        } else if (op->type == OpT::STATE_OP) {
            auto op_name = op->state_op_name;
            if (op_name.find("Packet::") != op_name.npos
                || op_name.find("WritablePacket::") != op_name.npos) {
                auto pkt_obj = op->oprands[0];
                result.pkt_obj = pkt_obj;
                v->print(std::cout);
                std::cout << " :: Packet method: " << op_name << std::endl;
                if (op_name == "Packet::uniqueify") {
                    result.is_pkt_obj = true;
                } else if (op_name == "WritablePacket::ip_header const") {
                    result.is_pkt_hdr_ptr = true;
                    result.header_name = "ipv4";
                    result.field_name = "";
                } else if (op_name == "WritablePacket::transport_header const") {
                    result.is_pkt_hdr_ptr = true;
                    result.header_name = "tcp";
                    result.field_name = "";
                } else if (op_name == "Packet::ip_header const") {
                    result.is_pkt_hdr_ptr = true;
                    result.header_name = "ipv4";
                    result.field_name = "";
                } else if (op_name == "Packet::transport_header const") {
                    result.is_pkt_hdr_ptr = true;
                    result.header_name = "tcp";
                    result.field_name = "";
                }
            }

            if (op_name == "HashMap::findp const") {
                result.is_stack_ptr = true;
            }
        }

    out:
        ctx.cache.insert({v, result});
        return result;
    }

    PASS_IMPL(PipePktOpRw, s) {
        // perform pointer analysis over the pipeir operations
        // replace load/store with packet operations

        PktPtrTraceCtx trace_ctx;
        trace_ctx.pass_ctx = s.get();

        // initialize packet object
        assert(s->funcs.find(s->entry_name) != s->funcs.end());
        auto &entry_f = s->funcs[s->entry_name];
        PktPtrInfo pkt_obj_info;
        pkt_obj_info.is_pkt_obj = true;
        std::shared_ptr<PipeIR::Var> pkt_obj_var;
        if (entry_f->params_.size() == 2) {
            // simple_action
            pkt_obj_var = entry_f->params_[1];
        } else if (entry_f->params_.size() == 3) {
            // push
            pkt_obj_var = entry_f->params_[2];
        } else {
            assert(false && "unknown entry func");
        }
        pkt_obj_info.pkt_obj = pkt_obj_var;
        trace_ctx.cache.insert({pkt_obj_var.get(), pkt_obj_info});

        PktPtrInfo ele_obj_info;
        ele_obj_info.is_element_ptr = true;
        ele_obj_info.element_obj = entry_f->params_[0];
        trace_ctx.cache.insert({entry_f->params_[0].get(), ele_obj_info});

        // for all packet operation, remove packet pointer gep
        for (auto &f_kv : s->funcs) {
            auto f_ptr = f_kv.second.get();
            for (auto &stage_kv : f_ptr->bbs_) {
                auto bb_ptr = stage_kv.second.get();
                for (int i = 0; i < bb_ptr->ops.size(); i++) {
                    auto op_ptr = bb_ptr->ops[i].get();
                    using OpT = PipeIR::Operation::Type;
                    if (op_ptr->type == OpT::STATE_OP) {
                        auto op_name = op_ptr->state_op_name;
                        if (str_begin_with(op_name, "Packet::")
                            || str_begin_with(op_name, "WritablePacket::")) {
                            if (op_ptr->oprands.size() >= 1) {
                                std::cout << *op_ptr << std::endl;
                                auto info = find_pkt_ptr_info(op_ptr->oprands[0].get(), trace_ctx);
                                if (info.is_pkt_obj) {
                                    op_ptr->oprands[0] = info.pkt_obj;
                                }
                            }
                        }
                    }
                }
            }
        }

        for (auto &f_kv : s->funcs) {
            auto f_ptr = f_kv.second.get();
            for (auto &stage_kv : f_ptr->bbs_) {
                auto bb_ptr = stage_kv.second.get();
                for (int i = 0; i < bb_ptr->ops.size(); i++) {
                    auto op_ptr = bb_ptr->ops[i].get();
                    using OpT = PipeIR::Operation::Type;
                    if (op_ptr->type == OpT::LOAD
                        || op_ptr->type == OpT::STORE) {
                        // trace pointer
                        auto ptr_var = op_ptr->get_load_store_pointer();
                        auto reg_info = find_pkt_ptr_info(ptr_var.get(), trace_ctx);

                        if (reg_info.is_pkt_hdr_ptr && !reg_info.have_offset) {
                            // change this instruction into a packet header read / write
                            auto new_op = std::make_unique<PipeIR::Operation>();
                            new_op->type = (op_ptr->type == OpT::LOAD) ? OpT::PKTHDR_R : OpT::PKTHDR_W;
                            for (auto &v : op_ptr->dst_var) {
                                new_op->dst_var.push_back(v);
                            }
                            new_op->oprands.clear();
                            new_op->oprands.push_back(reg_info.pkt_obj);
                            new_op->header_name = reg_info.header_name;
                            if (reg_info.field_name == "") {
                                // get first header field
                                auto &fields = NetHeader::header_defs.find(reg_info.header_name)->second;
                                reg_info.field_name = std::get<0>(fields[0]);
                            }
                            new_op->field_name = reg_info.field_name;
                            int field_size = NetHeader::find_field_num_bytes(reg_info.header_name,
                                                                             reg_info.field_name);
                            PipeIR::VarType *ptr_t = ptr_var->type->ptr_pointee_type;
                            assert(ptr_t != nullptr);
                            if (ptr_t->type == PipeIR::VarType::T::INT
                                && ptr_t->int_bitwidth == field_size * 8) {
                                if (op_ptr->type == OpT::STORE) {
                                    new_op->oprands.push_back(op_ptr->oprands[1]);
                                }
                                std::cout << "replacing op " << *op_ptr << " --> "
                                          << *new_op << std::endl;
                                bb_ptr->ops[i].swap(new_op);
                            } else {
                                std::cerr << "field size mismatch : "
                                          << ptr_t->int_bitwidth << " vs "
                                          << field_size * 8 << " ";
                                ptr_var->print(std::cerr);
                                std::cerr << std::endl;
                            }
                        }
                    } else if (op_ptr->type == OpT::STATE_OP) {
                        auto op_name = op_ptr->state_op_name;
                        // if globalstate ptr is null, then try find out the state
                        bool should_try_find_state = false;
                        std::string new_op_name;
                        if (op_name == "Vector::operator[]") {
                            should_try_find_state = true;
                            new_op_name = "vector_idx";
                        } else if (op_name == "HashMap::findp const") {
                            should_try_find_state = true;
                            new_op_name = "hashmap_get";
                        }

                        /*
                        if (should_try_find_state) {
                            auto state_reg_info = find_pkt_ptr_info(op_ptr->oprands[0].get(), trace_ctx);
                            if (state_reg_info.is_element_state_ptr) {
                                auto &e = state_reg_info.possible_state_entry[0];
                                assert(e.type != Click::StateEntry::T::UNKNOWN);
                                assert(s->states.find(e.state_name) != s->states.end());
                                // remove the first element from oprands
                                op_ptr->oprands.erase(op_ptr->oprands.begin());
                            }
                        }
                        */

                        if (op_name == "Element::checked_output_push const") {
                            assert(op_ptr->oprands.size() == 3);
                            auto state_reg_info = find_pkt_ptr_info(op_ptr->oprands[0].get(), trace_ctx);
                            assert(state_reg_info.is_element_ptr);
                            op_ptr->oprands[0] = state_reg_info.element_obj;

                            auto pkt_reg_info = find_pkt_ptr_info(op_ptr->oprands[2].get(), trace_ctx);
                            assert(pkt_reg_info.is_pkt_obj);
                            op_ptr->oprands[2] = pkt_reg_info.pkt_obj;
                        }
                    }
                }
            }
        }

        /*
        for (auto &kv : trace_ctx.cache) {
            auto v_ptr = kv.first;
            auto &reg_info = kv.second;
            v_ptr->print(std::cout);
            std::cout << ": got info "
                        << "is pkt hdr: " << reg_info.is_pkt_hdr_ptr << " "
                        << "is pkt obj: " << reg_info.is_pkt_obj << " "
                        << "header : " << reg_info.header_name << " "
                        << "field : " << reg_info.field_name << std::endl;
        }
        */
        return s;
    }
}
