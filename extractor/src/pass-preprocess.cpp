#include "pass-preprocess.hpp"
#include "llvm-incl.hpp"
#include "headerdef.hpp"

using namespace NetHeader;
using namespace Target;

#define DEF_FUNC_REPLACER(f_name)                                       \
    std::vector<std::shared_ptr<Instruction>>                           \
    f_name(std::shared_ptr<CallInst> inst, TraceCtx &ctx)

namespace Morula {

    struct TraceCtx {
        std::unordered_map<std::string, RegInfo> cache;
        PassCtx &ctx;
    };

    DEF_FUNC_REPLACER(hashmap_findp) {
        auto this_reg = inst->args()[0];
        auto this_info = trace_reg(this_reg, ctx);
        // only translate hashmap operation of element state
        // we assume that findp is called on correct object
        std::cerr << "hashmap findp this: " << this_reg << " "
                  << this_info << std::endl;
        // replace with MapGetInst
        //auto new_inst = std::make_shared<MapGetInst>(inst->get_dst_reg(), this_reg, inst->args()[1], "");
        auto new_inst = std::make_shared<DataStructureOp>("map", "findp",
                                                          this_reg,
                                                          inst->get_dst_reg(),
                                                          std::vector<std::string>{inst->args()[1]});
        new_inst->llvm_inst_ptr_ = inst->llvm_inst_ptr_;
        return {new_inst};
    }

    DEF_FUNC_REPLACER(vector_idx_op) {
        auto this_reg = inst->args()[0];
        auto this_info = trace_reg(this_reg, ctx);
        auto idx_reg = inst->args()[1];
        std::cerr << "vector operator []: " << this_reg << " "
                  << this_info << std::endl;
        auto new_inst = std::make_shared<DataStructureOp>("vector", "operator[]",
                                                          this_reg,
                                                          inst->get_dst_reg(),
                                                          std::vector<std::string>{idx_reg});
        new_inst->llvm_inst_ptr_ = inst->llvm_inst_ptr_;
        return {new_inst};
    }

    DEF_FUNC_REPLACER(pkt_push) {
        auto port_reg = inst->args()[1];
        auto pkt_reg = inst->args()[2];
        auto new_inst = std::make_shared<EmitPktInst>(pkt_reg, port_reg);
        new_inst->llvm_inst_ptr_ = inst->llvm_inst_ptr_;
        return {new_inst};
    }

    using ReplacerFunc = std::function<BasicBlock::InstList(std::shared_ptr<CallInst>, TraceCtx &)>;

    static std::unordered_map<std::string, ReplacerFunc>
    func_replacer = {
        {"HashMap::findp const", hashmap_findp},
        {"Vector::operator[]", vector_idx_op},
        {"Element::checked_output_push const", pkt_push},
    };
    
    std::unique_ptr<PassCtx> ClickStateOp::pass_impl(std::unique_ptr<PassCtx> s) {
        TraceCtx ctx = {
            .cache = {},
            .ctx = *s,
        };

        ctx.cache.insert({"%0", RegInfo{true, 0, "self", "state"}});
        ctx.cache.insert({"%1", RegInfo{false, 0, "in_port", "int"}});
        ctx.cache.insert({"%2", RegInfo{true, 0, "input_pkt", "packet"}});
        for (auto &kv : s->blocks) {
            auto blk = kv.second;
            auto insts = blk->insts_mut();
            std::vector<std::shared_ptr<Instruction>> ns;
            for (int i = 0; i < insts.size(); i++) {
                bool replace = false;
                if (insts[i]->is_call()) {
                    auto call = std::dynamic_pointer_cast<Target::CallInst>(insts[i]);
                    auto func_name = call->func_name();
                    if (func_replacer.find(func_name) == func_replacer.end()) {
                        func_name = remove_template(func_name);
                    }
                    if (func_replacer.find(func_name) == func_replacer.end()) {
                        func_name = remove_func_args(func_name);
                    }
                    std::cerr << "try func replace : " << func_name << std::endl;
                    if (func_replacer.find(func_name) != func_replacer.end()) {
                        auto replacer = func_replacer.find(func_name)->second;
                        auto new_insts = replacer(call, ctx);
                        for (auto iter = new_insts.begin(); iter != new_insts.end(); iter++) {
                            if ((*iter)->llvm_inst_ptr_ == nullptr) {
                                (*iter)->llvm_inst_ptr_ = insts[i]->llvm_inst_ptr_;
                            }
                            ns.push_back(*iter);
                        }
                        replace = true;
                    }
                }

                if (!replace) {
                    ns.push_back(insts[i]);
                }
            }
            blk->set_insts(ns);
        }
        return s;
    }

    #define DEF_FUNC_HANDLER(f_name) RegInfo f_name(Target::CallInst *inst, TraceCtx &ctx)

    DEF_FUNC_HANDLER(w_pkt_ip_header) {
        RegInfo info;
        const auto &args = inst->args();
        auto pkt_info = trace_reg(args[0], ctx);
        info.is_pointer = true;
        info.var_name = pkt_info.var_name;
        info.reg_type = "click_ip";
        return info;
    }
    
    DEF_FUNC_HANDLER(pkt_trans_header) {
        RegInfo info;
        const auto &args = inst->args();
        auto pkt_info = trace_reg(args[0], ctx);
        info.is_pointer = true;
        info.var_name = pkt_info.var_name;
        info.reg_type = "click_transport";
        return info;
    }

    DEF_FUNC_HANDLER(uniqueify_pkt) {
        const auto &args = inst->args();
        auto pkt_info = trace_reg(args[0], ctx);
        return pkt_info;
    }

    DEF_FUNC_HANDLER(click_hashmap_get) {
        auto this_reg = inst->args()[0];
        auto this_info = trace_reg(this_reg, ctx);
        RegInfo info;
        info.is_pointer = true;
        info.pointer_offset = 0;
        info.var_name = this_reg;
        info.entry_name = inst->get_dst_reg();
        info.reg_type = "entry:map";
        return info;
    }

    std::unordered_map<std::string, std::function<RegInfo(Target::CallInst *, TraceCtx &)>>
    func_handlers = {
        {"WritablePacket::ip_header() const", w_pkt_ip_header},
        {"Packet::transport_header() const", pkt_trans_header},
        {"Packet::uniqueify()", uniqueify_pkt},
    };

    RegInfo analyze_func_ret(CallInst *inst,
                             TraceCtx &ctx) {
        RegInfo info;
        std::string func_name = "";
        bool demangled = cxx_demangle(inst->func_name(), func_name);
        if (!demangled) {
            func_name = inst->func_name();
        }
        
        if (func_handlers.find(func_name) != func_handlers.end()) {
            return func_handlers.find(func_name)->second(inst, ctx);
        }
        
        std::cout << "unknown func: " << func_name << std::endl;
        return info;
    }

    std::string header_struct_gep(const RegInfo &base_info,
                                  llvm::GetElementPtrInst *inst,
                                  const std::vector<int> &offsets,
                                  const std::vector<std::string> &offset_regs,
                                  const std::vector<std::tuple<std::string, int>> &fields,
                                  TraceCtx &ctx) {
        auto type = inst->getOperand(0)->getType();//inst->getSourceElementType();
        auto llvm_module = ctx.ctx.llvm_module.get();
        int off_val = 0;
        for (int i = 0; i < offsets.size(); i++) {
            assert(offsets[i] >= 0);
            if (type->isPointerTy()) {
                auto size = get_type_size(llvm_module, type->getPointerElementType());
                //std::cerr << "pointer " << size << " offset: " << offsets[i] << std::endl;
                off_val += offsets[i] * size;
                type = type->getPointerElementType();
            } else if (type->isStructTy()) {
                llvm::DataLayout *dl = new llvm::DataLayout(llvm_module);
                const llvm::StructLayout* sl = dl->getStructLayout(static_cast<llvm::StructType *>(type));
                auto off = sl->getElementOffset(offsets[i]);
                //std::cerr << "struct " << off << std::endl;
                type = type->getStructElementType(offsets[i]);
                off_val += off;
            } else if (type->isArrayTy()) {
                auto size = get_type_size(llvm_module, type->getArrayElementType());
                //std::cerr << "array " << size << std::endl;
                off_val += offsets[i] * size;
                type = type->getArrayElementType();
            }
        }

        int field_off = 0;
        bool found = false;
        for (auto &t : fields) {
            auto &field_name = std::get<0>(t);
            auto &size = std::get<1>(t);
            if (off_val == field_off) {
                return field_name;
            }
            field_off += size;
        }
        std::cerr << "could not find field for offset: " << off_val << std::endl;
        assert(false);
    }

    RegInfo handle_gep(llvm::GetElementPtrInst *gep_inst, TraceCtx &ctx) {
        // Get Element Ptr:
        //   1) get the info for the base pointer
        //   2) walk through the struct (recursive)
        auto base_name = get_llvm_name(*gep_inst->getPointerOperand());
        auto base_info = trace_reg(base_name, ctx);
        auto ptr_type = gep_inst->getSourceElementType();
        auto llvm_module = ctx.ctx.llvm_module.get();

        // perform a walk through for the offset, only allow register or constant as offset
        std::vector<int> offsets;
        std::vector<std::string> offset_regs;
        for (int i = 1; i < gep_inst->getNumOperands(); i++) {
            auto v = gep_inst->getOperand(i);
            int o = 0;
            if (const llvm::ConstantInt* CI = llvm::dyn_cast<llvm::ConstantInt>(v)) {
                offsets.push_back(get_llvm_int_val(v));
                offset_regs.push_back("");
            } else {
                offsets.push_back(-1);
                offset_regs.push_back(get_llvm_name(*v));
            }
        }

        RegInfo info;
        // walk through the gep
        if (base_info.reg_type == "packet_obj") {
            // this pointer is a pointer to click packet object
            // TODO: handle gep on click packet object
        } else if (base_info.reg_type == "click_ip") {
            auto field_name = header_struct_gep(info, gep_inst, offsets, offset_regs, ip_field_sizes, ctx);
            info.reg_type = "field_value:click_ip." + field_name;
            info.is_pointer = true;
            info.var_name = base_info.var_name;
        } else if (base_info.reg_type == "click_transport") {
            /* "click_transport" is a common one for TCP and UDP,
             * we know that the first two fields are source and destination ports
             */
            auto field_name = header_struct_gep(info, gep_inst, offsets, offset_regs, transport_field_sizes, ctx);
            info.reg_type = "field_value:click_transport." + field_name;
            info.is_pointer = true;
            info.var_name = base_info.var_name;
        } else {
            // just calculate the offset
            auto type = gep_inst->getOperand(0)->getType();//inst->getSourceElementType();
            int off_val = 0;
            for (int i = 0; i < offsets.size(); i++) {
                if (offsets[i] < 0) {
                    off_val = -1;
                    break;
                }
                if (type->isPointerTy()) {
                    auto size = get_type_size(llvm_module, type->getPointerElementType());
                    //std::cerr << "pointer " << size << " offset: " << offsets[i] << std::endl;
                    off_val += offsets[i] * size;
                    type = type->getPointerElementType();
                } else if (type->isStructTy()) {
                    llvm::DataLayout *dl = new llvm::DataLayout(llvm_module);
                    const llvm::StructLayout* sl = dl->getStructLayout(static_cast<llvm::StructType *>(type));
                    auto off = sl->getElementOffset(offsets[i]);
                    //std::cerr << "struct " << off << std::endl;
                    type = type->getStructElementType(offsets[i]);
                    off_val += off;
                } else if (type->isArrayTy()) {
                    auto size = get_type_size(llvm_module, type->getArrayElementType());
                    //std::cerr << "array " << size << std::endl;
                    off_val += offsets[i] * size;
                    type = type->getArrayElementType();
                }
            }
            info = base_info;
            info.pointer_offset = off_val;
        }

        return info;
    }

    std::string get_entry_name(const DataStructureOp &op) {
        auto ds_type = op.data_structure_type();
        auto op_name = op.get_op();
        if (ds_type == "map") {
            if (op_name == "findp") {
                return op.get_dst_reg();
            }
        } else if (ds_type == "vector") {
            if (op_name == "operator[]") {
                return op.get_dst_reg();
            }
        }
        return "";
    }

    RegInfo trace_reg(const std::string &reg, TraceCtx &ctx) {
        if (ctx.cache.find(reg) != ctx.cache.end()) {
            return ctx.cache.find(reg)->second;
        } else {
            RegInfo info;
            assert(ctx.ctx.var_source.find(reg) != ctx.ctx.var_source.end());
            auto inst = ctx.ctx.get_inst(ctx.ctx.var_source.find(reg)->second);
            if (inst->is_llvm_inst()) {
                auto llvm_i = std::dynamic_pointer_cast<Target::LLVMInst>(inst);
                if (auto gep_inst = llvm::dyn_cast<llvm::GetElementPtrInst>(llvm_i->get_inst())) {
                    info = handle_gep(gep_inst, ctx);
                } else if (auto cast_inst = llvm::dyn_cast<llvm::BitCastInst>(llvm_i->get_inst())) {
                    llvm::Type *src_type = cast_inst->getSrcTy();
                    llvm::Type *dst_type = cast_inst->getDestTy();
                    assert(src_type->isPointerTy() && dst_type->isPointerTy());
                    auto src_reg = get_llvm_name(*cast_inst->getOperand(0));
                    info = trace_reg(src_reg, ctx);
                }
            } else if (inst->is_call()) {
                auto call = std::dynamic_pointer_cast<Target::CallInst>(inst);
                info = analyze_func_ret(call.get(), ctx);
            } else if (inst->is_alloca()) {
                info.reg_type = "alloca";
            } else if (inst->is_phi()) {
                auto phi = std::dynamic_pointer_cast<Target::PhiInst>(inst);
                const auto &vals = phi->vals();
                //std::cerr << "phi num of incoming: " << vals.size() << std::endl;
                for (auto val_i = vals.begin(); val_i != vals.end(); val_i++) {
                    auto from_bb = val_i->first;
                    auto reg_name = val_i->second;
                    auto reg_info = trace_reg(reg_name, ctx);
                    //std::cerr << "phi pointer: " << from_bb << " -> " << reg_info << std::endl;
                }
            } else if (inst->is_map_get()) {
                //std::cerr << "load/store of map-get result" << std::endl;
                // if this is a MapGetInst, then the return value should be an "entry"
                auto ptr = std::dynamic_pointer_cast<MapGetInst>(inst);
                auto map_reg = ptr->map_reg();
                info.is_pointer = true;
                info.pointer_offset = 0;
                info.var_name = map_reg;
                info.reg_type = "entry:map";
            } else if (inst->is_data_structure_op()) {
                auto ptr = std::dynamic_pointer_cast<DataStructureOp>(inst);
                auto ds_type = ptr->data_structure_type();
                auto op = ptr->get_op();
                auto obj = ptr->obj_reg();
                const auto &args = ptr->args();
                info.is_pointer = true;
                info.pointer_offset = 0;
                info.var_name = obj;
                info.entry_name = get_entry_name(*ptr);
                info.reg_type = "entry:" + ds_type;
            }
        ret:
            ctx.cache.insert({reg, info});
            //std::cerr << "got info: " << info << std::endl;
            return info;
        }
    }

    class PktLLVMVisitor : public llvm::InstVisitor<PktLLVMVisitor> {
    public:
        TraceCtx &ctx;
        RegInfo reg_info;
        bool traced = false;

        std::vector<std::shared_ptr<Instruction>> new_insts;

        PktLLVMVisitor(TraceCtx &c): ctx(c) {
            new_insts.clear();
        }

        void visitInstruction(const llvm::Instruction &inst) {
        }

        void visitLoadInst(const llvm::LoadInst &inst) {
            auto ptr_name = get_llvm_name(*inst.getOperand(0));
            auto dst_name = get_llvm_name(inst);
            reg_info = trace_reg(ptr_name, ctx);
            traced = true;
            std::string header_name;
            std::string field_name;
            bool replace = false;
 
            if (str_begin_with(reg_info.reg_type, "field_value:")) {
                auto field_str = reg_info.reg_type.substr(std::string("field_value:").length());
                auto dot_pos = field_str.find(".");
                header_name = field_str.substr(0, dot_pos);
                field_name = field_str.substr(dot_pos + 1);
                replace = true;
                // std::cerr << "load swaped to: ";
                // new_inst->print(std::cerr);
                // std::cerr << std::endl;
            } else if (header_defs.find(reg_info.reg_type) != header_defs.end()) {
                auto &header_info = header_defs.find(reg_info.reg_type)->second;
                bool found = false;
                int off = 0;
                auto load_size = get_type_size(ctx.ctx.llvm_module.get(),
                                               inst.getPointerOperandType()->getPointerElementType());
                std::string load_field = "";
                for (auto &t : header_info) {
                    std::string field_name = std::get<0>(t);
                    int field_size = std::get<1>(t);
                    if (off == reg_info.pointer_offset && field_size == load_size) {
                        found = true;
                        load_field = field_name;
                    }
                    off += field_size;
                }

                if (found) {
                    header_name = reg_info.reg_type;
                    field_name = load_field;
                    replace = true;
                    // std::cerr << "load swaped to: ";
                    // new_inst->print(std::cerr);
                    // std::cerr << std::endl;
                }
            }

            if (replace) {
                auto new_inst = std::make_shared<Target::HeaderReadInst>(dst_name, 
                                                                         reg_info.var_name,
                                                                         header_name, field_name);
                new_inst->llvm_inst_ptr_ = &inst;
                new_insts.push_back(new_inst);
            }
        }

        void visitStoreInst(const llvm::StoreInst &inst) {
            auto ptr_name = get_llvm_name(*inst.getOperand(1));
            auto val_name = get_llvm_name(*inst.getOperand(0));
            reg_info = trace_reg(ptr_name, ctx);
            traced = true;
            bool replace = false;
            std::string header_name;
            std::string field_name;
            if (str_begin_with(reg_info.reg_type, "field_value:")) {
                auto field_str = reg_info.reg_type.substr(std::string("field_value:").length());
                auto dot_pos = field_str.find(".");
                header_name = field_str.substr(0, dot_pos);
                field_name = field_str.substr(dot_pos + 1);
                replace = true;
            } else if (header_defs.find(reg_info.reg_type) != header_defs.end()) {
                auto &header_info = header_defs.find(reg_info.reg_type)->second;
                bool found = false;
                int off = 0;
                auto ptr_type = inst.getPointerOperandType();
                auto load_size = get_type_size(ctx.ctx.llvm_module.get(),
                                               ptr_type->getPointerElementType());
                std::string store_field = "";
                for (auto &t : header_info) {
                    std::string field_name = std::get<0>(t);
                    int field_size = std::get<1>(t);
                    if (off == reg_info.pointer_offset && field_size == load_size) {
                        found = true;
                        store_field = field_name;
                    }
                    off += field_size;
                }

                if (found) {
                    header_name = reg_info.reg_type;
                    field_name = store_field;
                    replace = true;
                }
            }

            if (replace) {
                auto new_inst = std::make_shared<Target::HeaderWriteInst>(reg_info.var_name,
                                                                          header_name,
                                                                          field_name, val_name);
                new_inst->llvm_inst_ptr_ = &inst;
                new_insts.push_back(new_inst);
            }
        }
    };
    
    std::unique_ptr<PassCtx> ClickPktOp::pass_impl(std::unique_ptr<PassCtx> s) {
        /* 
         * type signature of click's "push" method
         * void push(Element *this, int in_port, Packet *pkt);
         */
        
        // For each load and store, we check if it is accessing a packet field

        TraceCtx ctx = {
            .cache = {},
            .ctx = *s,
        };

        ctx.cache.insert({"%0", RegInfo{true, 0, "self", "state"}});
        ctx.cache.insert({"%1", RegInfo{false, 0, "in_port", "int"}});
        ctx.cache.insert({"%2", RegInfo{true, 0, "input_pkt", "packet"}});

        for (auto &kv : s->blocks) {
            auto blk = kv.second;
            auto insts = blk->insts_mut();
            std::vector<std::shared_ptr<Instruction>> ns;
            for (int i = 0; i < insts.size(); i++) {
                InstID id{kv.first, i};
                auto inst = insts[i];
                bool replace = false;
                if (inst->is_llvm_inst()) {
                    PktLLVMVisitor visitor(ctx);
                    visitor.visit(*std::dynamic_pointer_cast<LLVMInst>(inst)->get_inst());
                    if (visitor.new_insts.size() > 0) {
                        for (auto n_i : visitor.new_insts) {
                            ns.push_back(n_i);
                        }
                        replace = true;
                    }
                }
                
                if (!replace) {
                    ns.push_back(inst);
                }
            }
            blk->set_insts(ns);
        }
        
        return s;
    }

    PASS_IMPL(RewriteEntryOp, s) {
        TraceCtx ctx = {
            .cache = {},
            .ctx = *s,
        };
        for (auto &kv : s->blocks) {
            auto &insts = kv.second->insts_mut();
            for (int i = 0; i < insts.size(); i++) {
                // here we only care about load or store
                InstID id{kv.first, i};
                if (!insts[i]->is_llvm_inst()) {
                    continue;
                }
                auto llvm = std::dynamic_pointer_cast<LLVMInst>(insts[i]);
                auto llvm_inst = llvm->get_inst();
                /* Now trace the pointer register.
                 * If we find the pointer originated from a map get,
                 * then we know that this instruction is a write to a map entry
                 */
                if (auto load = llvm::dyn_cast<llvm::LoadInst>(llvm_inst)) {
                    auto src_name = get_llvm_name(*load->getOperand(0));
                    RegInfo info = trace_reg(src_name, ctx);
                    if (str_begin_with(info.reg_type, "entry")) {
                        std::cerr << "found entry load: " << id
                                  << " " << info.pointer_offset
                                  << std::endl;
                        auto new_inst = std::make_shared<EntryReadInst>(insts[i]->get_dst_reg(),
                                                                        info.entry_name,
                                                                        info.pointer_offset);
                        new_inst->llvm_inst_ptr_ = load;
                        insts[i] = new_inst;
                    }
                } else if (auto store = llvm::dyn_cast<llvm::StoreInst>(llvm_inst)) {
                    auto dst_name = get_llvm_name(*store->getOperand(1));
                    auto val_name = get_llvm_name(*store->getOperand(0));
                    RegInfo info = trace_reg(dst_name, ctx);
                    if (str_begin_with(info.reg_type, "entry")) {
                        std::cerr << "found entry write: " << id << std::endl;
                        auto new_inst = std::make_shared<EntryWriteInst>(info.entry_name,
                                                                         info.pointer_offset,
                                                                         val_name);
                        new_inst->llvm_inst_ptr_ = store;
                        insts[i] = new_inst;
                    }
                }
            }
        }
        return s;
    }
}

std::ostream &operator<<(std::ostream &os, const Morula::RegInfo &info) {
    os << "RegInfo {is_pointer : " << info.is_pointer
       << ", pointer_offset : " << info.pointer_offset
       << ", var_name : " << info.var_name
       << ", reg_type : " << info.reg_type
       << "}";
    return os;
}
