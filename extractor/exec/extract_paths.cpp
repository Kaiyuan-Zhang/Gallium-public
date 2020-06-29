#include <iostream>
#include <fstream>
#include <unordered_map>
#include <unordered_set>
#include <queue>
#include "llvm-incl.hpp"
#include "target-lang.hpp"
#include "target-codegen.hpp"
#include "target-partition.hpp"
#include "utils.hpp"
#include "placer.hpp"
#include "opt-pass.hpp"
#include "headerdef.hpp"
#include <cxxabi.h>

using namespace NetHeader;

class TranslationCtx {
public:
    TranslationCtx(NameFactory &name_gen): name_gen_(name_gen) {}

    std::unordered_map<std::string, Target::BasicBlock *> blocks_;
    std::vector<std::shared_ptr<Target::Instruction>> insts_;
    std::string block_in_construction_;
    NameFactory &name_gen_;
};


class RegisterInfo {
public:
    bool is_pointer = false;
    int pointer_offset = 0;
    std::string var_name;
    std::string reg_type;

    RegisterInfo() {}
    RegisterInfo(bool a1, int a2, const std::string &a3, const std::string &a4):
        is_pointer(a1),
        pointer_offset(a2),
        var_name(a3),
        reg_type(a4) {
    }
};

std::ostream &operator<<(std::ostream &os, const RegisterInfo &info) {
    os << "RegisterInfo {is_pointer : " << info.is_pointer
       << ", pointer_offset : " << info.pointer_offset
       << ", var_name : " << info.var_name
       << ", reg_type : " << info.reg_type
       << "}";
    return os;
}

class AnalyzeCtx {
public:
    std::unordered_map<std::string, std::shared_ptr<Target::Instruction>> reg_inst;
    std::unordered_map<std::string, RegisterInfo> reg_cache;

    llvm::Module *module;
};

int64_t get_int_val(const llvm::Value *value) {
    if (const llvm::ConstantInt* CI = llvm::dyn_cast<llvm::ConstantInt>(value)) {
        if (CI->getBitWidth() <= 64) {
            return CI->getSExtValue();
        }
    }
    assert(false && "not an integer constant");
    throw "not an integer constant";
}

class InstVisitor : public llvm::InstVisitor<InstVisitor> {
public:
    InstVisitor(llvm::Module &module,
                TranslationCtx &ctx) : m_(module),
                                       ctx_(ctx) {}

    void visitInstruction(const llvm::Instruction &inst) {
        auto new_inst = std::make_shared<Target::LLVMInst>(inst);
        ctx_.insts_.push_back(new_inst);
    }

    void visitReturnInst(const llvm::ReturnInst &inst) {
        assert(inst.getNumOperands() <= 1);
        std::string ret_val = "";
        if (inst.getNumOperands() == 1) {
            ret_val = get_llvm_name(*inst.getOperand(0));
        }
        auto target_i = std::make_shared<Target::ReturnInst>(ret_val);
        ctx_.insts_.push_back(target_i);
        auto block = new Target::BasicBlock(ctx_.block_in_construction_, ctx_.insts_);
        ctx_.insts_.clear();
        ctx_.blocks_.insert({ctx_.block_in_construction_, block});
    }

    void visitBranchInst(const llvm::BranchInst &inst) {
        auto new_block = new Target::BasicBlock(ctx_.block_in_construction_, ctx_.insts_);
        if (inst.isConditional()) {
            auto cond_reg = get_llvm_name(*inst.getCondition());
            auto t_target = "bb_" + get_llvm_name(*inst.getSuccessor(0));
            auto f_target = "bb_" + get_llvm_name(*inst.getSuccessor(1));
            new_block->add_branch(cond_reg, t_target, f_target);
        } else {
            auto target_bb = "bb_" + get_llvm_name(*inst.getSuccessor(0));
            new_block->add_next(target_bb);
        }
        ctx_.blocks_.insert({new_block->get_name(), new_block});
        ctx_.insts_.clear();
    }

    void visitSwitchInst(const llvm::SwitchInst &inst) {
        auto switch_reg = get_llvm_name(*inst.getCondition());
        auto switch_reg_t = inst.getCondition()->getType();
        Target::BasicBlock *block = nullptr;
        std::string target_bb;
        std::string cond_reg;
        for (auto iter = inst.case_begin(); iter != inst.case_end(); iter++) {
            if (block != nullptr) {
                block->add_branch(cond_reg, target_bb, ctx_.block_in_construction_);
                ctx_.blocks_.insert({block->get_name(), block});
            }
            auto &c = *iter;
            auto val = c.getCaseValue()->getSExtValue();
            target_bb = "bb_" + get_llvm_name(*c.getCaseSuccessor());
            auto const_reg = ctx_.name_gen_("const_tmp");
            using Op = Target::ArithInst::Op;
            auto const_inst = std::make_shared<Target::ArithInst>(const_reg, Op::CONST_VAL,
                                                                  std::vector<std::string>{std::to_string(val)});
            const_inst->dst_type_anno = switch_reg_t;
            ctx_.insts_.push_back(const_inst);
            cond_reg = ctx_.name_gen_("switch_cond");
            auto cmp_inst = std::make_shared<Target::ArithInst>(cond_reg, Op::EQ,
                                                                std::vector<std::string>{switch_reg, const_reg});
            auto next_bb = ctx_.name_gen_("switch_bb");
            ctx_.insts_.push_back(cmp_inst);
            block = new Target::BasicBlock(ctx_.block_in_construction_, ctx_.insts_);
            ctx_.insts_.clear();
            ctx_.block_in_construction_ = next_bb;
            ctx_.blocks_.insert({block->get_name(), block});
        }
        auto default_bb = "bb_" + get_llvm_name(*inst.getDefaultDest());
        assert(block != nullptr);
        block->add_branch(cond_reg, target_bb, default_bb);
        ctx_.block_in_construction_ = default_bb;
        ctx_.blocks_.insert({block->get_name(), block});
    }

    void visitSelectInst(const llvm::SelectInst &inst) {
        auto dst_reg = get_llvm_name(inst);
        auto cond_reg = get_llvm_name(*inst.getCondition());
        auto t_reg = get_llvm_name(*inst.getTrueValue());
        auto f_reg = get_llvm_name(*inst.getFalseValue());
        auto blk_name_base = ctx_.name_gen_("select");
        auto t_block = new Target::BasicBlock(blk_name_base + "_t_block", {});
        auto f_block = new Target::BasicBlock(blk_name_base + "_f_block", {});
        auto next_bb = blk_name_base + "_after";

        t_block->add_next(next_bb);
        f_block->add_next(next_bb);
        auto curr_block = new Target::BasicBlock(ctx_.block_in_construction_, ctx_.insts_);
        ctx_.insts_.clear();
        curr_block->add_branch(cond_reg, t_block->get_name(), f_block->get_name());
        ctx_.blocks_.insert({curr_block->get_name(), curr_block});
        ctx_.blocks_.insert({t_block->get_name(), t_block});
        ctx_.blocks_.insert({f_block->get_name(), f_block});


        std::unordered_map<std::string, std::string> phi_vals =
            {{t_block->get_name(), t_reg},
             {f_block->get_name(), f_reg}};

        auto phi_inst = std::make_shared<Target::PhiInst>(dst_reg, phi_vals);
        ctx_.insts_.push_back(phi_inst);
        ctx_.block_in_construction_ = next_bb;
    }

    void visitPHINode(const llvm::PHINode &inst) {
        auto dst_reg = get_llvm_name(inst);
        std::unordered_map<std::string, std::string> vals;
        for (auto i = 0; i < inst.getNumIncomingValues(); i++) {
            auto bb = get_llvm_name(*inst.getIncomingBlock(i));
            auto val_reg = get_llvm_name(*inst.getIncomingValue(i));
            vals.insert({bb, val_reg});
        }
        ctx_.insts_.push_back(std::make_shared<Target::PhiInst>(dst_reg, vals));
    }

    // void visitICmpInst(const llvm::ICmpInst &inst) {
    //     auto dst_reg = get_llvm_name(inst);
    //     using P = llvm::CmpInst::Predicate;
    //     auto predicate = inst.getPredicate();
    //     auto oprand1 = get_llvm_name(*inst.getOperand(0));
    //     auto oprand2 = get_llvm_name(*inst.getOperand(1));
    //     using Op = Target::ArithInst::Op;
    //     Op op;
    //     switch (predicate) {
    //     case P::ICMP_EQ:
    //         op = Op::EQ;
    //         break;
    //     case P::ICMP_NE:
    //         op = Op::NE;
    //         break;
    //     case P::ICMP_SLE:
    //         op = Op::SLE;
    //         break;
    //     case P::ICMP_SLT:
    //         op = Op::SLT;
    //         break;
    //     case P::ICMP_SGE:
    //         op = Op::SGE;
    //         break;
    //     case P::ICMP_SGT:
    //         op = Op::SGT;
    //         break;
    //     case P::ICMP_ULE:
    //         op = Op::ULE;
    //         break;
    //     case P::ICMP_ULT:
    //         op = Op::ULT;
    //         break;
    //     case P::ICMP_UGE:
    //         op = Op::UGE;
    //         break;
    //     case P::ICMP_UGT:
    //         op = Op::UGT;
    //         break;
    //     default:
    //         assert(false && "unsupported icmp");
    //     }
    //     auto new_inst = new Target::ArithInst(dst_reg, op, {oprand1, oprand2});
    //     ctx_.insts_.push_back(new_inst);
    // }

    void visitAllocaInst(const llvm::AllocaInst &inst) {
        // Ignoring this for now
        /* plans:
         *   1) change it into registers
         *   2) add alloca instruction in target lang
         */
        auto dst_reg = get_llvm_name(inst);
        const llvm::Value *val = inst.getArraySize();
        int64_t size64 = get_int_val(val);
        int size = (int)size64;
        auto type = inst.getAllocatedType();
        auto type_str = get_llvm_type_str(*type);
        auto new_inst = std::make_shared<Target::AllocaInst>(dst_reg, type_str, size);
        ctx_.insts_.push_back(new_inst);
    }
    
    void visitCallInst(const llvm::CallInst &inst) {
        int num_args = inst.getNumArgOperands();
        llvm::Function* fp = inst.getCalledFunction();
        std::string func_name;
        if (fp==NULL) {
            const llvm::Value* v = inst.getCalledValue();
            const llvm::Value* sv = v->stripPointerCasts();
            llvm::StringRef fname = sv->getName();
            //llvm::errs() << "indirect call? " << fname << "\n";
            func_name = fname.str();
        } else {
            func_name = fp->getName().str();
        }

        // TODO: filter out llvm internal functions
        if (inst.isInlineAsm()) {
            llvm::errs() << "got inline asm\n";
            auto asm_val = inst.getCalledValue();
            if (const llvm::InlineAsm* asm_inst = llvm::dyn_cast<llvm::InlineAsm>(asm_val)) {
                auto asm_str = asm_inst->getAsmString();
                llvm::errs() << "got asm pointer\n";
                llvm::errs() << asm_str << " ";
                // Now give a list of known asms, assert(false) if no match
                if (str_begin_with(asm_str, "rorw")) {
                    func_name = "llvm.bswap.i16";
                } else {
                    throw "Unknown asm";
                }
            }
        }

        std::string dst_reg = "";
        if (inst.getType()->getTypeID() != llvm::Type::TypeID::VoidTyID) {
            dst_reg = get_llvm_name(inst);
        }
        std::vector<std::string> args;
        for (int i = 0; i < num_args; i++) {
            auto arg = get_llvm_name(*inst.getArgOperand(i));
            args.push_back(arg);
        }

        if (func_name == "__assert_fail") {
            args.clear();
        }
        auto new_inst = std::make_shared<Target::CallInst>(dst_reg, func_name, args);
        new_inst->llvm_inst_ptr_ = &inst;
        ctx_.insts_.push_back(new_inst);
    }
    
protected:
    llvm::Module &m_;
    TranslationCtx &ctx_;
};


RegisterInfo trace_pointer(const std::string &reg_name, AnalyzeCtx &ctx);


#define DEF_FUNC_HANDLER(f_name) RegisterInfo f_name(Target::CallInst *inst, AnalyzeCtx &ctx)

DEF_FUNC_HANDLER(w_pkt_ip_header) {
    RegisterInfo info;
    const auto &args = inst->args();
    auto pkt_info = trace_pointer(args[0], ctx);
    info.is_pointer = true;
    info.var_name = pkt_info.var_name;
    info.reg_type = "click_ip";
    return info;
}

DEF_FUNC_HANDLER(pkt_trans_header) {
    RegisterInfo info;
    const auto &args = inst->args();
    auto pkt_info = trace_pointer(args[0], ctx);
    info.is_pointer = true;
    info.var_name = pkt_info.var_name;
    info.reg_type = "click_transport";
    return info;
}

DEF_FUNC_HANDLER(uniqueify_pkt) {
    const auto &args = inst->args();
    auto pkt_info = trace_pointer(args[0], ctx);
    return pkt_info;
}


std::unordered_map<std::string, std::function<RegisterInfo(Target::CallInst *, AnalyzeCtx &)>>
func_handlers = {
    {"WritablePacket::ip_header() const", w_pkt_ip_header},
    {"Packet::transport_header() const", pkt_trans_header},
    {"Packet::uniqueify()", uniqueify_pkt},
};


#define DEF_FUNC_REPLACER(f_name) std::vector<std::shared_ptr<Target::Instruction>> f_name(std::shared_ptr<Target::CallInst> inst, AnalyzeCtx &ctx)


DEF_FUNC_REPLACER(hashmap_findp) {
    auto this_reg = inst->args()[0];
    auto this_info = trace_pointer(this_reg, ctx);
    // only translate hashmap operation of element state
    // we assume that findp is called on correct object
    std::cerr << "hashmap findp this: " << this_reg << " " << this_info << std::endl;
    // replace with MapGetInst
    auto new_inst = std::make_shared<Target::MapGetInst>(inst->get_dst_reg(), this_reg, inst->args()[1], "");
    return {new_inst};
}

using ReplacerFunc = std::function<Target::BasicBlock::InstList(std::shared_ptr<Target::CallInst>, AnalyzeCtx &)>;

std::unordered_map<std::string, ReplacerFunc>
func_replacer = {
    {"HashMap::findp const", hashmap_findp},
};


RegisterInfo analyze_func_ret(Target::CallInst *inst,
                              AnalyzeCtx &ctx) {
    RegisterInfo info;
    size_t size = 0;
    int status = 0;
    char *n = abi::__cxa_demangle(inst->func_name().c_str(), NULL, &size, &status);
    std::string func_name = "";
    if (n != NULL) {
        func_name = std::string(n);
    }

    if (func_handlers.find(func_name) != func_handlers.end()) {
        return func_handlers.find(func_name)->second(inst, ctx);
    }

    std::cout << "unknown func: " << func_name << std::endl;
    
    if (n != NULL) {
        free(n);
    }
    return info;
}


std::string header_struct_gep(const RegisterInfo &base_info,
                              llvm::GetElementPtrInst *inst,
                              const std::vector<int> &offsets,
                              const std::vector<std::string> &offset_regs,
                              const std::vector<std::tuple<std::string, int>> &fields,
                              AnalyzeCtx &ctx) {
    auto type = inst->getOperand(0)->getType();//inst->getSourceElementType();
    int off_val = 0;
    for (int i = 0; i < offsets.size(); i++) {
        assert(offsets[i] >= 0);
        if (type->isPointerTy()) {
            auto size = get_type_size(ctx.module, type->getPointerElementType());
            //std::cerr << "pointer " << size << " offset: " << offsets[i] << std::endl;
            off_val += offsets[i] * size;
            type = type->getPointerElementType();
        } else if (type->isStructTy()) {
            llvm::DataLayout *dl = new llvm::DataLayout(ctx.module);
            const llvm::StructLayout* sl = dl->getStructLayout(static_cast<llvm::StructType *>(type));
            auto off = sl->getElementOffset(offsets[i]);
            //std::cerr << "struct " << off << std::endl;
            type = type->getStructElementType(offsets[i]);
            off_val += off;
        } else if (type->isArrayTy()) {
            auto size = get_type_size(ctx.module, type->getArrayElementType());
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

RegisterInfo handle_gep(llvm::GetElementPtrInst *gep_inst, AnalyzeCtx &ctx) {
    // Get Element Ptr:
    //   1) get the info for the base pointer
    //   2) walk through the struct (recursive)
    auto base_name = get_llvm_name(*gep_inst->getPointerOperand());
    auto base_info = trace_pointer(base_name, ctx);
    auto ptr_type = gep_inst->getSourceElementType();

    // perform a walk through for the offset, only allow register or constant as offset
    std::vector<int> offsets;
    std::vector<std::string> offset_regs;
    for (int i = 1; i < gep_inst->getNumOperands(); i++) {
        auto v = gep_inst->getOperand(i);
        int o = 0;
        if (const llvm::ConstantInt* CI = llvm::dyn_cast<llvm::ConstantInt>(v)) {
            offsets.push_back(get_int_val(v));
            offset_regs.push_back("");
        } else {
            offsets.push_back(-1);
            offset_regs.push_back(get_llvm_name(*v));
        }
    }

    RegisterInfo info;
    // walk through the gep
    if (base_info.reg_type == "packet_obj") {
        // this pointer is a pointer to click packet object
        // TODO: handle click packet object
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
                auto size = get_type_size(ctx.module, type->getPointerElementType());
                //std::cerr << "pointer " << size << " offset: " << offsets[i] << std::endl;
                off_val += offsets[i] * size;
                type = type->getPointerElementType();
            } else if (type->isStructTy()) {
                llvm::DataLayout *dl = new llvm::DataLayout(ctx.module);
                const llvm::StructLayout* sl = dl->getStructLayout(static_cast<llvm::StructType *>(type));
                auto off = sl->getElementOffset(offsets[i]);
                //std::cerr << "struct " << off << std::endl;
                type = type->getStructElementType(offsets[i]);
                off_val += off;
            } else if (type->isArrayTy()) {
                auto size = get_type_size(ctx.module, type->getArrayElementType());
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


RegisterInfo trace_pointer(const std::string &reg_name,
                           AnalyzeCtx &ctx) {
    //std::cerr << "tracing: " << reg_name << std::endl;
    if (ctx.reg_cache.find(reg_name) != ctx.reg_cache.end()) {
        return ctx.reg_cache.find(reg_name)->second;
    } else {
        RegisterInfo info;
        assert(ctx.reg_inst.find(reg_name) != ctx.reg_inst.end());
        auto inst = ctx.reg_inst.find(reg_name)->second;
        if (inst->is_llvm_inst()) {
            auto llvm_i = std::dynamic_pointer_cast<Target::LLVMInst>(inst);
            if (auto gep_inst = llvm::dyn_cast<llvm::GetElementPtrInst>(llvm_i->get_inst())) {
                info = handle_gep(gep_inst, ctx);
            } else if (auto cast_inst = llvm::dyn_cast<llvm::BitCastInst>(llvm_i->get_inst())) {
                llvm::Type *src_type = cast_inst->getSrcTy();
                llvm::Type *dst_type = cast_inst->getDestTy();
                assert(src_type->isPointerTy() && dst_type->isPointerTy());
                auto src_reg = get_llvm_name(*cast_inst->getOperand(0));
                info = trace_pointer(src_reg, ctx);
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
                auto reg_info = trace_pointer(reg_name, ctx);
                //std::cerr << "phi pointer: " << from_bb << " -> " << reg_info << std::endl;
            }
        } else if (inst->is_map_get()) {
            //std::cerr << "load/store of map-get result" << std::endl;
        }
    ret:
        ctx.reg_cache.insert({reg_name, info});
        //std::cerr << "got info: " << info << std::endl;
        return info;
    }
}


void replace_call(TranslationCtx &ctx, AnalyzeCtx &a_ctx) {
    for (auto iter = ctx.blocks_.begin(); iter != ctx.blocks_.end(); iter++) {
        auto blk = iter->second;
        auto insts = blk->insts_mut();
        Target::BasicBlock::InstList ns;
        for (auto i = 0; i < insts.size(); i++) {
            auto inst = insts[i];
            if (inst->is_call()) {
                auto call = std::dynamic_pointer_cast<Target::CallInst>(inst);
                auto fn = call->func_name();
                std::string func_name = "";
                auto demangled = cxx_demangle(fn, func_name);
                if (demangled) {
                    func_name = remove_template(func_name);
                    //std::cerr << "calling: " << func_name << std::endl;
                    auto no_arg_ver = remove_func_args(func_name);
                    if (func_replacer.find(no_arg_ver) != func_replacer.end()) {
                        func_name = no_arg_ver;
                    }
                } else {
                    func_name = fn;
                }

                if (str_begin_with(func_name, "llvm.dbg") || str_begin_with(func_name, "llvm.lifetime")) {
                    continue;
                }

                if (func_replacer.find(func_name) != func_replacer.end()) {
                    auto replacer = func_replacer.find(func_name)->second;
                    auto new_insts = replacer(call, a_ctx);
                    for (auto iter = new_insts.begin(); iter != new_insts.end(); iter++) {
                        if ((*iter)->llvm_inst_ptr_ == nullptr) {
                            (*iter)->llvm_inst_ptr_ = inst->llvm_inst_ptr_;
                        }
                        ns.push_back(*iter);
                    }
                    //delete inst;
                } else {
                    ns.push_back(inst);
                }
            } else {
                ns.push_back(inst);
            }
        }
        blk->set_insts(ns);
    }
}


void find_pkt_access(TranslationCtx &ctx, AnalyzeCtx &a_ctx) {
    for (auto iter = ctx.blocks_.begin(); iter != ctx.blocks_.end(); iter++) {
        auto blk = iter->second;
        for (auto inst_i = blk->inst_begin(); inst_i != blk->inst_end(); inst_i++) {
            /* There are 3 types of instructions that needs to be inspected
             * 1) Load  : could be loading from packet header or global state
             * 2) store : packet rewriting and global state update
             * 3) call  : each called function need to be inspected to 
             *            check whether it modifies global state or packets
             */
            auto inst = *inst_i;
            if (inst->is_llvm_inst()) {
                auto llvm_inst = std::dynamic_pointer_cast<Target::LLVMInst>(inst)->get_inst();
                if (auto load = llvm::dyn_cast<llvm::LoadInst>(llvm_inst)) {
                    auto src_name = get_llvm_name(*load->getOperand(0));
                    RegisterInfo src_info = trace_pointer(src_name, a_ctx);
                    if (str_begin_with(src_info.reg_type, "field_value:")) {
                        auto field_str = src_info.reg_type.substr(std::string("field_value:").length());
                        auto dot_pos = field_str.find(".");
                        auto header_name = field_str.substr(0, dot_pos);
                        auto field_name = field_str.substr(dot_pos + 1);
                        auto new_inst = std::make_shared<Target::HeaderReadInst>(inst->get_dst_reg(), src_info.var_name,
                                                                                 header_name, field_name);
                        new_inst->llvm_inst_ptr_ = llvm_inst;
                        *inst_i = new_inst;
                        // std::cerr << "load swaped to: ";
                        // new_inst->print(std::cerr);
                        // std::cerr << std::endl;
                    } else if (header_defs.find(src_info.reg_type) != header_defs.end()) {
                        auto &header_info = header_defs.find(src_info.reg_type)->second;
                        bool found = false;
                        int off = 0;
                        auto load_size = get_type_size(a_ctx.module, load->getPointerOperandType()->getPointerElementType());
                        std::string load_field = "";
                        for (auto &t : header_info) {
                            std::string field_name = std::get<0>(t);
                            int field_size = std::get<1>(t);
                            if (off == src_info.pointer_offset && field_size == load_size) {
                                found = true;
                                load_field = field_name;
                            }
                            off += field_size;
                        }

                        if (found) {
                            auto header_name = src_info.reg_type;
                            auto field_name = load_field;
                            auto new_inst = std::make_shared<Target::HeaderReadInst>(inst->get_dst_reg(), src_info.var_name,
                                                                                     header_name, field_name);
                            *inst_i = new_inst;
                            new_inst->llvm_inst_ptr_ = llvm_inst;
                            // std::cerr << "load swaped to: ";
                            // new_inst->print(std::cerr);
                            // std::cerr << std::endl;
                        }
                    }
                } else if (auto store = llvm::dyn_cast<llvm::StoreInst>(llvm_inst)) {
                    auto dst_name = get_llvm_name(*store->getOperand(1));
                    auto val_name = get_llvm_name(*store->getOperand(0));
                    RegisterInfo dst_info = trace_pointer(dst_name, a_ctx);
                    if (str_begin_with(dst_info.reg_type, "field_value:")) {
                        auto field_str = dst_info.reg_type.substr(std::string("field_value:").length());
                        auto dot_pos = field_str.find(".");
                        auto header_name = field_str.substr(0, dot_pos);
                        auto field_name = field_str.substr(dot_pos + 1);
                        auto new_inst = std::make_shared<Target::HeaderWriteInst>(dst_info.var_name, header_name,
                                                                                  field_name, val_name);
                        *inst_i = new_inst;
                        new_inst->llvm_inst_ptr_ = llvm_inst;
                    } else if (header_defs.find(dst_info.reg_type) != header_defs.end()) {
                        auto &header_info = header_defs.find(dst_info.reg_type)->second;
                        bool found = false;
                        int off = 0;
                        auto ptr_type = store->getPointerOperandType();
                        auto load_size = get_type_size(a_ctx.module,
                                                       ptr_type->getPointerElementType());
                        std::string store_field = "";
                        for (auto &t : header_info) {
                            std::string field_name = std::get<0>(t);
                            int field_size = std::get<1>(t);
                            if (off == dst_info.pointer_offset && field_size == load_size) {
                                found = true;
                                store_field = field_name;
                            }
                            off += field_size;
                        }

                        if (found) {
                            auto header_name = dst_info.reg_type;
                            auto field_name = store_field;
                            auto new_inst = std::make_shared<Target::HeaderWriteInst>(dst_info.var_name, header_name,
                                                                                      field_name, val_name);
                            *inst_i = new_inst;
                            new_inst->llvm_inst_ptr_ = llvm_inst;
                        }
                    }
                }
            } else if (inst->is_call()) {
                std::shared_ptr<Target::CallInst> call_inst = std::dynamic_pointer_cast<Target::CallInst>(inst);
                std::string demangled;
                if (cxx_demangle(call_inst->func_name(), demangled) &&
                    demangled == "Element::checked_output_push(int, Packet*) const") {
                    auto pkt_reg = call_inst->args()[2];
                    RegisterInfo pkt_info = trace_pointer(pkt_reg, a_ctx);
                    auto pkt_name = pkt_info.var_name;
                    auto port_reg = call_inst->args()[1];
                    auto new_inst = std::make_shared<Target::EmitPktInst>(pkt_name, port_reg);
                    new_inst->llvm_inst_ptr_ = call_inst->llvm_inst_ptr_;
                    *inst_i = new_inst;
                }
            }
        }
    }
}


void remove_dead_insts(TranslationCtx &ctx, AnalyzeCtx &a_ctx,
                       std::unordered_map<std::string, InstID> &dst_map) {
    std::unordered_map<InstID, Target::InstDeps,
                       InstIDHasher, InstIDEqual> inst_reqs;
    std::unordered_set<InstID, InstIDHasher, InstIDEqual> keep_inst;
    std::unordered_set<std::string> required_regs;
    for (auto &blk_kv : ctx.blocks_) {
        auto &blk = blk_kv.second;
        auto &insts = blk->insts_mut();
        for (auto inst_i = 0; inst_i < insts.size(); inst_i++) {
            InstID id{blk->get_name(), inst_i};
            std::shared_ptr<Target::Instruction> inst = insts[inst_i];
            Target::InstDeps deps;
            Target::get_deps(*inst, deps);
            inst_reqs.insert({id, deps});
        }
    }

    std::queue<InstID> queue;
    std::unordered_set<InstID, InstIDHasher, InstIDEqual> visited;
    for (auto &blk_kv : ctx.blocks_) {
        auto &blk = blk_kv.second;
        auto &insts = blk->insts_mut();
        for (auto inst_i = 0; inst_i < insts.size(); inst_i++) {
            InstID id{blk->get_name(), inst_i};
            std::shared_ptr<Target::Instruction> inst = insts[inst_i];
            if (!Target::no_side_effect(*inst)) {
                queue.push(id);
                visited.insert(id);
            }
        }
        if (blk->is_conditional()) {
            auto cond_reg = blk->branch_cond();
            if (dst_map.find(cond_reg) != dst_map.end()) {
                auto cond_inst_id = dst_map.find(cond_reg)->second;
                queue.push(cond_inst_id);
                visited.insert(cond_inst_id);
                required_regs.insert(cond_reg);
            }
        }
    }

    while (queue.size() > 0) {
        InstID id = queue.front();
        queue.pop();

        auto blk_name = std::get<0>(id);
        auto inst_i = std::get<1>(id);
        auto blk_iter = ctx.blocks_.find(blk_name);
        if (blk_name == "args") {
            continue;
        }
        assert(blk_iter != ctx.blocks_.end());
        auto blk = blk_iter->second;
        auto &insts = blk->insts_mut();
        std::shared_ptr<Target::Instruction> inst = insts[inst_i];
        assert(inst_reqs.find(id) != inst_reqs.end());
        Target::InstDeps &deps = inst_reqs.find(id)->second;
        for (auto &reg : deps.reg_dep) {
            if (dst_map.find(reg) == dst_map.end()) {
                continue;
            }
            auto dep_id = dst_map.find(reg)->second;
            // if (std::get<0>(dep_id) == "args") {
            //     continue;
            // }
            required_regs.insert(reg);
            if (visited.find(dep_id) == visited.end()) {
                queue.push(dep_id);
                visited.insert(dep_id);
            }
        }
    }
    
    for (auto &blk_kv : ctx.blocks_) {
        auto &blk = blk_kv.second;
        auto &insts = blk->insts_mut();
        std::vector<std::shared_ptr<Target::Instruction>> ns;
        for (auto inst_i = 0; inst_i < insts.size(); inst_i++) {
            std::shared_ptr<Target::Instruction> inst = insts[inst_i];
            InstID new_id{blk->get_name(), ns.size()};
            auto required = (required_regs.find(inst->get_dst_reg()) != required_regs.end());
            if (Target::no_side_effect(*inst) && !required) {
                dst_map.erase(inst->get_dst_reg());
            } else {
                ns.push_back(inst);
                auto dst_reg = inst->get_dst_reg();
                if (dst_reg != "") {
                    if (dst_map.find(dst_reg) != dst_map.end()) {
                        dst_map.find(dst_reg)->second = new_id;
                    } else {
                        dst_map.insert({dst_reg, new_id});
                    }
                }
            }
        }
        blk->set_insts(ns);
    }
}


void print_blocks(const TranslationCtx &ctx, const Placement &p) {
    for (auto &blk_kv: ctx.blocks_) {
        auto &blk = blk_kv.second;
        auto &insts = blk->insts_mut();
        //std::cerr << "blk: " << blk->get_name() << std::endl;
        for (auto inst_i = 0; inst_i < insts.size(); inst_i++) {
            auto inst = insts[inst_i];
            InstID id{blk->get_name(), inst_i};
            auto loc_iter = p.fixed_inst.find(id);
            std::cerr << " @ ";
            if (loc_iter == p.fixed_inst.end()) {
                std::cerr << "???";
            } else {
                std::cerr << loc_iter->second;
            }
            std::cerr << std::endl;
        }
        std::cerr << "============" << std::endl << std::endl;
    }
}


std::unordered_map<std::string, Target::BasicBlock *>
split_blocks(std::unordered_map<std::string, Target::BasicBlock *> &blocks) {
    std::unordered_map<std::string, Target::BasicBlock *> result;

    for (auto &kv : blocks) {
        auto blk = kv.second;
        auto blocks = blk->split_to_parallel_blks();
        assert(blocks.size() > 0);
        blocks[0]->set_name(blk->get_name());
        for (int i = 0; i < blocks.size() - 1; i++) {
            blocks[i]->add_next(blocks[i+1]->get_name());
        }

        auto last_blk = blocks[blocks.size() - 1];
        if (blk->is_conditional()) {
            last_blk->add_branch(blk->branch_cond(),
                                 blk->t_branch(),
                                 blk->f_branch());
        } else {
            last_blk->add_next(blk->next_bb());
        }

        for (auto b : blocks) {
            result.insert({b->get_name(), b});
        }
    }
    return result;
}


int main(int argc, char *argv[]) {
    llvm::LLVMContext llvm_ctx;
    llvm::SMDiagnostic err;
    if (argc < 2) {
        printf("Usage: %s <ir-file> [-o cpp-file] [-dot dot-file]\n", argv[0]);
        return -1;
    }

    const std::string ir_filename = std::string(argv[1]);
    //const std::string function_name = std::string(argv[2]);
    std::string dot_filename = "";
    std::string output_file = "";
    for (int i = 2; i < argc; i++) {
        if (std::string(argv[i]) == "-o") {
            if (i >= argc - 1) {
                std::cerr << "Expect parameter for option!" << std::endl;
                exit(-1);
            }
            i++;
            output_file = argv[i];
        } else if (std::string(argv[i]) == "-dot") {
            if (i >= argc - 1) {
                std::cerr << "Expect parameter for option!" << std::endl;
                exit(-1);
            }
            i++;
            dot_filename = argv[i];
        }
    }

    auto module = llvm::parseIRFile(ir_filename, err, llvm_ctx);

    if (module == nullptr) {
        err.print("prog", llvm::errs());
    }

    //auto func = module->getFunction(function_name);
    llvm::Function *func = nullptr;
    int num_entries = 0;
    for (auto iter = module->begin(); iter != module->end(); iter++) {
        auto func_name = iter->getName().str();
        std::string demangled;
        if (cxx_demangle(func_name, demangled)) {
            auto pos = demangled.find("::push(int, Packet*)");
            if (pos != std::string::npos) {
                func = module->getFunction(func_name);
                num_entries++;
            }
        }
    }

    if (num_entries > 1) {
        assert(false && "found multiple entries");
    } else if (num_entries == 0) {
        assert(false && "could not find entry");
    }

    auto &entry_bb = func->getEntryBlock();
    auto entry_bb_name = "bb_" + get_llvm_name(entry_bb);

    NameFactory name_gen;
    TranslationCtx ctx(name_gen);

    for (auto iter = func->begin(); iter != func->end(); iter++) {
        std::string bb_name = "bb_" + get_llvm_name(*iter);
        ctx.block_in_construction_ = bb_name;
        for (auto i2 = iter->begin(); i2 != iter->end(); i2++) {
            InstVisitor visitor(*module, ctx);
            visitor.visit(*i2);
        }
        if (ctx.insts_.size() > 0) {
            auto block = new Target::BasicBlock(ctx.block_in_construction_, ctx.insts_);
            ctx.insts_.clear();
            ctx.blocks_.insert({ctx.block_in_construction_, block});
        }
    }

    std::unordered_map<std::string, std::shared_ptr<Target::Instruction>> reg_inst;

    for (auto iter = ctx.blocks_.begin(); iter != ctx.blocks_.end(); iter++) {
        auto blk = iter->second;
        for (auto i2 = blk->inst_begin(); i2 != blk->inst_end(); i2++) {
            auto inst = *i2;
            if (inst->get_dst_reg() != "") {
                reg_inst.insert({inst->get_dst_reg(), inst});
            }
        }
    }

    AnalyzeCtx a_ctx;
    a_ctx.module = module.get();
    a_ctx.reg_cache.insert({"%0", RegisterInfo{true, 0, "self", "state"}});
    a_ctx.reg_cache.insert({"%1", RegisterInfo{false, 0, "in_port", "int"}});
    a_ctx.reg_cache.insert({"%2", RegisterInfo{true, 0, "input_pkt", "packet"}});
    a_ctx.reg_inst = reg_inst;

    replace_call(ctx, a_ctx);
    find_pkt_access(ctx, a_ctx);
    /*
    for (auto iter = ctx.blocks_.begin(); iter != ctx.blocks_.end(); iter++) {
        auto blk = iter->second;
        auto insts = blk->insts_mut();
        std::cerr << "blk: " << blk->get_name() << std::endl;
        for (auto i = 0; i < insts.size(); i++) {
            Target::Instruction *inst = insts[i];
            inst->print(std::cerr);
            std::cerr << std::endl;
        }
        std::cerr << "=====================" << std::endl;
    }    
    */

    std::unordered_map<std::string, InstID> dst_mapping;
    int num_insts = 0;
    for (auto &blk_kv : ctx.blocks_) {
        auto &blk = blk_kv.second;
        auto &insts = blk->insts_mut();
        for (auto inst_i = 0; inst_i < insts.size(); inst_i++) {
            auto inst = insts[inst_i];
            InstID id{blk->get_name(), inst_i};
            auto dst = inst->get_dst_reg();
            num_insts++;
            if (dst != "") {
                assert(dst_mapping.find(dst) == dst_mapping.end());
                dst_mapping.insert({dst, id});
            }
        }
    }

    PlaceReqSet req_set;
    dst_mapping.insert({"%0", {"args", 0}});
    dst_mapping.insert({"%1", {"args", 1}});
    dst_mapping.insert({"%2", {"args", 2}});
    req_set.inst_reqs.insert({{"args", 0}, PlaceReq("p4")});
    req_set.inst_reqs.insert({{"args", 1}, PlaceReq("p4")});
    req_set.inst_reqs.insert({{"args", 2}, PlaceReq("p4")});

    // Placement tmp;
    // print_blocks(ctx, tmp);
    remove_dead_insts(ctx, a_ctx, dst_mapping);
    // print_blocks(ctx, tmp);
    InfoSet info_set = get_place_info(ctx.blocks_, entry_bb_name);
    info_set.inst_info.insert({{"args", 0}, PlaceInfo::P4_prefix()});
    info_set.inst_info.insert({{"args", 1}, PlaceInfo::P4_prefix()});
    info_set.inst_info.insert({{"args", 2}, PlaceInfo::P4_prefix()});
    info_set.state_info.insert({"input_pkt", PlaceInfo::P4_both()});

    auto result = label_insts(info_set);

    for (auto &kv : ctx.blocks_) {
        auto &blk = *kv.second;
        Target::reorder_insts(blk, info_set, result);
    }

    Placement p;
    auto t2str = [](PlaceType t) -> std::string {
        std::string result;
        switch (t) {
        case PlaceType::CPU:
            result = "cpu";
            break;
        case PlaceType::P4_PREFIX:
            result = "p4_prefix";
            break;
        case PlaceType::P4_SUFFIX:
            result = "p4_suffix";
            break;
        case PlaceType::P4_BOTH:
            result = "p4_both";
            break;
        }
        return result;
    };
    
    for (auto &kv : result.fixed_inst) {
        p.fixed_inst.insert({kv.first, t2str(kv.second)});
    }

    for (auto &kv : result.fixed_state) {
        p.fixed_state.insert({kv.first, t2str(kv.second)});
    }

    

    //print_blocks(ctx, p);
    auto t2color = [](PlaceType t) -> std::string {
        std::string result;
        switch (t) {
        case PlaceType::CPU:
            result = "lightgray";
            break;
        case PlaceType::P4_PREFIX:
            result = "lightblue";
            break;
        case PlaceType::P4_SUFFIX:
            result = "lightyellow";
            break;
        case PlaceType::P4_BOTH:
            result = "#90ee90";
            break;
        }
        return result;
    };
    std::unordered_map<InstID, std::string, InstIDHasher, InstIDEqual> inst_color;
    for (auto &kv : result.fixed_inst) {
        inst_color.insert({kv.first, t2color(kv.second)});
    }

    std::string exit_bb_name = "";

    for (auto &blk_kv: ctx.blocks_) {
        auto &blk = blk_kv.second;
        auto &insts = blk->insts_mut();
        //std::cerr << "blk: " << blk->get_name() << std::endl;
        for (auto inst_i = 0; inst_i < insts.size(); inst_i++) {
            if (insts[inst_i]->is_return()) {
                assert(exit_bb_name == "");
                exit_bb_name = blk->get_name();
            }
        }
    }

    auto prefix = Target::peel(ctx.blocks_, entry_bb_name, result, false);
    auto suffix = Target::peel(ctx.blocks_, exit_bb_name, result, true);

    std::ofstream dot_file;
    if (dot_filename != "") {
        dot_file.open(dot_filename + ".dot");
        Target::generate_dot_file(dot_file, ctx.blocks_, inst_color);
        dot_file.close();

        // also generate the splitted version
        auto splitted = ::split_blocks(ctx.blocks_);
        dot_file.open(dot_filename + "_splitted.dot");
        Target::generate_dot_file(dot_file, splitted, inst_color);
        dot_file.close();
    }

    inst_color.clear();
    int num_prefix = 0;
    int num_suffix = 0;
    for (auto &kv : prefix.blocks) {
        auto blk = kv.second;
        auto &insts = blk->insts_mut();
        for (int i = 0; i < insts.size(); i++) {
            InstID id{kv.first, i};
            inst_color.insert({id, t2color(PlaceType::P4_PREFIX)});
            num_prefix++;
        }
    }
    if (dot_filename != "") {
        dot_file.open(dot_filename + "_prefix.dot");    
        Target::generate_dot_file(dot_file, prefix.blocks, inst_color);
        dot_file.close();
    }
    
    for (auto &kv : suffix.blocks) {
        auto blk = kv.second;
        auto &insts = blk->insts_mut();
        for (int i = 0; i < insts.size(); i++) {
            InstID id{kv.first, i};
            inst_color.insert({id, t2color(PlaceType::P4_SUFFIX)});
            num_suffix++;
        }
    }

    if (dot_filename != "") {
        dot_file.open(dot_filename + "_suffix.dot");    
        Target::generate_dot_file(dot_file, suffix.blocks, inst_color);
        dot_file.close();
    }

        
    Target::GlobalTypes globals;
    std::vector<std::string> entries = {entry_bb_name};
    Target::CppGen codegen(ctx.blocks_, module.get(), entries, globals);
    auto lines = codegen.gen_code();

    std::ostream *os = &std::cout;
    if (output_file != "") {
        dot_file.open(output_file);
        os = &dot_file;
    }
    *os << "#include \"morula.hpp\"" << std::endl;
    *os << "void foo(char *v0, int v1, Packet *v2, MyPkt *input_pkt) {" << std::endl;
    for (auto &l : lines) {
        *os << l << std::endl;
    }
    *os << "}" << std::endl;

    if (output_file != "") {
        dot_file.close();
    }

    float prefix_percent = num_prefix / (float)(num_insts) * 100;
    float suffix_percent = num_suffix / (float)(num_insts) * 100;
    std::cout << "Num Inst: " << num_insts << std::endl
              << "Num Prefix: " << num_prefix
              << "(" << prefix_percent << "%" << ")" << std::endl
              << "Num Suffix: " << num_suffix
              << "(" << suffix_percent << "%" << ")" << std::endl;
    //auto parts = find_partitions(ctx.blocks_, entries);
    
    return 0;
}
