#include "pass-llvm.hpp"
#include "utils.hpp"
#include <memory>

using namespace Target;

namespace Morula {
    class FromLLVMVisitor : public llvm::InstVisitor<FromLLVMVisitor> {
    public:
        std::unordered_map<std::string, std::shared_ptr<BasicBlock>> &blocks_;
        BasicBlock::InstList insts_;
        std::string curr_blk_;
        LLVMCtx &ctx_;

        FromLLVMVisitor(LLVMCtx &ctx,
                        std::unordered_map<std::string, std::shared_ptr<BasicBlock>> &blks) :
            ctx_(ctx), blocks_(blks) {}
        
        void visitInstruction(const llvm::Instruction &inst) {
            auto new_inst = std::make_shared<LLVMInst>(inst);
            new_inst->llvm_inst_ptr_ = &inst;
            insts_.push_back(new_inst);
        }
        void visitReturnInst(const llvm::ReturnInst &inst) {
            assert(inst.getNumOperands() <= 1);
            std::string ret_val = "";
            if (inst.getNumOperands() == 1) {
                ret_val = get_llvm_name(*inst.getOperand(0));
            }
            auto target_i = std::make_shared<ReturnInst>(ret_val);
            insts_.push_back(target_i);
            auto block = std::make_shared<BasicBlock>(curr_blk_, insts_);
            insts_.clear();
            blocks_.insert({curr_blk_, block});
        }
        
        void visitBranchInst(const llvm::BranchInst &inst) {
            auto new_block = std::make_shared<BasicBlock>(curr_blk_, insts_);
            if (inst.isConditional()) {
                auto cond_reg = get_llvm_name(*inst.getCondition());
                auto t_target = "bb_" + get_llvm_name(*inst.getSuccessor(0));
                auto f_target = "bb_" + get_llvm_name(*inst.getSuccessor(1));
                new_block->add_branch(cond_reg, t_target, f_target);
            } else {
                auto target_bb = "bb_" + get_llvm_name(*inst.getSuccessor(0));
                new_block->add_next(target_bb);
            }
            blocks_.insert({new_block->get_name(), new_block});
            insts_.clear();
        }
        
        void visitSwitchInst(const llvm::SwitchInst &inst) {
            auto switch_reg = get_llvm_name(*inst.getCondition());
            auto switch_reg_t = inst.getCondition()->getType();
            std::shared_ptr<BasicBlock> block = nullptr;
            std::string target_bb;
            std::string cond_reg;
            for (auto iter = inst.case_begin(); iter != inst.case_end(); iter++) {
                if (block != nullptr) {
                    block->add_branch(cond_reg, target_bb, curr_blk_);
                    blocks_.insert({block->get_name(), block});
                }
                auto &c = *iter;
                auto val = c.getCaseValue()->getSExtValue();
                target_bb = "bb_" + get_llvm_name(*c.getCaseSuccessor());
                auto const_reg = (*ctx_.name_gen)("const_tmp");
                using Op = ArithInst::Op;
                auto const_inst = std::make_shared<ArithInst>(const_reg, Op::CONST_VAL,
                                                                      std::vector<std::string>{std::to_string(val)});
                const_inst->dst_type_anno = switch_reg_t;
                const_inst->llvm_type_ = switch_reg_t;
                insts_.push_back(const_inst);
                cond_reg = (*ctx_.name_gen)("switch_cond");
                auto cmp_inst = std::make_shared<ArithInst>(cond_reg, Op::EQ,
                                                                    std::vector<std::string>{switch_reg, const_reg});
                auto next_bb = (*ctx_.name_gen)("switch_bb");
                insts_.push_back(cmp_inst);
                block = std::make_shared<BasicBlock>(curr_blk_, insts_);
                insts_.clear();
                curr_blk_ = next_bb;
                blocks_.insert({block->get_name(), block});
            }
            auto default_bb = "bb_" + get_llvm_name(*inst.getDefaultDest());
            assert(block != nullptr);
            block->add_branch(cond_reg, target_bb, default_bb);
            curr_blk_ = default_bb;
            blocks_.insert({block->get_name(), block});
        }
        
        void visitSelectInst(const llvm::SelectInst &inst) {
            auto dst_reg = get_llvm_name(inst);
            auto cond_reg = get_llvm_name(*inst.getCondition());
            auto t_reg = get_llvm_name(*inst.getTrueValue());
            auto f_reg = get_llvm_name(*inst.getFalseValue());
            auto blk_name_base = (*ctx_.name_gen)("select");
            auto t_block = std::make_shared<BasicBlock>(blk_name_base + "_t_block",
                                                        BasicBlock::InstList{});
            auto f_block = std::make_shared<BasicBlock>(blk_name_base + "_f_block",
                                                        BasicBlock::InstList{});
            auto next_bb = blk_name_base + "_after";
            
            t_block->add_next(next_bb);
            f_block->add_next(next_bb);
            auto curr_block = std::make_shared<BasicBlock>(curr_blk_, insts_);
            insts_.clear();
            curr_block->add_branch(cond_reg, t_block->get_name(), f_block->get_name());
            blocks_.insert({curr_block->get_name(), curr_block});
            blocks_.insert({t_block->get_name(), t_block});
            blocks_.insert({f_block->get_name(), f_block});
            
            
            std::unordered_map<std::string, std::string> phi_vals =
                {{t_block->get_name(), t_reg},
                 {f_block->get_name(), f_reg}};
            
            auto phi_inst = std::make_shared<PhiInst>(dst_reg, phi_vals);
            phi_inst->llvm_type_ = inst.getType();
            phi_inst->llvm_inst_ptr_ = nullptr;
            insts_.push_back(phi_inst);
            curr_blk_ = next_bb;
        }
        
        void visitPHINode(const llvm::PHINode &inst) {
            auto dst_reg = get_llvm_name(inst);
            std::unordered_map<std::string, std::string> vals;
            for (auto i = 0; i < inst.getNumIncomingValues(); i++) {
                auto bb = get_llvm_name(*inst.getIncomingBlock(i));
                auto val_reg = get_llvm_name(*inst.getIncomingValue(i));
                vals.insert({bb, val_reg});
            }
            insts_.push_back(std::make_shared<PhiInst>(dst_reg, vals));
        }
    };
    
    std::unique_ptr<PassCtx> FromLLVM::pass_impl(std::unique_ptr<LLVMCtx> s) {
        auto result = std::make_unique<PassCtx>();
        std::shared_ptr<llvm::Module> llvm_ptr = std::move(s->module);
        llvm::Module *module = s->module.get();
        result->llvm_module = llvm_ptr;
        result->name_gen = s->name_gen;
        NameFactory &gen_name = *(result->name_gen);

        auto &entry_bb = s->entry_func->getEntryBlock();
        auto entry_bb_name = "bb_" + get_llvm_name(entry_bb);

        FromLLVMVisitor visitor(*s, result->blocks);
        for (auto iter = s->entry_func->begin(); iter != s->entry_func->end(); iter++) {
            std::string bb_name = "bb_" + get_llvm_name(*iter);
            visitor.curr_blk_ = bb_name;
            for (auto i2 = iter->begin(); i2 != iter->end(); i2++) {
                visitor.visit(*i2);
            }
            if (visitor.insts_.size() > 0) {
                auto block = std::make_shared<BasicBlock>(visitor.curr_blk_,
                                                          visitor.insts_);
                visitor.insts_.clear();
                visitor.blocks_.insert({visitor.curr_blk_, block});
            }
        }
        
        return result;
    }

    class RemoveFuncVisitor : public InstVisitor {
    public:
        bool keep_old = true;
        std::shared_ptr<Instruction> new_inst = nullptr;
        class RemoveFuncLLVM : public llvm::InstVisitor<RemoveFuncLLVM> {
        public:
            bool keep_old = true;
            std::shared_ptr<Instruction> new_inst = nullptr;
            
            void visitCallInst(const llvm::CallInst &inst) {
                keep_old = false;
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

                // filter out llvm internal functions
                if (str_begin_with(func_name, "llvm.dbg.")) {
                    return;
                } else if (str_begin_with(func_name, "llvm.lifetime.")) {
                    return;
                }
                
                // handle inline asm
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

                std::string demangled_fn;
                auto demangled = cxx_demangle(func_name, demangled_fn);
                if (demangled) {
                    func_name = demangled_fn;
                }

                if (func_name == "__assert_fail") {
                    args.clear();
                }
                new_inst = std::make_shared<Target::CallInst>(dst_reg, func_name, args);
                new_inst->llvm_inst_ptr_ = &inst;
            }
        };
        
        void visit_inst(Instruction &inst) {
            keep_old = true;
        }
        
        void visit_inst(LLVMInst &inst) {
            RemoveFuncLLVM visitor;
            visitor.visit(inst.get_inst());
            new_inst = visitor.new_inst;
            keep_old = visitor.keep_old;
        }
    };

    std::unique_ptr<PassCtx> RemoveFunc::pass_impl(std::unique_ptr<PassCtx> s) {
        for (auto &kv : s->blocks) {
            auto blk = kv.second;
            auto insts = blk->insts_mut();
            BasicBlock::InstList ns;
            for (auto inst : insts) {
                RemoveFuncVisitor visitor;
                visitor.visit(*inst);
                if (visitor.keep_old) {
                    ns.push_back(inst);
                } else if (visitor.new_inst != nullptr) {
                    ns.push_back(visitor.new_inst);
                }
            }
            blk->set_insts(ns);
        }
        return s;
    }

    class AllocaLLVMVisitor : public llvm::InstVisitor<AllocaLLVMVisitor> {
    public:
        std::shared_ptr<Instruction> new_inst = nullptr;

        void visitAllocaInst(const llvm::AllocaInst &inst) {
            auto dst_reg = get_llvm_name(inst);
            const llvm::Value *val = inst.getArraySize();
            int64_t size64 = get_llvm_int_val(val);
            int size = (int)size64;
            auto type = inst.getAllocatedType();
            auto type_str = get_llvm_type_str(*type);
            auto ni = std::make_shared<Target::AllocaInst>(dst_reg, type_str, size);
            ni->llvm_inst_ptr_ = &inst;
            ni->llvm_type = type;
            new_inst = ni;
        }
    };

    std::unique_ptr<PassCtx> TranslateAlloca::pass_impl(std::unique_ptr<PassCtx> s) {
        for (auto &kv : s->blocks) {
            auto blk = kv.second;
            auto &insts = blk->insts_mut();
            for (int i = 0; i < insts.size(); i++) {
                if (insts[i]->is_llvm_inst()) {
                    auto inst = std::dynamic_pointer_cast<LLVMInst>(insts[i]);
                    AllocaLLVMVisitor v;
                    v.visit(*inst->get_inst());
                    if (v.new_inst != nullptr) {
                        insts[i] = v.new_inst;
                    }
                }
            }
        }
        return s;
    }
}
