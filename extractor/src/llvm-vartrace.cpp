#include "llvm-vartrace.hpp"

namespace Morula {
    namespace LLVMAnalysis {
        class RegInfoVisitor : public llvm::InstVisitor<RegInfoVisitor> {
        public:
            Analyzer &analyzer;
            RegInfo &info;
            RegInfoVisitor(Analyzer &a, RegInfo &i) : analyzer(a), info(i) {}

            RegInfo info_from_llvm_type(llvm::Type *t) {
                RegInfo i;
                if (t->isIntegerTy()) {
                    i.t = RegInfo::Type::NUMBER;
                } else if (t->isPointerTy()) {
                    i.t = RegInfo::Type::POINTER;
                } else {
                    assert(false && "analyzer: unknown llvm type");
                }
                return i;
            }

            void visitInstruction(llvm::Instruction &inst) {
                assert(false && "not supported instruction");
            }

            void visitGetElementPtrInst(llvm::GetElementPtrInst &gep) {
                auto base_info = analyzer.get_reg_info(gep.getPointerOperand());
                info.t = base_info.t;
                for (int i = 1; i < gep.getNumOperands(); i++) {
                    auto v = gep.getOperand(i);
                    if (const llvm::ConstantInt *CI = llvm::dyn_cast<llvm::ConstantInt>(v)) {
                        auto off = CI->getSExtValue();
                        switch (info.t) {
                            case RegInfo::Type::NUMBER:
                                assert(false && "gep reg could not be a pointer");
                                break;
                            case RegInfo::Type::POINTER:
                                break;
                            case RegInfo::Type::GLOBAL_STATE_PTR:
                                assert(false && "TODO");
                                break;
                            case RegInfo::Type::HEADER_PTR:
                                break;
                            default:
                                break;
                        }
                    } else {
                        assert(false && "not supported");
                    }
                }
            }

            void visitPhiNode(llvm::PHINode &phi) {
            }

            void visitICmpInst(llvm::ICmpInst &icmp) {
            }

            void visitLoadInst(llvm::LoadInst &load) {
                auto ptr_t = load.getPointerOperand()->getType();
                auto val_t = ptr_t->getPointerElementType();
                info = info_from_llvm_type(val_t);
            }

            void visitStoreInst(llvm::StoreInst &store) {
            }

            void visitTruncInst(llvm::TruncInst &inst) {
                info = info_from_llvm_type(inst.getType());
            }

            void visitZExtInst(llvm::ZExtInst &inst) {
                info = info_from_llvm_type(inst.getType());
            }

            void visitSExtInst(llvm::SExtInst &inst) {
                info = info_from_llvm_type(inst.getType());
            }

            void visitPtrToIntInst(llvm::PtrToIntInst &inst) {
                assert(false && "ptr to int not supported");
            }

            void visitIntToPtrInst(llvm::IntToPtrInst &inst) {
                assert(false && "int to ptr not supported");
            }

            void visitBitCastInst(llvm::BitCastInst &inst) {
                auto i = analyzer.get_reg_info(inst.getOperand(0));
                info = info_from_llvm_type(inst.getType());
            }

            void visitSelectInst(llvm::SelectInst &inst) {
                auto t_i = analyzer.get_reg_info(inst.getTrueValue());
                auto f_i = analyzer.get_reg_info(inst.getFalseValue());
                if (t_i.t == RegInfo::Type::HEADER_PTR) {
                    info = t_i;
                    info.is_known_obj = false;
                } else {
                    info = t_i;
                }
            }

            void visitCallInst(llvm::CallInst &call) {
                auto fn = call.getCalledFunction();
                if (fn == nullptr) {
                    assert(false && "analyzer: unknown function called");
                }

                auto ret_t = fn->getReturnType();
                if (ret_t->isVoidTy()) {
                    assert(false && "analyzer: tracing void type");
                } else if (ret_t->isIntegerTy()) {
                    info.t = RegInfo::Type::NUMBER;
                }
            }

            void visitBinaryOperator(llvm::BinaryOperator &binop) {
                assert(binop.getType()->isIntegerTy());
                info.t = RegInfo::Type::NUMBER;
            }
        };

        RegInfo Analyzer::get_reg_info(llvm::Value *reg) {
            if (cache_.find(reg) != cache_.end()) {
                return cache_.find(reg)->second;
            }

            RegInfo result;

            if (auto inst = llvm::dyn_cast<llvm::Instruction>(reg)) {
                // perform analysis base on instruction type
                RegInfoVisitor v(*this, result);
                v.visit(*inst);
            }

            cache_.insert({reg, result});
            return result;
        }
    }
}
