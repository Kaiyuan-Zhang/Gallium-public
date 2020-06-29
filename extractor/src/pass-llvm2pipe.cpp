#include "pass-llvm2pipe.hpp"
#include "pass-pipeline.hpp"
#include <queue>
#include <functional>
#include <boost/uuid/uuid_io.hpp>

namespace Morula {
    std::string PipeIRCtx::get_func_name(llvm::Function *f) {
        return f->getName().str();
    }

    bool PipeIRCtx::have_func(llvm::Function *f) const {
        auto fn = PipeIRCtx::get_func_name(f);
        return funcs.find(fn) != funcs.end();
    }

    void PipeIRCtx::insert_func(llvm::Function *llvm_f, std::unique_ptr<PipeIR::Function> f) {
        assert(!this->have_func(llvm_f));
        funcs[PipeIRCtx::get_func_name(llvm_f)] = std::move(f);
    }

    bool is_known_class(const std::string &type_str) {
        if (str_begin_with(type_str, "%class.Packet")) {
            return true;
        } else if (str_begin_with(type_str, "%class.Element")) {
            return true;
        }
        return false;
    }

    PipeIR::VarType *PipeIRCtx::from_llvm_type(llvm::Type *t) {
        std::string type_str;
        llvm::raw_string_ostream rso(type_str);
        t->print(rso);
        auto t_str = rso.str();
        // std::cout << t_str << std::endl;
        if (type_mapping.find(t) != type_mapping.end()) {
            return type_mapping[t].get();
        }

        std::unique_ptr<PipeIR::VarType> new_type = nullptr;
        std::shared_ptr<PipeIR::VarType> tp = std::make_shared<PipeIR::VarType>();
        type_mapping[t] = tp;
        types.push_back(tp);

        if (is_known_class(t_str)) {
            tp->EmplaceClass(t_str);
        } else if (t->isVoidTy()) {
            assert(false && "got void type");
        } else if (t->isIntegerTy()) {
            tp->EmplaceIntType(t->getIntegerBitWidth());
        } else if (t->isPointerTy()) {
            auto pointee_type = from_llvm_type(t->getPointerElementType());
            tp->EmplacePtrType(pointee_type);
        } else if (t->isStructTy()) {
            // First check if this is some known class
            std::vector<PipeIR::VarType *> ts;
            for (int i = 0; i < t->getStructNumElements(); i++) {
                ts.push_back(from_llvm_type(t->getStructElementType(i)));
            }
            tp->EmplaceStructType(ts);

            auto sl = this->llvm_layout->getStructLayout(static_cast<llvm::StructType *>(t));
            for (int i = 0; i < t->getStructNumElements(); i++) {
                tp->struct_offset.push_back(sl->getElementOffset(i));
            }
            tp->struct_num_bytes = this->llvm_layout->getTypeAllocSize(t);
        } else if (t->isArrayTy()) {
            auto ele_type = from_llvm_type(t->getArrayElementType());
            auto array_size = t->getArrayNumElements();
            tp->EmplaceArrayType(ele_type, array_size);
        } else {
            assert(false && "unknown type");
        }

        return tp.get();
    }

    void PipeIRCtx::clean_up(void) {
    }

    struct TranslationCtx {
        LLVMCtx *llvm_c;
        PipeIRCtx *pipe_c;
        std::queue<llvm::Function *> todo_list;
        std::unordered_map<llvm::Function *, PipeIR::Function *> f_map;
        std::unordered_map<llvm::Value *, std::shared_ptr<PipeIR::Var>> var_map;
        std::unordered_map<llvm::BasicBlock *, PipeIR::uuid_t> bb_end_map;
    };

    class LLVM2PipeVisitor : public llvm::InstVisitor<LLVM2PipeVisitor> {
    public:
        LLVMAnalysis::Analyzer analyzer;
        TranslationCtx &ctx;
        std::vector<std::unique_ptr<PipeIR::Operation>> ops;

        LLVM2PipeVisitor(TranslationCtx &_c) : ctx(_c) {}

        PipeIR::VarType *from_llvm_type(llvm::Type *t) {
            return ctx.pipe_c->from_llvm_type(t);
        }

        std::shared_ptr<PipeIR::Var> var_from_llvm_val(llvm::Value *val) {
            if (ctx.var_map.find(val) != ctx.var_map.end()) {
                return ctx.var_map[val];
            } else if (const llvm::ConstantInt *CI = llvm::dyn_cast<llvm::ConstantInt>(val)) {
                auto int_val = CI->getSExtValue();
                auto var = std::make_shared<PipeIR::Var>();
                var->type = PipeIR::VarType::IntType(CI->getBitWidth()).release();
                var->is_constant = true;
                var->const_val = int_val;
                return var;
            } else if (get_llvm_name(*val) == "null") {
                auto var = std::make_shared<PipeIR::Var>();
                var->type = PipeIR::VarType::PtrType(nullptr).release();
                var->is_constant = true;
                var->const_val = 0;
                return var;
            } else if (get_llvm_name(*val) == "undef") {
                auto var = std::make_shared<PipeIR::Var>();
                var->type = PipeIR::VarType::PtrType(nullptr).release();
                var->is_constant = true;
                var->const_val = -1;
                return var;
            }
            std::cerr << "could not find llvm var: " << get_llvm_name(*val) << std::endl;
            assert(false && "could not find var");
            return nullptr;
        }

        void add_dst_var_and_append_op(std::unique_ptr<PipeIR::Operation> op, llvm::Instruction &inst) {
            auto new_var = std::make_shared<PipeIR::Var>();
            op->dst_var.push_back(new_var);
            auto val_ptr = llvm::dyn_cast<llvm::Value>(&inst);
            new_var->type = from_llvm_type(inst.getType());
            new_var->from = op.get();
            assert(val_ptr);
            ctx.var_map[val_ptr] = new_var;
            ops.push_back(std::move(op));
        }

        void add_var_mapping(llvm::Value &val, std::shared_ptr<PipeIR::Var> v) {
            assert(ctx.var_map.find(&val) == ctx.var_map.end());
            ctx.var_map[&val] = v;
        }

        void visitInstruction(llvm::Instruction &inst) {
            assert(false && "unknown instruction");
        }

        void visitAllocaInst(llvm::AllocaInst &inst) {
            auto alloca_t = from_llvm_type(inst.getAllocatedType());
            auto var_t = PipeIR::VarType::PtrType(std::move(alloca_t));
            auto op = std::make_unique<PipeIR::Operation>();
            op->type = PipeIR::Operation::Type::ALLOC_TMP;
            add_dst_var_and_append_op(std::move(op), inst);
        }

        void visitGetElementPtrInst(llvm::GetElementPtrInst &inst) {
            auto op = std::make_unique<PipeIR::Operation>();
            op->type = PipeIR::Operation::Type::POINTER_OFF;
            auto dst_var_t = from_llvm_type(inst.getType());
            auto base_ptr_var = var_from_llvm_val(inst.getOperand(0));
            op->oprands.push_back(base_ptr_var);
            for (int i = 1; i < inst.getNumOperands(); i++) {
                auto off = inst.getOperand(i);
                auto off_var = var_from_llvm_val(off);
                op->oprands.push_back(off_var);
            }
            add_dst_var_and_append_op(std::move(op), inst);
        }

        void visitPhiNode(llvm::PHINode &phi) {
            // leave phi node as is, but need to use our stage uuid instead of llvm's
            auto op = std::make_unique<PipeIR::Operation>();
            op->type = PipeIR::Operation::Type::PHI;

            auto dst_type = phi.getType();

            for (auto i = 0; i < phi.getNumIncomingValues(); i++) {
                auto src_bb = phi.getIncomingBlock(i);
                auto val = phi.getIncomingValue(i);
                assert(ctx.bb_end_map.find(src_bb) != ctx.bb_end_map.end());
                auto src_uuid = ctx.bb_end_map[src_bb];
                op->phi_incoming_stages.push_back(src_uuid);
                if (const llvm::ConstantInt *CI = llvm::dyn_cast<llvm::ConstantInt>(val)) {
                    auto int_val = CI->getSExtValue();
                    auto var = std::make_shared<PipeIR::Var>();
                    var->type = PipeIR::VarType::IntType(CI->getBitWidth()).release();
                    var->const_val = int_val;
                } else {
                    assert(ctx.var_map.find(val) != ctx.var_map.end());
                    auto var = ctx.var_map[val];
                }
            }

            auto new_var = std::make_shared<PipeIR::Var>();
            op->dst_var.push_back(new_var);
            auto val_ptr = llvm::dyn_cast<llvm::Value>(&phi);
            new_var->type = from_llvm_type(dst_type);
            assert(val_ptr);
            ctx.var_map[val_ptr] = new_var;
            ops.push_back(std::move(op));
        }

        void visitICmpInst(llvm::ICmpInst &icmp) {
            auto predicate = icmp.getPredicate();
            using CMP = llvm::ICmpInst;
            static std::unordered_map<llvm::CmpInst::Predicate, std::string> op_map =
            {
                {CMP::ICMP_EQ, "eq"},
                {CMP::ICMP_NE, "ne"},
                {CMP::ICMP_SLE, "sle"},
                {CMP::ICMP_SLT, "slt"},
                {CMP::ICMP_SGE, "sge"},
                {CMP::ICMP_SGT, "sgt"},
                {CMP::ICMP_ULE, "ule"},
                {CMP::ICMP_ULT, "ult"},
                {CMP::ICMP_UGE, "uge"},
                {CMP::ICMP_UGT, "ugt"},
            };
            assert(op_map.find(predicate) != op_map.end());
            auto op_str = op_map[predicate];
            auto op = std::make_unique<PipeIR::Operation>();
            op->type = PipeIR::Operation::Type::ARITH;
            op->arith_op_name = op_str;
            for (int i = 0; i < icmp.getNumOperands(); i++) {
                auto var = var_from_llvm_val(icmp.getOperand(i));
                op->oprands.push_back(var);
            }
            add_dst_var_and_append_op(std::move(op), icmp);
        }

        void visitLoadInst(llvm::LoadInst &load) {
            auto op = std::make_unique<PipeIR::Operation>();
            op->type = PipeIR::Operation::Type::LOAD;
            op->oprands.push_back(var_from_llvm_val(load.getPointerOperand()));
            add_dst_var_and_append_op(std::move(op), load);
        }

        void visitStoreInst(llvm::StoreInst &store) {
            // get the reg info
            auto op = std::make_unique<PipeIR::Operation>();
            op->type = PipeIR::Operation::Type::STORE;
            op->oprands.push_back(var_from_llvm_val(store.getPointerOperand()));
            op->oprands.push_back(var_from_llvm_val(store.getValueOperand()));
            ops.push_back(std::move(op));
        }

        void visitTruncInst(llvm::TruncInst &inst) {
            assert(false && "trunc not supported");
        }

        void visitZExtInst(llvm::ZExtInst &zext) {
            auto op = std::make_unique<PipeIR::Operation>();
            op->type = PipeIR::Operation::Type::ARITH;
            op->arith_op_name = "zext";
            op->oprands.push_back(var_from_llvm_val(zext.getOperand(0)));
            auto var = std::make_shared<PipeIR::Var>();
            var->type = from_llvm_type(zext.getType());
            add_var_mapping(zext, var);
            ops.push_back(std::move(op));
        }

        void visitSExtInst(llvm::SExtInst &sext) {
            auto op = std::make_unique<PipeIR::Operation>();
            op->type = PipeIR::Operation::Type::ARITH;
            op->arith_op_name = "sext";
            op->oprands.push_back(var_from_llvm_val(sext.getOperand(0)));
            auto var = std::make_shared<PipeIR::Var>();
            var->type = from_llvm_type(sext.getType());
            add_var_mapping(sext, var);
            ops.push_back(std::move(op));
        }

        void visitPtrToIntInst(llvm::PtrToIntInst &inst) {
            assert(false && "ptr to int not supported");
        }

        void visitIntToPtrInst(llvm::IntToPtrInst &inst) {
            assert(false && "int to ptr not supported");
        }

        void visitBitCastInst(llvm::BitCastInst &inst) {
            auto op = std::make_unique<PipeIR::Operation>();
            op->type = PipeIR::Operation::Type::ARITH;
            op->arith_op_name = "bitcast";
            op->oprands.push_back(var_from_llvm_val(inst.getOperand(0)));
            auto var = std::make_shared<PipeIR::Var>();
            var->type = from_llvm_type(inst.getType());
            add_var_mapping(inst, var);
            op->dst_var.push_back(var);
            ops.push_back(std::move(op));
        }

        void visitSelectInst(llvm::SelectInst &inst) {
            auto cond = inst.getCondition();
            auto cond_var = var_from_llvm_val(cond);
            auto t_var = var_from_llvm_val(inst.getTrueValue());
            auto f_var = var_from_llvm_val(inst.getFalseValue());

            auto op = std::make_unique<PipeIR::Operation>();
            op->type = PipeIR::Operation::Type::ARITH;
            op->arith_op_name = "ite";
            op->oprands.push_back(cond_var);
            op->oprands.push_back(t_var);
            op->oprands.push_back(f_var);

            auto var = std::make_shared<PipeIR::Var>();
            var->type = from_llvm_type(inst.getType());
            add_var_mapping(inst, var);
            op->dst_var.push_back(var);
            ops.push_back(std::move(op));
        }

        void visitCallInst(llvm::CallInst &call) {
            // all the function calls should be state op
            auto op = std::make_unique<PipeIR::Operation>();
            op->type = PipeIR::Operation::Type::STATE_OP;
            auto fn = call.getCalledFunction();
            std::string func_name;
            if (fn == nullptr) {
                // indirect function call
                const llvm::Value* v = call.getCalledValue();
                const llvm::Value* sv = v->stripPointerCasts();
                llvm::StringRef fname = sv->getName();
                //llvm::errs() << "indirect call? " << fname << "\n";
                func_name = fname.str();
            } else {
                func_name = fn->getName().str();
            }
            if (call.isInlineAsm()) {
                auto v = call.getCalledValue();
                auto asm_inst = llvm::dyn_cast<llvm::InlineAsm>(v);
                assert(asm_inst != nullptr);
                auto asm_str = asm_inst->getAsmString();
                func_name = asm_str;
            }
            // std::cout << "CallInst: " << func_name;
            std::string f_name;
            if (cxx_demangle(func_name, f_name)) {
                func_name = f_name;
            }

            // std::cout << " demangled: " << func_name << std::endl;
            auto f1 = remove_template(func_name);
            auto f2 = remove_func_args(f1);
            auto f3 = remove_func_paran(f2);
            op->state_op_name = f3;
            if (f3 != "__assert_fail") {
                for (int i = 0; i < call.getNumArgOperands(); i++) {
                    op->oprands.push_back(var_from_llvm_val(call.getArgOperand(i)));
                }
            }

            if (!call.getType()->isVoidTy()) {
                auto var = std::make_shared<PipeIR::Var>();
                var->type = from_llvm_type(call.getType());
                add_var_mapping(call, var);
                op->dst_var.push_back(var);
            }
            ops.push_back(std::move(op));
        }

        std::string opcode_to_str(llvm::BinaryOperator::BinaryOps op) {
            using Op = llvm::BinaryOperator::BinaryOps;
            switch (op) {
                case Op::Add :
                    return "add";
                case Op::Sub:
                    return "sub";
                case Op::Mul:
                    return "mul";
                case Op::UDiv:
                    return "udiv";
                case Op::SDiv:
                    return "sdiv";
                case Op::And:
                    return "and";
                case Op::Or:
                    return "or";
                case Op::Xor:
                    return "xor";
                case Op::URem:
                    return "urem";
                case Op::SRem:
                    return "srem";
                default:
                    assert(false && "unknown binary op");
            }
        }

        void visitBinaryOperator(llvm::BinaryOperator &inst) {
            auto op = std::make_unique<PipeIR::Operation>();
            op->type = PipeIR::Operation::Type::ARITH;
            for (int i = 0; i < inst.getNumOperands(); i++) {
                op->oprands.push_back(var_from_llvm_val(inst.getOperand(i)));
            }
            auto opcode = inst.getOpcode();
            op->arith_op_name = opcode_to_str(opcode);
            auto var = std::make_shared<PipeIR::Var>();
            var->type = from_llvm_type(inst.getType());
            add_var_mapping(inst, var);
            op->dst_var.push_back(var);
            ops.push_back(std::move(op));
        }
    };

    static std::unique_ptr<PipeIR::Function> translate_llvm_func(llvm::Function *f,
                                                                 TranslationCtx &ctx) {
        auto fn = PipeIRCtx::get_func_name(f);
        std::unordered_map<llvm::BasicBlock *, int> bb2stage;
        std::vector<std::unique_ptr<PipeIR::Stage>> stages;

        std::cout << "translating function: " << fn << std::endl;

        auto pipe_f = std::make_unique<PipeIR::Function>();
        for (auto iter = f->arg_begin(); iter != f->arg_end(); iter++) {
            llvm::Argument &a = *iter;
            auto arg_t = PipeIR::VarType::ArgType().release();
            auto arg_var = std::make_shared<PipeIR::Var>();
            arg_var->type = arg_t;
            ctx.var_map[&a] = arg_var;
            pipe_f->params_.push_back(arg_var);
        }

        for (auto iter = f->begin(); iter != f->end(); iter++) {
            llvm::BasicBlock *bb = &*iter;
            auto s = std::make_unique<PipeIR::Stage>();
            s->name = fn + "_" + get_llvm_name(*iter);
            // std::cout << "insert bb: " << bb << std::endl;
            bb2stage[bb] = stages.size();
            stages.push_back(std::move(s));
        }

        std::cout << "entry bb ptr: " << &f->getEntryBlock() << std::endl;
        assert(bb2stage.find(&f->getEntryBlock()) != bb2stage.end());

        LLVM2PipeVisitor visitor(ctx);

        auto create_stage = [](LLVM2PipeVisitor &v) -> std::unique_ptr<PipeIR::Stage> {
            auto result = std::make_unique<PipeIR::Stage>();
            result->ops = std::move(v.ops);
            v.ops.clear();
            return result;
        };

        auto update_stage = [](LLVM2PipeVisitor &v, PipeIR::Stage *s) -> void {
            s->ops = std::move(v.ops);
            v.ops.clear();
        };

        for (auto iter = f->begin(); iter != f->end(); iter++) {
            llvm::BasicBlock *bb = &*iter;
            assert(bb2stage.find(bb) != bb2stage.end());
            auto idx = bb2stage[bb];
            PipeIR::Stage *s_ptr = stages[idx].get();
            bool is_new_stage = false;
            int num_stage_in_bb = 1;
            std::string bb_name_base = get_llvm_name(*iter);
            for (auto iter = bb->begin(); iter != bb->end(); iter++) {
                llvm::BasicBlock::iterator iter_copy = iter;
                iter_copy++;
                if (should_ignore_inst(&*iter)) {
                    continue;
                }
                // std::cout << get_llvm_inst_str(&*iter) << std::endl;
                bool use_visitor = true;
                if (auto call = llvm::dyn_cast<llvm::CallInst>(iter)) {
                    // create new basic block
                    auto llvm_f = call->getCalledFunction();
                    if (llvm_f == nullptr) {
                        // indirect function call
                        const llvm::Value* v = call->getCalledValue();
                        const llvm::Value* sv = v->stripPointerCasts();
                        if (auto c = llvm::dyn_cast<llvm::Function>(sv)) {
                            llvm_f = const_cast<llvm::Function *>(c);
                        } else if (auto c = llvm::dyn_cast<llvm::Function>(v)) {
                            llvm_f = const_cast<llvm::Function *>(c);
                        }
                        llvm::StringRef fname = sv->getName();
                    }
                    // check if this is a known function (therefore does not need to expand)
                    if (should_inline(call)) {
                        assert(llvm_f != nullptr);
                        use_visitor = false;
                        ctx.todo_list.push(llvm_f);
                        update_stage(visitor, s_ptr);
                        s_ptr->terminator_type = PipeIR::StageTerminatorType::FUNC_CALL;
                        s_ptr->func_called = llvm_f->getName().str();
                        for (int i = 0; i < call->getNumArgOperands(); i++) {
                            auto param_var = visitor.var_from_llvm_val(call->getArgOperand(i));
                            s_ptr->call_params.push_back(param_var);
                        }

                        // also need to create a new stage
                        if (iter_copy == bb->end()) {
                            // if this call is the last instruction in the basic block (which is unlikely)
                            // we do nothing
                        } else {
                            auto new_stage = std::make_unique<PipeIR::Stage>();
                            new_stage->name = fn + "_" + bb_name_base + "_"
                                              + std::to_string(num_stage_in_bb++);
                            s_ptr->next_stages.push_back(new_stage.get());
                            update_stage(visitor, s_ptr);
                            s_ptr = new_stage.get();
                            idx = stages.size();
                            stages.push_back(std::move(new_stage));
                        }
                    }
                } else if (iter_copy == bb->end()) {
                    // the last instruction
                    use_visitor = false;
                    if (auto branch_inst = llvm::dyn_cast<llvm::BranchInst>(iter)) {
                        s_ptr->terminator_type = PipeIR::StageTerminatorType::BRANCH;
                        if (branch_inst->isConditional()) {
                            auto cond = visitor.var_from_llvm_val(branch_inst->getCondition());
                            s_ptr->cond_vars.push_back(cond.get());
                        }
                        for (auto i = 0; i < branch_inst->getNumSuccessors(); i++) {
                            auto next_bb = branch_inst->getSuccessor(i);
                            assert(bb2stage.find(next_bb) != bb2stage.end());
                            auto next_bb_idx = bb2stage[next_bb];
                            s_ptr->next_stages.push_back(stages[next_bb_idx].get());
                        }
                    } else if (auto ret_inst = llvm::dyn_cast<llvm::ReturnInst>(iter)) {
                        s_ptr->terminator_type = PipeIR::StageTerminatorType::RETURN;
                        auto ret_val_llvm = ret_inst->getReturnValue();
                        if (ret_val_llvm != nullptr && !ret_val_llvm->getType()->isVoidTy()) {
                            auto ret_val = visitor.var_from_llvm_val(ret_val_llvm);
                            s_ptr->ret_vals.push_back(ret_val);
                        }
                    } else if (auto switch_inst = llvm::dyn_cast<llvm::SwitchInst>(iter)) {
                        s_ptr->terminator_type = PipeIR::StageTerminatorType::SWITCH;
                        auto cond = visitor.var_from_llvm_val(switch_inst->getCondition());
                        s_ptr->cond_vars.push_back(cond.get());
                        for (auto iter = switch_inst->case_begin(); iter != switch_inst->case_end(); iter++) {
                            s_ptr->switch_cases.push_back(iter->getCaseValue()->getSExtValue());
                            auto case_bb = iter->getCaseSuccessor();
                            assert(bb2stage.find(case_bb) != bb2stage.end());
                            s_ptr->next_stages.push_back(stages[bb2stage[case_bb]].get());
                        }
                    } else if (auto unreachable = llvm::dyn_cast<llvm::UnreachableInst>(iter)) {
                        s_ptr->terminator_type = PipeIR::StageTerminatorType::FAULT;
                    } else {
                        assert(false && "unknown last inst");
                    }
                }
                if (use_visitor) {
                    // use the visitor to translate the instruction
                    visitor.visit(*iter);
                }
            }
            update_stage(visitor, s_ptr);
        }

        assert(bb2stage.find(&f->getEntryBlock()) != bb2stage.end());
        pipe_f->entry_bb = stages[bb2stage[&f->getEntryBlock()]]->get_uuid();
        for (auto &p : stages) {
            pipe_f->bbs_[p->get_uuid()] = std::move(p);
        }
        ctx.var_map.clear();
        ctx.bb_end_map.clear();
        return pipe_f;
    }

    void print_terminator(std::ostream &os, const PipeIR::Stage &stage, unsigned line_limit) {
        using TT = PipeIR::StageTerminatorType;
        switch (stage.terminator_type) {
            case TT::BRANCH:
                os << "branch ";
                if (stage.cond_vars.size() > 0) {
                    stage.cond_vars[0]->print(os);
                }
                for (int i = 0; i < stage.next_stages.size(); i++) {
                    os << " " << str_escape_html(str_line_break(stage.next_stages[i]->name, line_limit, "\n"));
                }
                break;
            case TT::FAULT:
                os << "(fault)";
                break;
            case TT::FUNC_CALL:
                os << "call " << stage.func_called << " with params [";
                for (int i = 0; i < stage.call_params.size(); i++) {
                    if (i != 0) {
                        os << ", ";
                    }
                    auto &a = stage.call_params[i];
                    a->print(os);
                }
                os << "]";
                break;
            case TT::NEXT_DEV:
                os << "(to next dev)";
                break;
            case TT::RETURN:
                os << "return";
                break;
            case TT::SWITCH:
                os << "(switch ";
                assert(stage.cond_vars.size() == 1);
                stage.cond_vars[0]->print(os);
                os << " ";
                for (int i = 0; i < stage.switch_cases.size(); i++) {
                    os << "(" << stage.switch_cases[i] << " --&gt; ";
                    os << str_escape_html(str_line_break(stage.next_stages[i]->name, line_limit, "\n"));
                    os << ")";
                }
                break;
            case TT::TABLE_DISPATCH:
                os << "(table dispatch)";
                break;
            default:
                os << "unknown terminator";
                break;
        }
    }

    void generate_graphviz(std::ostream &os, const PipeIRCtx &ctx, unsigned line_limit) {
        PipeIR::uuid_unordered_map_t<PipeIR::uuid_unordered_set_t> edge_map;
        os << "digraph cfg {" << std::endl;
        for (auto &kv : ctx.funcs) {
            auto &func_name = kv.first;
            for (auto &stage_kv : kv.second->bbs_) {
                auto &stage_uuid = stage_kv.first;
                // print instructions in the stage
                auto stage_ptr = stage_kv.second.get();
                auto &ops = stage_ptr->ops;
                auto stage_name = get_bb_name_for_graphviz(stage_ptr->name);
                if (stage_ptr->terminator_type == PipeIR::StageTerminatorType::RETURN) {
                    stage_name = ctx.name_gen->gen(stage_name + "_return");
                }
                stage_name = str_line_break(stage_name, line_limit, "\n");

                os << "\"stage_" << boost::uuids::to_string(stage_uuid) << "\"";
                os << " [" << std::endl << "shape=none" << std::endl;
                // print instructions, we use html style label
                os << "label = <<table border=\"0\" cellspacing=\"0\">" << std::endl;
                os << "<tr><td port=\"title\" border=\"1\" bgcolor=\"black\">"
                << "<font color=\"white\">"
                << str_escape_html(stage_name)
                << "</font>"
                << "</td></tr>"
                << std::endl;
                for (int i = 0; i < ops.size(); i++) {
                    auto op_ptr = ops[i].get();
                    auto op_str = op_to_str(*op_ptr);
                    // if (op_str.size() > line_limit - 3) {
                    //     op_str = op_str.substr(0, line_limit - 3) + "...";
                    // }
                    op_str = str_escape_html(str_line_break(op_str, line_limit, "\n"));
                    auto port_str = "port" + std::to_string(i);
                    os << "<tr><td port=\"" << port_str << "\" ";
                    os << "border=\"1\"";
                    if (op_ptr->color_str) {
                        os << " bgcolor=\"" << *(op_ptr->color_str) << "\"";
                    }
                    os << ">"
                       << op_str
                       << "</td></tr>"
                       << std::endl;
                }
                // print terminator:
                os << "<tr><td border=\"1\" bgcolor=\"gray\">";
                print_terminator(os, *stage_ptr, line_limit);
                os << "</td></tr>" << std::endl;
                os << "</table>>" << std::endl;
                os << "];" << std::endl;
            }
        }

        for (auto &kv : ctx.funcs) {
            auto &func_name = kv.first;
            for (auto &stage_kv : kv.second->bbs_) {
                std::string stage_name = "stage_" + boost::uuids::to_string(stage_kv.first);
                auto stage_ptr = stage_kv.second.get();
                for (int i = 0; i < stage_ptr->next_stages.size(); i++) {
                    auto dst_stage_ptr = stage_ptr->next_stages[i];
                    auto dst_uuid = dst_stage_ptr->get_uuid();
                    std::string dst_stage_name = "stage_" + boost::uuids::to_string(dst_uuid);
                    os << "\"" << stage_name << "\":s -> \"";
                    os << dst_stage_name << "\":n";
                    os << ";" << std::endl;
                }
            }
        }
        os << "}" << std::endl;
    }

    void global_state_from_click(
        Click::ElementStateType &t,
        std::unordered_map<
            std::string,
            std::shared_ptr<PipeIR::GlobalState>> &state) {
        for (auto &e : t.field_type) {
            if (e.type == Click::StateEntry::T::STRUCT) {
                global_state_from_click(*e.struct_rec, state);
            } else if (e.type != Click::StateEntry::T::UNKNOWN) {
                auto gs = std::make_shared<PipeIR::GlobalState>();
                gs->type = PipeIR::GlobalState::Type::CLICK_STATE;
                gs->name_anno = e.state_name;
                gs->click_t = e;
                state.insert({e.state_name, gs});
            }
        }
    }

    PASS_IMPL(LLVM2PipeP1, s) {
        auto ctx = std::make_unique<PipeIRCtx>();
        ctx->name_gen = std::make_shared<NameFactory>("_");
        ctx->module = std::move(s->module);
        ctx->llvm_layout = std::make_shared<llvm::DataLayout>(ctx->module.get());

        /* Step 0: initilize Translation Ctx */
        TranslationCtx translate_ctx;
        translate_ctx.llvm_c = s.get();
        translate_ctx.pipe_c = ctx.get();

        /* Step 1: start from the entry function */
        translate_ctx.todo_list.push(s->entry_func);

        /* Step 2: start from entry recursively process all function
         *  This should simply be a line-by-line translation.
         *  For each load / store instruction, we perform a var trace
         *  to check whether it is a packet header or global state
         */
        while (!translate_ctx.todo_list.empty()) {
            auto f = translate_ctx.todo_list.front();
            translate_ctx.todo_list.pop();

            auto f_name = PipeIRCtx::get_func_name(f);
            if (!ctx->have_func(f)) {
                auto pipe_fn = translate_llvm_func(f, translate_ctx);
                ctx->funcs.insert({f_name, std::move(pipe_fn)});
            }
        }

        ctx->entry_name = PipeIRCtx::get_func_name(s->entry_func);

        /* Step 3: create globalstates from the element state record 
         * note that we only create records for KNOWN state 
         * unknown states will be ignored 
         */
        ctx->states.clear();
        ctx->element_state = s->element_state;
        global_state_from_click(*ctx->element_state, ctx->states);

        return ctx;
    }

    bool have_recursion(const PipeIRCtx &ctx,
                        const PipeIR::Function *func,
                        std::unordered_set<const PipeIR::Function *> &visited_funcs) {
        if (visited_funcs.find(func) != visited_funcs.end()) {
            std::cerr << "got recursive func: " << func << std::endl;
            assert(false);
            return true;
        }

        visited_funcs.insert(func);
        for (auto &kv : func->bbs_) {
            auto bb_ptr = kv.second.get();
            if (bb_ptr->terminator_type == PipeIR::StageTerminatorType::FUNC_CALL) {
                auto fn = bb_ptr->func_called;
                assert(ctx.funcs.find(fn) != ctx.funcs.end());
                const PipeIR::Function *fn_ptr = ctx.funcs.find(fn)->second.get();
                if (have_recursion(ctx, fn_ptr, visited_funcs)) {
                    return true;
                }
            }
        }

        visited_funcs.erase(func);

        return false;
    }

    struct InlineCtx {
        PipeIRCtx *ctx;
        PipeIR::uuid_unordered_map_t<std::unique_ptr<PipeIR::Stage>> *bbs;
        std::unordered_map<std::string, int> num_inline;
    };

    class PipeOpRewriteVisitor : public PipeIR::OperationVisitor<std::unique_ptr<PipeIR::Operation>> {
    public:
        using RetT = std::unique_ptr<PipeIR::Operation>;

        std::unordered_map<PipeIR::Var *,
                           std::shared_ptr<PipeIR::Var>> *var_mapping;
        PipeIR::uuid_unordered_map_t<PipeIR::Stage *> *stage_mapping;

        void copy_dst_vars(PipeIR::Operation &dst, PipeIR::Operation &src) {
            for (int i = 0; i < src.dst_var.size(); i++) {
                assert(var_mapping->find(src.dst_var[i].get()) != var_mapping->end());
                //auto new_var = std::make_shared<PipeIR::Var>(*src.dst_var[i]);
                //(*var_mapping)[src.dst_var[i]] = new_var;
                dst.dst_var.push_back((*var_mapping)[src.dst_var[i].get()]);
            }
        }

        void copy_oprands(PipeIR::Operation &dst, PipeIR::Operation &src) {
            for (int i = 0; i < src.oprands.size(); i++) {
                if (src.oprands[i]->is_constant) {
                    dst.oprands.push_back(src.oprands[i]);
                    continue;
                }
                auto iter = var_mapping->find(src.oprands[i].get());
                assert(iter != var_mapping->end());
                auto new_var = iter->second;
                dst.oprands.push_back(new_var);
            }
        }

        virtual RetT visitNop(PipeIR::Operation &op) override {
            return nullptr;
        }

        virtual RetT visitArith(PipeIR::Operation &op) override {
            auto new_op = std::make_unique<PipeIR::Operation>();
            new_op->type = op.type;
            copy_dst_vars(*new_op, op);
            copy_oprands(*new_op, op);
            new_op->arith_op_name = op.arith_op_name;

            return new_op;
        }

        virtual RetT visitAllocTmp(PipeIR::Operation &op) override {
            auto new_op = std::make_unique<PipeIR::Operation>();
            new_op->type = op.type;
            copy_dst_vars(*new_op, op);
            copy_oprands(*new_op, op);
            return new_op;
        }

        virtual RetT visitPhi(PipeIR::Operation &op) override {
            auto new_op = std::make_unique<PipeIR::Operation>();
            new_op->type = op.type;
            copy_dst_vars(*new_op, op);
            copy_oprands(*new_op, op);
            for (int i = 0; i < op.phi_incoming_stages.size(); i++) {
                auto &s = op.phi_incoming_stages[i];
                auto iter = stage_mapping->find(s);
                assert(iter != stage_mapping->end());
                new_op->phi_incoming_stages.push_back(iter->second->get_uuid());
            }

            for (int i = 0; i < op.phi_incoming_vals.size(); i++) {
                auto &v = op.phi_incoming_vals[i];
                auto iter = var_mapping->find(v.get());
                assert(iter != var_mapping->end());
                new_op->phi_incoming_vals.push_back(iter->second);
            }

            return new_op;
        }

        virtual RetT visitStateOp(PipeIR::Operation &op) override {
            auto new_op = std::make_unique<PipeIR::Operation>();
            new_op->type = op.type;
            copy_dst_vars(*new_op, op);
            copy_oprands(*new_op, op);
            new_op->state_op_name = op.state_op_name;
            new_op->state = op.state;
            return new_op;
        }

        virtual RetT visitPointerOffOp(PipeIR::Operation &op) override {
            auto new_op = std::make_unique<PipeIR::Operation>();
            new_op->type = op.type;
            copy_dst_vars(*new_op, op);
            copy_oprands(*new_op, op);
            return new_op;
        }

        virtual RetT visitLoadOp(PipeIR::Operation &op) override {
            auto new_op = std::make_unique<PipeIR::Operation>();
            new_op->type = op.type;
            copy_dst_vars(*new_op, op);
            copy_oprands(*new_op, op);
            return new_op;
        }

        virtual RetT visitStoreOp(PipeIR::Operation &op) override {
            auto new_op = std::make_unique<PipeIR::Operation>();
            new_op->type = op.type;
            copy_dst_vars(*new_op, op);
            copy_oprands(*new_op, op);
            return new_op;
        }
    };

    struct InlineFuncRet {
        PipeIR::uuid_t entry_bb;
        PipeIR::uuid_unordered_set_t ret_bb;
    };

    InlineFuncRet inline_func(const std::string &func, InlineCtx &ctx,
                              const std::vector<std::shared_ptr<PipeIR::Var>> &params) {
        InlineFuncRet ret;
        assert(ctx.ctx->funcs.find(func) != ctx.ctx->funcs.end());
        auto f = ctx.ctx->funcs.find(func)->second.get();

        // create variable rewrite mapping
        // first create for parameter
        std::unordered_map<PipeIR::Var *,
                           std::shared_ptr<PipeIR::Var>> var_mapping;
        PipeIR::uuid_t new_entry_uuid;
        assert(f->params_.size() == params.size());
        for (int i = 0; i < params.size(); i++) {
            var_mapping[f->params_[i].get()] = params[i];
        }

        int cnt = ctx.num_inline[func]++;
        PipeIR::uuid_unordered_map_t<PipeIR::Stage *> stage_mapping;
        std::vector<PipeIR::uuid_t> bb_stages;
        for (auto &kv : f->bbs_) {
            auto bb_ptr = kv.second.get();
            auto new_bb = std::make_unique<PipeIR::Stage>();
            new_bb->name = bb_ptr->name + "_inline_" + std::to_string(cnt);
            assert(stage_mapping.find(bb_ptr->get_uuid()) == stage_mapping.end());
            stage_mapping[bb_ptr->get_uuid()] = new_bb.get();
            ctx.bbs->insert({new_bb->get_uuid(), std::move(new_bb)});
            for (auto &op : bb_ptr->ops) {
                for (auto &v : op->dst_var) {
                    auto new_var = std::make_shared<PipeIR::Var>(*v);
                    var_mapping[v.get()] = new_var;
                }
            }
            bb_stages.push_back(kv.first);
        }

        PipeOpRewriteVisitor visitor;
        visitor.var_mapping = &var_mapping;
        visitor.stage_mapping = &stage_mapping;
        for (auto &bb_id : bb_stages) {
            auto bb_ptr = f->bbs_[bb_id].get();
            auto new_bb = stage_mapping[bb_id];
            for (auto &op : bb_ptr->ops) {
                auto new_op = visitor.visit(*op);
                if (new_op != nullptr) {
                    new_bb->ops.push_back(std::move(new_op));
                }
            }
            new_bb->cond_vars.clear();
            new_bb->next_stages.clear();
            switch (bb_ptr->terminator_type) {
                using T = PipeIR::StageTerminatorType;
                case T::FUNC_CALL:
                    {
                        auto called_func_name = bb_ptr->func_called;
                        auto inline_ret = inline_func(called_func_name, ctx, bb_ptr->call_params);
                        assert(ctx.bbs->find(inline_ret.entry_bb) != ctx.bbs->end());
                        new_bb->terminator_type = T::BRANCH;
                        new_bb->next_stages.push_back((*ctx.bbs)[inline_ret.entry_bb].get());
                        auto origin_next = bb_ptr->next_stages[0];
                        auto next_id = origin_next->get_uuid();
                        assert(stage_mapping.find(next_id) != stage_mapping.end());
                        auto next_stage = stage_mapping[next_id];
                        for (auto &id : inline_ret.ret_bb) {
                            auto iter = ctx.bbs->find(id);
                            assert(iter != ctx.bbs->end());
                            auto &bb = iter->second;
                            bb->terminator_type = T::BRANCH;
                            bb->cond_vars.clear();
                            bb->next_stages.clear();
                            bb->next_stages.push_back(next_stage);
                        }
                    }
                    break;
                case T::RETURN:
                    ret.ret_bb.insert(new_bb->get_uuid());
                    break;
                case T::BRANCH:
                    {
                        new_bb->terminator_type = T::BRANCH;
                        for (int i = 0; i < bb_ptr->cond_vars.size(); i++) {
                            auto &v = bb_ptr->cond_vars[i];
                            auto iter = var_mapping.find(v);
                            assert(iter != var_mapping.end());
                            new_bb->cond_vars.push_back(iter->second.get());
                        }
                        for (int i = 0; i < bb_ptr->next_stages.size(); i++) {
                            auto &next_stage = bb_ptr->next_stages[i];
                            auto id = next_stage->get_uuid();
                            auto iter = stage_mapping.find(id);
                            assert(iter != stage_mapping.end());
                            new_bb->next_stages.push_back(iter->second);
                        }
                    }
                    break;
                case T::SWITCH:
                    new_bb->terminator_type = T::SWITCH;
                    for (int i = 0; i < bb_ptr->cond_vars.size(); i++) {
                        auto &v = bb_ptr->cond_vars[i];
                        auto iter = var_mapping.find(v);
                        assert(iter != var_mapping.end());
                        new_bb->cond_vars.push_back(iter->second.get());
                    }
                    new_bb->switch_cases.clear();
                    for (int i = 0; i < bb_ptr->switch_cases.size(); i++) {
                        new_bb->switch_cases.push_back(bb_ptr->switch_cases[i]);
                    }
                    for (int i = 0; i < bb_ptr->next_stages.size(); i++) {
                        auto &next_stage = bb_ptr->next_stages[i];
                        auto id = next_stage->get_uuid();
                        auto iter = stage_mapping.find(id);
                        assert(iter != stage_mapping.end());
                        new_bb->next_stages.push_back(iter->second);
                    }
                    break;
                case T::FAULT:
                    new_bb->terminator_type = T::FAULT;
                    break;
                default:
                    assert(false && "unknown stage terminator");
            }
        }

        assert(stage_mapping.find(f->entry_bb) != stage_mapping.end());
        new_entry_uuid = stage_mapping[f->entry_bb]->get_uuid();
        assert(ctx.bbs->find(new_entry_uuid) != ctx.bbs->end());
        ret.entry_bb = new_entry_uuid;
        return ret;
    }

    PASS_IMPL(PipeP1Inline, s) {
        assert(s->funcs.find(s->entry_name) != s->funcs.end());
        auto main_f = std::make_unique<PipeIR::Function>();

        for (auto &kv : s->funcs) {
            std::cout << "Function " << kv.first << " : " << kv.second.get() << std::endl;
        }
        // first check that there is no recursion
        auto entry_f = s->funcs.find(s->entry_name)->second.get();
        std::unordered_set<const PipeIR::Function *> visited_funcs;
        assert(!have_recursion(*s, entry_f, visited_funcs));

        InlineCtx inline_ctx;
        for (auto &kv : entry_f->bbs_) {
            auto bb_ptr = kv.second.get();
            if (bb_ptr->terminator_type == PipeIR::StageTerminatorType::FUNC_CALL) {
                std::cout << "Start inlining: " << bb_ptr->func_called << std::endl;
                PipeIR::uuid_unordered_map_t<std::unique_ptr<PipeIR::Stage>> bbs;
                inline_ctx.ctx = s.get();
                inline_ctx.bbs = &bbs;

                auto called_func_name = bb_ptr->func_called;
                auto inline_ret = inline_func(called_func_name, inline_ctx, bb_ptr->call_params);
                assert(inline_ctx.bbs->find(inline_ret.entry_bb) != inline_ctx.bbs->end());
                assert(bb_ptr->next_stages.size() == 1);
                auto origin_next = bb_ptr->next_stages[0];
                auto next_id = origin_next->get_uuid();

                bb_ptr->terminator_type = PipeIR::StageTerminatorType::BRANCH;
                bb_ptr->next_stages.push_back((*inline_ctx.bbs)[inline_ret.entry_bb].get());

                auto iter = entry_f->bbs_.find(next_id);
                assert(iter != entry_f->bbs_.end());
                auto next_stage = iter->second.get();
                for (auto &id : inline_ret.ret_bb) {
                    auto iter = inline_ctx.bbs->find(id);
                    assert(iter != inline_ctx.bbs->end());
                    auto &bb = iter->second;
                    bb->terminator_type = PipeIR::StageTerminatorType::BRANCH;
                    bb->cond_vars.clear();
                    bb->next_stages.clear();
                    bb->next_stages.push_back(next_stage);
                }

                for (auto &new_bb_kv : bbs) {
                    entry_f->bbs_.insert(std::move(new_bb_kv));
                }
            }
        }

        std::vector<std::string> to_remove;
        for (auto &kv : s->funcs) {
            if (kv.first != s->entry_name) {
                to_remove.push_back(kv.first);
            }
        }

        for (auto &n : to_remove) {
            s->funcs.erase(n);
        }
        return s;
    }

    PASS_IMPL(PipeUpdateUseDef, ctx) {
        auto clear_var_meta = [](PipeIR::Var *v) -> void {
            v->from = nullptr;
            v->uses.clear();
            v->branch_uses.clear();
            v->func_call_uses.clear();
        };
        for (auto &f_kv : ctx->funcs) {
            for (auto &v : f_kv.second->params_) {
                clear_var_meta(v.get());
            }
            for (auto &stage_kv : f_kv.second->bbs_) {
                auto bb_ptr = stage_kv.second.get();
                for (auto &op : bb_ptr->ops) {
                    for (auto &v : op->dst_var) {
                        clear_var_meta(v.get());
                    }
                    for (auto &v : op->oprands) {
                        clear_var_meta(v.get());
                    }
                    for (auto &v : op->vars_read()) {
                        clear_var_meta(v);
                    }
                    for (auto &v : op->vars_written()) {
                        clear_var_meta(v);
                    }
                }
            }
        }

        for (auto &f_kv : ctx->funcs) {
            for (auto &stage_kv : f_kv.second->bbs_) {
                auto bb_ptr = stage_kv.second.get();
                bb_ptr->parent = f_kv.second.get();
                for (int i = 0; i < bb_ptr->ops.size(); i++) {
                    auto op_ptr = bb_ptr->ops[i].get();
                    op_ptr->parent = bb_ptr;
                    op_ptr->idx_in_stage = i;

                    for (auto &v : op_ptr->vars_read()) {
                        v->uses.insert(op_ptr);
                    }

                    for (auto &v : op_ptr->dst_var) {
                        v->from = op_ptr;
                    }
                }
                if (bb_ptr->terminator_type == PipeIR::StageTerminatorType::BRANCH) {
                    for (auto &v : bb_ptr->cond_vars) {
                        v->branch_uses.insert(bb_ptr);
                    }
                } else if (bb_ptr->terminator_type == PipeIR::StageTerminatorType::SWITCH) {
                    for (auto &v : bb_ptr->cond_vars) {
                        v->branch_uses.insert(bb_ptr);
                    }
                } else if (bb_ptr->terminator_type == PipeIR::StageTerminatorType::FUNC_CALL) {
                    for (auto &v : bb_ptr->call_params) {
                        v->func_call_uses.insert(bb_ptr);
                    }
                }
            }
        }

        std::cout << "===========================================" << std::endl;
        for (auto &f_kv : ctx->funcs) {
            for (auto &stage_kv : f_kv.second->bbs_) {
                auto bb_ptr = stage_kv.second.get();
                bb_ptr->parent = f_kv.second.get();
                for (int i = 0; i < bb_ptr->ops.size(); i++) {
                    auto op_ptr = bb_ptr->ops[i].get();
                    for (auto &v : op_ptr->dst_var) {
                        v->print(std::cout);
                        std::cout << " :: " << std::endl;
                        for (auto &u : v->uses) {
                            std::cout << "    ";
                            std::cout << u->parent->name << " "
                                      << u->idx_in_stage << std::endl;
                        }
                        std::cout << "  branch : " << std::endl;
                        for (auto &s : v->branch_uses) {
                            std::cout << "    ";
                            std::cout << s->name << std::endl;
                        }
                        std::cout << "  func_call : " << std::endl;
                        for (auto &s : v->func_call_uses) {
                            std::cout << "    ";
                            std::cout << s->name << std::endl;
                        }
                    }
                    std::cout << std::endl;
                }
            }
        }
        return ctx;
    }
}
