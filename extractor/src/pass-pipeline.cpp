#include "pass-pipeline.hpp"
#include <boost/uuid/uuid_io.hpp>
#include "llvm-vartrace.hpp"
#include <queue>


namespace Morula {
    bool should_inline(llvm::CallInst *call) {
        static std::unordered_set<std::string> noninline_func = {
            "Packet::uniqueify",
            "WritablePacket::ip_header const",
            "Packet::ip_header const",
            "Packet::transport_length const",
            "Packet::has_network_header const",
            "WritablePacket::ip_header const",
            "Packet::transport_header const",

            "Vector::operator[]",
            "Packet::kill",
            "HashMap::findp const",
            "HashMap::insert",

            "Element::checked_output_push const",
            "click_jiffies",
            "__assert_fail",

            "llvm.memcpy.p0i8.p0i8.i64",
        };
        auto fn = call->getCalledFunction();
        if (fn == nullptr) {
            return false;
        }
        auto func_name = fn->getName().str();
        // std::cout << "CallInst: " << func_name;
        std::string f_name;
        if (cxx_demangle(func_name, f_name)) {
            func_name = f_name;
        }

        auto f1 = remove_template(func_name);
        auto f2 = remove_func_args(f1);
        auto f3 = remove_func_paran(f2);

        if (noninline_func.find(f3) != noninline_func.end()) {
            return false;
        }
        return true;
    }

    std::string get_bb_name_for_graphviz(const std::string &s) {
        return "bb_" + str_replace_all(s, "%", "_");
    }

    bool should_ignore_inst(llvm::Instruction *inst) {
        if (auto call = llvm::dyn_cast<llvm::CallInst>(inst)) {
            auto fn = call->getCalledFunction();
            if (fn == nullptr) {
                return false;
            }
            auto func_name = fn->getName().str();
            if (str_begin_with(func_name, "llvm.dbg.") ||
                str_begin_with(func_name, "llvm.lifetime")) {
                return true;
            }
        }
        return false;
    }

    struct TranslateCtx {
        std::unordered_map<PipeIR::uuid_t, std::unique_ptr<PipeIR::PreStage>,
                           boost::hash<PipeIR::uuid_t>> stages;
        std::unordered_map<llvm::Function *, PipeIR::PreStage *> func_map;
        std::unordered_map<llvm::Function *, int> num_called;
        std::unordered_map<llvm::BasicBlock *, PipeIR::PreStage *> bb_map;

        // this map is for phi node
        // mapping from llvm::BasicBlock to the stage where the basic block ends
        std::unordered_map<llvm::BasicBlock *, PipeIR::uuid_t> bb_end_map;
    };

    void translate_func(llvm::Function *func, TranslateCtx &ctx,
                        PipeIR::PreStage *curr_stage,
                        PipeIR::PreStage *continue_stage);

    void translate_bb_part(llvm::BasicBlock *bb, llvm::BasicBlock::iterator inst_i,
                           const std::string &curr_func_prefix,
                           TranslateCtx &ctx, PipeIR::PreStage *curr_stage,
                           PipeIR::PreStage *continue_stage) {
        std::cout << "Filling " << get_llvm_name(*bb) << " "
                  << curr_stage->get_uuid() << std::endl;
        for (; inst_i != bb->end(); inst_i++) {
            /**
             * Basic block should be a single stage, unless
             * 1. This is a call instruction
             */
            if (should_ignore_inst(&*inst_i)) {
                continue;
            }
            llvm::BasicBlock::iterator iter_copy = inst_i;
            iter_copy++;
            if (auto phi = llvm::dyn_cast<llvm::PHINode>(inst_i)) {
                std::cout << "PHI:: " << get_llvm_inst_str(&*inst_i) << std::endl;
                curr_stage->insts.push_back(&*inst_i);
            } else if (auto call = llvm::dyn_cast<llvm::CallInst>(inst_i)) {
                // std::cout << get_llvm_inst_str(&*inst_i) << std::endl;
                auto fn = call->getCalledFunction();
                int func_num_called = ctx.num_called[fn]++;
                if (should_inline(call)) {
                    // break basic block into two
                    // if this instruction is the last one in the basic block,
                    // then we don't have to create an extra stage
                    std::cout << "found inline call inst" << get_llvm_inst_str(call) << std::endl;
                    PipeIR::PreStage *after_call_stage = continue_stage;
                    if (iter_copy != bb->end()) {
                        // call is not the last instruction in the basic block
                        auto next_stage = std::make_unique<PipeIR::PreStage>();
                        PipeIR::PreStage *next_ptr = next_stage.get();
                        next_stage->name = "after_call_" + fn->getName().str()
                                           + std::to_string(func_num_called);
                        std::cout << "inserting bb: " << next_stage->name << std::endl;
                        ctx.stages.insert({next_stage->get_uuid(), std::move(next_stage)});
                        translate_bb_part(bb, iter_copy, curr_func_prefix, ctx, next_ptr, continue_stage);
                        after_call_stage = next_ptr;
                    }
                    PipeIR::PreStage *f_stage_ptr = nullptr;
                    if (ctx.func_map.find(fn) != ctx.func_map.end()) {
                        f_stage_ptr = ctx.func_map.find(fn)->second;
                    } else {
                        auto f_stage = std::make_unique<PipeIR::PreStage>();
                        f_stage->name = "call_" + fn->getName().str();
                        f_stage_ptr = f_stage.get();
                        std::cout << "inserting bb: " << f_stage->name << std::endl;
                        ctx.stages.insert({f_stage->get_uuid(), std::move(f_stage)});
                        ctx.func_map.insert({fn, f_stage_ptr});
                        translate_func(fn, ctx, f_stage_ptr, after_call_stage);
                    }
                    curr_stage->next_stages.push_back(f_stage_ptr);
                    curr_stage->terminator_type = PipeIR::StageTerminatorType::BRANCH;
                    return;
                } else {
                    curr_stage->insts.push_back(&*inst_i);
                }
            } else if (auto ret = llvm::dyn_cast<llvm::ReturnInst>(inst_i)) {
                // this has to be the last instruction in the basic block
                assert(iter_copy == bb->end());
                curr_stage->terminator_type = PipeIR::StageTerminatorType::RETURN;
            } else if (auto switch_inst = llvm::dyn_cast<llvm::SwitchInst>(inst_i)) {
                assert(iter_copy == bb->end());
                curr_stage->terminator_type = PipeIR::StageTerminatorType::SWITCH;
                curr_stage->cond_vars.push_back(switch_inst->getCondition());
                for (auto iter = switch_inst->case_begin(); iter != switch_inst->case_end(); iter++) {
                    curr_stage->switch_cases.push_back(iter->getCaseValue());
                    PipeIR::PreStage *next_ptr = nullptr;
                    auto case_bb = iter->getCaseSuccessor();
                    if (ctx.bb_map.find(case_bb) != ctx.bb_map.end()) {
                        next_ptr = ctx.bb_map.find(case_bb)->second;
                    } else {
                        auto next_stage = std::make_unique<PipeIR::PreStage>();
                        next_stage->name = curr_func_prefix + get_llvm_name(*case_bb);
                        next_ptr = next_stage.get();
                        std::cout << "inserting bb: " << next_stage->name << std::endl;
                        ctx.stages.insert({next_stage->get_uuid(), std::move(next_stage)});
                        ctx.bb_map.insert({case_bb, next_ptr});
                        translate_bb_part(case_bb, case_bb->begin(), curr_func_prefix, ctx,
                                          next_ptr, continue_stage);
                    }
                    curr_stage->next_stages.push_back(next_ptr);
                }
            } else if (auto branch = llvm::dyn_cast<llvm::BranchInst>(inst_i)) {
                assert(iter_copy == bb->end());
                curr_stage->terminator_type = PipeIR::StageTerminatorType::BRANCH;
                if (branch->isConditional()) {
                    curr_stage->cond_vars.push_back(branch->getCondition());
                }
                for (auto i = 0; i < branch->getNumSuccessors(); i++) {
                    // first check if this basic block has already been translated
                    PipeIR::PreStage *next_ptr = nullptr;
                    auto target_bb = branch->getSuccessor(i);
                    if (ctx.bb_map.find(target_bb) != ctx.bb_map.end()) {
                        next_ptr = ctx.bb_map.find(target_bb)->second;
                    } else {
                        auto next_stage = std::make_unique<PipeIR::PreStage>();
                        next_stage->name = curr_func_prefix + get_llvm_name(*target_bb);
                        next_ptr = next_stage.get();
                        std::cout << "inserting bb: " << next_stage->name << std::endl;
                        ctx.stages.insert({next_stage->get_uuid(), std::move(next_stage)});
                        ctx.bb_map.insert({target_bb, next_ptr});
                        translate_bb_part(target_bb, target_bb->begin(), curr_func_prefix, ctx,
                                          next_ptr, continue_stage);
                    }
                    curr_stage->next_stages.push_back(next_ptr);
                }
            } else {
                curr_stage->insts.push_back(&*inst_i);
            }

            if (iter_copy == bb->end()) {
                // this is the last instruction of the original bb
                ctx.bb_end_map[bb] = curr_stage->get_uuid();
            }
        }
    }

    void translate_func(llvm::Function *func, TranslateCtx &ctx,
                        PipeIR::PreStage *curr_stage,
                        PipeIR::PreStage *continue_stage) {
        // always start with a new stage
        std::cout << "Translating Function: " << func->getName().str() << std::endl;
        auto entry_bb = &(func->getEntryBlock());
        auto func_name = func->getName().str();
        std::string fn;
        if (cxx_demangle(func_name, fn)) {
            func_name = fn;
        }
        func_name = func_name + "_";
        translate_bb_part(entry_bb, entry_bb->begin(), func_name, ctx, curr_stage, continue_stage);
    }

    PASS_IMPL(LLVM2PrePipe, s) {
        // start from the entry function.
        auto entry_func = s->entry_func;
        auto pre_pipe_ctx = std::make_unique<PrePipeCtx>();
        pre_pipe_ctx->llvm_module = std::move(s->module);

        auto curr_stage = std::make_unique<PipeIR::PreStage>();
        curr_stage->name = "start";
        auto curr_stage_ptr = curr_stage.get();
        TranslateCtx ctx;
        ctx.stages.insert({curr_stage->get_uuid(), std::move(curr_stage)});
        translate_func(s->entry_func, ctx, curr_stage_ptr, nullptr);
        std::cout << "After pass: got " << ctx.stages.size() << " stages" << std::endl;
        for (auto &kv : ctx.stages) {
            pre_pipe_ctx->stages.insert({kv.first, std::move(kv.second)});
        }
        pre_pipe_ctx->root_stage_id = curr_stage_ptr->get_uuid();
        return pre_pipe_ctx;
    }

    PASS_IMPL(LLVM2Pipe, s) {
        auto pipe_ctx = std::make_unique<PipeCtx>();
        return pipe_ctx;
    }

    struct PrePipe2PipeCtx {
        std::vector<std::unique_ptr<PipeIR::Operation>> ops;
        LLVMAnalysis::Analyzer analyzer;
        std::unordered_map<llvm::BasicBlock *, PipeIR::uuid_t> bb_end_map;
        std::unordered_map<llvm::Value *, std::shared_ptr<PipeIR::Var>> var_map;
    };

    PipeIR::VarType * from_llvm_type(llvm::Type *t) {
        // TODO: fill this
        // std::string type_str;
        // llvm::raw_string_ostream rso(type_str);
        // t->print(rso);
        // auto t_str = rso.str();
        // std::cout << t_str << std::endl;
        if (t->isVoidTy()) {
            assert(false && "got void type");
        } else if (t->isIntegerTy()) {
            return PipeIR::VarType::IntType(t->getIntegerBitWidth()).release();
        } else if (t->isPointerTy()) {
            auto pointee_type = from_llvm_type(t->getPointerElementType());
            return PipeIR::VarType::PtrType(pointee_type).release();
        } else if (t->isStructTy()) {
            std::vector<PipeIR::VarType *> ts;
            for (int i = 0; i < t->getStructNumElements(); i++) {
                ts.push_back(from_llvm_type(t->getStructElementType(i)));
            }
            return PipeIR::VarType::StructType(ts).release();
        } else if (t->isArrayTy()) {
            auto ele_type = from_llvm_type(t->getArrayElementType());
            auto array_size = t->getArrayNumElements();
            return PipeIR::VarType::ArrayType(ele_type, array_size).release();
        } else {
            assert(false && "unknown type");
        }
    }

    class LLVM2PipeOpVisitor : public llvm::InstVisitor<LLVM2PipeOpVisitor> {
    public:
        PrePipe2PipeCtx &ctx;

        LLVM2PipeOpVisitor(PrePipe2PipeCtx &_c) : ctx(_c) {}

        std::shared_ptr<PipeIR::Var> var_from_llvm_val(llvm::Value *val) {
            if (ctx.var_map.find(val) != ctx.var_map.end()) {
                return ctx.var_map[val];
            } else if (const llvm::ConstantInt *CI = llvm::dyn_cast<llvm::ConstantInt>(val)) {
                auto int_val = CI->getSExtValue();
                auto var = std::make_shared<PipeIR::Var>();
                var->type = PipeIR::VarType::IntType(CI->getBitWidth()).release();
                var->const_val = int_val;
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
            ctx.ops.push_back(std::move(op));
        }

        void add_var_mapping(llvm::Value &val, std::shared_ptr<PipeIR::Var> v) {
            assert(ctx.var_map.find(&val) == ctx.var_map.end());
            ctx.var_map[&val] = v;
        }

        void visitInstruction(const llvm::Instruction &inst) {
            assert(false && "LLVM2PipeOp: unknown inst");
        }

        void visitGetElementPtrInst(llvm::GetElementPtrInst &gep) {
            // GEP translation rules
            // 1. if the result is a pointer to header fields, SKIP this instruction
            // 2. if the result is a pointer to global state, SKIP this instruction
            // 3. ?
            auto reg_info = ctx.analyzer.get_reg_info(gep.getPointerOperand());
            using RegT = LLVMAnalysis::RegInfo::Type;

            return;
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
            ctx.ops.push_back(std::move(op));
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
            // switch (predicate) {
            //     case CMP::ICMP_EQ:
            //         break;
            //     case CMP::ICMP_NE:
            //         break;
            //     case CMP::ICMP_SGE:
            //         break;
            //     case CMP::ICMP_SGT:
            //         break;
            //     case CMP::ICMP_SLE:
            //         break;
            //     case CMP::ICMP_SLT:
            //         break;
            //     case CMP::ICMP_UGE:
            //         break;
            //     case CMP::ICMP_UGT:
            //         break;
            //     case CMP::ICMP_ULE:
            //         break;
            //     case CMP::ICMP_ULT:
            //         break;
            //     default:
            //         assert(false && "unsupported icmp op");
            //         break;
            // }
            add_dst_var_and_append_op(std::move(op), icmp);
        }

        void visitLoadInst(llvm::LoadInst &load) {
            // get the reg info
            auto reg_info = ctx.analyzer.get_reg_info(load.getPointerOperand());
            using RegT = LLVMAnalysis::RegInfo::Type;
            auto op = std::make_unique<PipeIR::Operation>();
            auto dst_type = from_llvm_type(load.getType());
            if (reg_info.t == RegT::HEADER_PTR) {
                // read from packet header
                // just add a variable mapping for the header field
                auto var = std::make_shared<PipeIR::Var>();
                var->type = std::move(dst_type);
                var->is_pkt_header = true;
                var->header_name = reg_info.header;
                var->field_name = reg_info.field;
                add_var_mapping(load, var);
            } else if (reg_info.t == RegT::GLOBAL_STATE_PTR) {
                // TODO: global state
            } else {
                assert(false && "unknown pointer type");
            }
        }

        void visitStoreInst(llvm::StoreInst &store) {
            // get the reg info
            auto reg_info = ctx.analyzer.get_reg_info(store.getPointerOperand());
            using RegT = LLVMAnalysis::RegInfo::Type;
            auto op = std::make_unique<PipeIR::Operation>();
            auto dst_type = from_llvm_type(store.getType());
            if (reg_info.t == RegT::HEADER_PTR) {
                // write to header
                auto val = store.getValueOperand();
                auto val_var = var_from_llvm_val(val);
                op->type = PipeIR::Operation::Type::STATE_OP;
                op->state_op_name = "header-write";
                op->oprands.push_back(val_var);
                op->header_name = reg_info.header;
                op->field_name = reg_info.field;
                ctx.ops.push_back(std::move(op));
            } else if (reg_info.t == RegT::GLOBAL_STATE_PTR) {
                // TODO: global state
            } else {
                assert(false && "unknown pointer type");
            }
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
            ctx.ops.push_back(std::move(op));
        }

        void visitSExtInst(llvm::SExtInst &sext) {
            auto op = std::make_unique<PipeIR::Operation>();
            op->type = PipeIR::Operation::Type::ARITH;
            op->arith_op_name = "sext";
            op->oprands.push_back(var_from_llvm_val(sext.getOperand(0)));
            auto var = std::make_shared<PipeIR::Var>();
            var->type = from_llvm_type(sext.getType());
            add_var_mapping(sext, var);
            ctx.ops.push_back(std::move(op));
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
            ctx.ops.push_back(std::move(op));
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
            ctx.ops.push_back(std::move(op));
        }

        void visitCallInst(llvm::CallInst &call) {
            // all the function calls should be state op
            auto op = std::make_unique<PipeIR::Operation>();
            op->type = PipeIR::Operation::Type::STATE_OP;
            auto fn = call.getCalledFunction();
            if (fn == nullptr) {
                assert(false && "NULL pointer function");
            }
            auto func_name = fn->getName().str();
            std::cout << "CallInst: " << func_name;
            std::string f_name;
            if (cxx_demangle(func_name, f_name)) {
                func_name = f_name;
            }

            auto f1 = remove_template(func_name);
            auto f2 = remove_func_args(f1);
            auto f3 = remove_func_paran(f2);
            op->state_op_name = f3;
            for (int i = 0; i < call.getNumArgOperands(); i++) {
                op->oprands.push_back(var_from_llvm_val(call.getArgOperand(i)));
            }

            if (!call.getType()->isVoidTy()) {
                auto var = std::make_shared<PipeIR::Var>();
                var->type = from_llvm_type(call.getType());
                add_var_mapping(call, var);
                ctx.ops.push_back(std::move(op));
            }
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
            ctx.ops.push_back(std::move(op));
        }
    };

    PASS_IMPL(PrePipe2Pipe, s) {
        auto pipe_ctx = std::make_unique<PipeCtx>();

        // for each pre stage, translate it into a stage
        LLVMAnalysis::Analyzer analyzer;

        // first create one stage for the pre stage
        // this is a mapping from prestage to stage
        PipeIR::uuid_unordered_map_t<std::unique_ptr<PipeIR::Stage>> stages_mapping;

        PrePipe2PipeCtx visitor_ctx;
        for (auto &kv : s->stages) {
            auto stage = std::make_unique<PipeIR::Stage>();
            stages_mapping[kv.first] = std::move(stage);
        }

        for (auto &kv : s->bb_end_map) {
            assert(stages_mapping.find(kv.second) != stages_mapping.end());
            visitor_ctx.bb_end_map[kv.first] = stages_mapping[kv.second]->get_uuid();
        }

        for (auto &kv : s->stages) {
            auto prestage_ptr = kv.second.get();
            LLVM2PipeOpVisitor visitor(visitor_ctx);
            for (int i = 0; i < prestage_ptr->insts.size(); i++) {
                auto inst_ptr = prestage_ptr->insts[i];
                visitor.visit(*inst_ptr);
            }
            for (int i = 0; i < visitor_ctx.ops.size(); i++) {
                stages_mapping[kv.first]->ops.push_back(std::move(visitor_ctx.ops[i]));
            }
            visitor_ctx.ops.clear();
        }

        return pipe_ctx;
    }

    static void print_llvm_inst(std::ostream &os, const llvm::Instruction *inst) {
        os << get_llvm_inst_str(inst);
    }

    void generate_graphviz(std::ostream &os, const PrePipeCtx &ctx) {
        using uuid_hash = boost::hash<PipeIR::uuid_t>;
        std::unordered_map<PipeIR::uuid_t,
                           std::unordered_set<PipeIR::uuid_t, uuid_hash>,
                           uuid_hash> edge_map;
        std::unordered_set<PipeIR::uuid_t, uuid_hash> visited_stage;

        os << "digraph cfg {" << std::endl;
        std::cout << "got " << ctx.stages.size() << " stages" << std::endl;

        for (auto &kv : ctx.stages) {
            // print instructions in the stage
            auto stage_ptr = kv.second.get();
            auto &insts = stage_ptr->insts;
            auto stage_name = get_bb_name_for_graphviz(stage_ptr->name);
            if (stage_ptr->terminator_type == PipeIR::StageTerminatorType::RETURN) {
                stage_name = stage_name + "_return";
            }
            os << "\"stage_" << boost::uuids::to_string(kv.first) << "\"";
            os << " [" << std::endl << "shape=none" << std::endl;
            // print instructions, we use html style label
            os << "label = <<table border=\"0\" cellspacing=\"0\">" << std::endl;
            os << "<tr><td port=\"title\" border=\"1\" bgcolor=\"black\">" << "<font color=\"white\">"
               << str_escape_html(stage_name)
               << "</font>"
               << "</td></tr>"
               << std::endl;
            for (int i = 0; i < insts.size(); i++) {
                auto i_ptr = insts[i];
                auto inst_str = get_llvm_inst_str(i_ptr);
                if (inst_str.size() > 32) {
                    inst_str = inst_str.substr(0, 28) + "...";
                }
                auto port_str = "port" + std::to_string(i);
                os << "<tr><td port=\"" << port_str << "\" ";
                os << "border=\"1"
                   << "\">"
                   << inst_str
                   << "</td></tr>"
                   << std::endl;
            }
            os << "</table>>" << std::endl;
            os << "];" << std::endl;
        }

        for (auto &kv : ctx.stages) {
            auto stage_ptr = kv.second.get();
            std::string stage_name = "stage_" + boost::uuids::to_string(kv.first);
            for (int i = 0; i < stage_ptr->next_stages.size(); i++) {
                auto dst_stage_ptr = stage_ptr->next_stages[i];
                auto dst_uuid = dst_stage_ptr->get_uuid();
                std::string dst_stage_name = "stage_" + boost::uuids::to_string(dst_uuid);
                os << "\"" << stage_name << "\":s -> \"";
                os << dst_stage_name << "\":n";
                os << ";" << std::endl;
            }
        }
        os << "}" << std::endl;
    }

    void generate_graphviz(std::ostream &os, const PipeCtx &ctx) {
        using uuid_hash = boost::hash<PipeIR::uuid_t>;
        std::unordered_map<PipeIR::uuid_t,
                           std::unordered_set<PipeIR::uuid_t, uuid_hash>,
                           uuid_hash> edge_map;
        std::unordered_set<PipeIR::uuid_t, uuid_hash> visited_stage;

        os << "digraph cfg {" << std::endl;

        for (auto &kv : ctx.program->stages_) {
            // print instructions in the stage
            auto stage_ptr = kv.second.get();
            auto &ops = stage_ptr->ops;
            auto stage_name = get_bb_name_for_graphviz(stage_ptr->name);
            if (stage_ptr->terminator_type == PipeIR::StageTerminatorType::RETURN) {
                stage_name = stage_name + "_return";
            }
            os << "\"stage_" << boost::uuids::to_string(kv.first) << "\"";
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
                if (op_str.size() > 32) {
                    op_str = op_str.substr(0, 28) + "...";
                }
                auto port_str = "port" + std::to_string(i);
                os << "<tr><td port=\"" << port_str << "\" ";
                os << "border=\"1"
                   << "\">"
                   << op_str
                   << "</td></tr>"
                   << std::endl;
            }
            os << "</table>>" << std::endl;
            os << "];" << std::endl;
        }

        for (auto &kv : ctx.program->stages_) {
            auto stage_ptr = kv.second.get();
            std::string stage_name = "stage_" + boost::uuids::to_string(kv.first);
            for (int i = 0; i < stage_ptr->next_stages.size(); i++) {
                auto dst_stage_ptr = stage_ptr->next_stages[i];
                auto dst_uuid = dst_stage_ptr->get_uuid();
                std::string dst_stage_name = "stage_" + boost::uuids::to_string(dst_uuid);
                os << "\"" << stage_name << "\":s -> \"";
                os << dst_stage_name << "\":n";
                os << ";" << std::endl;
            }
        }
        os << "}" << std::endl;
    }

    struct FindDepCtx {
        std::unordered_map<PipeIR::Var *, std::unordered_set<PipeIR::Operation *>> read_var_ops;
        std::unordered_map<PipeIR::Var *, std::unordered_set<PipeIR::Operation *>> write_var_ops;

        std::unordered_map<PipeIR::GlobalState *, std::unordered_set<PipeIR::Operation *>> read_state_ops;
        std::unordered_map<PipeIR::GlobalState *, std::unordered_set<PipeIR::Operation *>> write_state_ops;

        PipeIR::uuid_unordered_set_t *visited;

        PipeCtx::dependency_map_t *dep;
    };

    static void check_dep_for_op(PipeIR::Operation *op, FindDepCtx &ctx, bool add_to_set) {
        auto vars_read = op->vars_read();
        auto vars_written = op->vars_written();

        auto states_read = op->state_read();
        auto states_written = op->state_written();

        for (auto v : vars_read) {
            // all instructions that writes the var later should depend on this op
            if (ctx.write_var_ops.find(v) != ctx.write_var_ops.end()) {
                // add dependency
                auto &ops = ctx.write_var_ops[v];
                for (auto op_ptr : ops) {
                    (*ctx.dep)[op_ptr].insert(op);
                }
                ctx.write_var_ops.erase(v);
            }
        }

        for (auto v : vars_written) {
            // all ops that reads or writes the same var
            if (ctx.write_var_ops.find(v) != ctx.write_var_ops.end()) {
                // add dependency
                auto &ops = ctx.write_var_ops[v];
                for (auto op_ptr : ops) {
                    (*ctx.dep)[op_ptr].insert(op);
                }
                ctx.write_var_ops.erase(v);
            }

            if (ctx.read_var_ops.find(v) != ctx.read_var_ops.end()) {
                // add dependency
                auto &ops = ctx.read_var_ops[v];
                for (auto op_ptr : ops) {
                    (*ctx.dep)[op_ptr].insert(op);
                }
                ctx.read_var_ops.erase(v);
            }
        }

        // same thing for global states
        for (auto v : states_read) {
            // all instructions that writes the var later should depend on this op
            if (ctx.write_state_ops.find(v) != ctx.write_state_ops.end()) {
                // add dependency
                auto &ops = ctx.write_state_ops[v];
                for (auto op_ptr : ops) {
                    (*ctx.dep)[op_ptr].insert(op);
                }
                ctx.write_state_ops.erase(v);
            }
        }

        for (auto v : states_written) {
            // all ops that reads or writes the same var
            if (ctx.write_state_ops.find(v) != ctx.write_state_ops.end()) {
                // add dependency
                auto &ops = ctx.write_state_ops[v];
                for (auto op_ptr : ops) {
                    (*ctx.dep)[op_ptr].insert(op);
                }
                ctx.write_state_ops.erase(v);
            }

            if (ctx.read_state_ops.find(v) != ctx.read_state_ops.end()) {
                // add dependency
                auto &ops = ctx.read_state_ops[v];
                for (auto op_ptr : ops) {
                    (*ctx.dep)[op_ptr].insert(op);
                }
                ctx.read_state_ops.erase(v);
            }
        }

        if (add_to_set) {
            for (auto v : vars_read) {
                ctx.read_var_ops[v].insert(op);
            }
            for (auto v : vars_written) {
                ctx.write_var_ops[v].insert(op);
            }

            for (auto v : states_read) {
                ctx.read_state_ops[v].insert(op);
            }
            for (auto v : states_written) {
                ctx.write_state_ops[v].insert(op);
            }
        }
    }

    static void find_dep_for_stage(const PipeIR::Stage &stage, FindDepCtx dep_ctx, PipeCtx &ctx) {
        for (int i = stage.ops.size() - 1; i >= 0; i--) {
            auto op = stage.ops[i].get();
            check_dep_for_op(op, dep_ctx, false);
        }

        // after processing this stage, follow the reverse edges
        auto &rev_edges = ctx.program->rev_edges;

        if (rev_edges.find(stage.get_uuid()) == rev_edges.end()) {
            return;
        }

        auto prev_stages = rev_edges[stage.get_uuid()];

        dep_ctx.visited->insert(stage.get_uuid());

        for (auto &prev_id : prev_stages) {
            // ops should be removed from the ctx
            if (dep_ctx.visited->find(prev_id) == dep_ctx.visited->end()) {
                find_dep_for_stage(*ctx.program->stages_[prev_id], dep_ctx, ctx);
            }
        }
    }

    static void add_dep_for_stage(PipeCtx::dependency_map_t &deps,
                                  PipeIR::Operation *op,
                                  PipeIR::Stage &stage) {
    }

    PASS_IMPL(PipeDataDep, s) {
        for (auto &kv : s->program->stages_) {
            FindDepCtx dep_ctx;
            dep_ctx.dep = &s->dependency;
            PipeIR::uuid_unordered_set_t visited;
            dep_ctx.visited = &visited;
            auto stage_id = kv.first;
            auto stage_ptr = kv.second.get();
            for (int i = stage_ptr->ops.size() - 1; i >= 0; i--) {
                auto op = stage_ptr->ops[i].get();
                check_dep_for_op(op, dep_ctx, true);
            }
            // now start to find dependency
            auto &prev_stages = s->program->rev_edges[stage_ptr->get_uuid()];
            for (auto &prev_id : prev_stages) {
                find_dep_for_stage(*s->program->stages_[prev_id], dep_ctx, *s);
            }
        }

        // also create dependency for control flow
        for (auto &kv : s->program->stages_) {
            auto stage_ptr = kv.second.get();
            switch (stage_ptr->terminator_type) {
                case PipeIR::StageTerminatorType::BRANCH:
                    if (stage_ptr->cond_vars.size() > 0) {
                        assert(stage_ptr->cond_vars.size() == 1);
                        auto src = stage_ptr->cond_vars[0]->from;
                        for (auto n : stage_ptr->next_stages) {
                            add_dep_for_stage(s->dependency, src, *n);
                        }
                    }
                    break;
                case PipeIR::StageTerminatorType::RETURN:
                    break;
                case PipeIR::StageTerminatorType::SWITCH:
                    if (stage_ptr->cond_vars.size() > 0) {
                        auto src = stage_ptr->cond_vars[0]->from;
                        for (auto n : stage_ptr->next_stages) {
                            add_dep_for_stage(s->dependency, src, *n);
                        }
                    }
                    break;
                default:
                    assert(false && "unknown terminator");
                    break;
            }
        }

        // also create reverse dependencies
        for (auto &kv : s->dependency) {
            auto op = kv.first;
            auto &deps = kv.second;
            for (auto dep_op : deps) {
                s->rev_dep[dep_op].insert(op);
            }
        }
        return s;
    }

    static void remove_label_from_set(std::unordered_set<std::string> &dst,
                                      const std::unordered_set<std::string> &to_remove) {
        for (auto &l : to_remove) {
            dst.erase(l);
        }
    }

    PASS_IMPL(PipeLabel, s) {
        // same algorithm as it was before
        bool have_delta = false;
        for (auto &kv : s->program->stages_) {
            auto stage_ptr = kv.second.get();
            for (auto &op : stage_ptr->ops) {
                s->labels.insert({op.get(), op->possible_labels()});
            }
        }

        do {
            have_delta = false;
            // keep removing labels until a fixed point
            for (auto &kv : s->dependency) {
                auto op_ptr = kv.first;
                auto &deps = kv.second;
                if (s->labels[op_ptr].find("suffix") == s->labels[op_ptr].end()) {
                    for (auto dep_op : deps) {
                        if (s->labels[dep_op].find("suffix") != s->labels[dep_op].end()) {
                            have_delta = true;
                            s->labels[dep_op].erase("suffix");
                        }
                    }
                }
            }

            for (auto &kv : s->rev_dep) {
                auto op_ptr = kv.first;
                auto &deps = kv.second;
                if (s->labels[op_ptr].find("prefix") == s->labels[op_ptr].end()) {
                    for (auto dep_op : deps) {
                        if (s->labels[dep_op].find("prefix") != s->labels[dep_op].end()) {
                            have_delta = true;
                            s->labels[dep_op].erase("prefix");
                        }
                    }
                }
            }
        } while (have_delta);
        return s;
    }
}
