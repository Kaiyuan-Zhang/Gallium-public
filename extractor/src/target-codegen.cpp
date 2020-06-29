#include "target-codegen.hpp"
#include "target-p4.hpp"
#include "formatter.hpp"
#include <queue>
#include <sstream>


namespace Target {
    CodeGen::CodeGen(std::unordered_map<std::string, BasicBlock *> &blocks,
                     llvm::Module *module,
                     std::vector<std::string> &entries): blocks_(blocks),
                                                         module_(module),
                                                         entries_(entries) {
    }

    void CodeGen::print_code(std::ostream &os) const {
        auto lines = this->gen_code();
        for (int i = 0; i < lines.size(); i++) {
            os << lines[i] << std::endl;
        }
    }

    static std::string sanitize_name(const std::string &name) {
        return str_replace_all(str_replace_all(name, "%", "v"), "!", "_");
    }

    static std::string sanitize_func_name(const std::string &f) {
        return str_replace_all(str_replace_all(f, "%", "f_"), ".", "_");
    }

    static std::string sanitize_type(const std::string &type_str) {
        static const std::vector<std::string> prefix_to_remove = {
            "%class.",
            "class.",
            "%struct.",
            "struct.",
        };
        for (auto &prefix : prefix_to_remove) {
            if (str_begin_with(type_str, prefix)) {
                auto start_pos = std::string(prefix).length();
                int end_pos = 0;
                int i = start_pos;
                while(type_str[i] != ' ') {
                    i++;
                }
                auto result = type_str.substr(start_pos, i - start_pos);
                //auto pos = result.find(".");
                //return result.substr(0, pos);
                return result;
            }
        }
        return type_str;
    }

    static std::string operator_to_str(const std::string &name,
                                       const std::vector<std::string> &args) {
        std::string result = "";
        if (name == "operator[]") {
            result = "[" + sanitize_name(args[1]) + "];";
        } else {
            throw CodeGenException{"unknown operator"};
        }
        return result;
    }

    static std::string get_llvm_type_name(const llvm::Module *module, llvm::Type *t) {
        if (t->isPointerTy()) {
            auto val_type = t->getPointerElementType();
            if (val_type->isStructTy()) {
                return sanitize_type(val_type->getStructName().str()) + " *";
            } else {
                auto type_size = get_type_size(module, val_type);
                std::string type_str = "u" + std::to_string(type_size * 8) + " *";
                return type_str;
            }
        } else if (t->isStructTy()) {
            return sanitize_type(t->getStructName().str());
        } else {
            auto type_size = get_type_size(module, t);
            std::string type_str = "u" + std::to_string(type_size * 8);
            return type_str;
        }
    }

    struct CppGenCtx {
        llvm::Module *module;
        std::unordered_map<std::string, std::string> reg_type;
        std::unordered_map<std::string, std::string> func_name;
        std::unordered_map<std::string, std::string> func_ret_type;
        std::unordered_map<std::string, int> bb_id;
        std::unordered_map<std::string, std::string> template_mapping;
    };

    static std::string get_llvm_type(const CppGenCtx &ctx,
                                     const llvm::Module *module, llvm::Type *t) {
        if (t->isPointerTy()) {
            auto val_type = t->getPointerElementType();
            auto val_type_str = get_llvm_type(ctx, module, val_type);
            return val_type_str + " *";
        } else if (t->isStructTy()) {
            auto type_str = t->getStructName().str();
            type_str = sanitize_type(type_str);
            if (ctx.template_mapping.find(type_str) != ctx.template_mapping.end()) {
                type_str = ctx.template_mapping.find(type_str)->second;
            }
            return type_str;
        } else {
            auto type_size = get_type_size(module, t);
            std::string type_str = "u" + std::to_string(type_size * 8);
            return type_str;
        }
    }

    class CppDeclLLVMVisitor : public llvm::InstVisitor<CppDeclLLVMVisitor> {
    public:
        std::string type_str;
        const GlobalTypes &types;
        const std::string &var_name;
        const CppGenCtx &ctx;
        std::string line;
        std::string val;
        std::string decl;
        std::vector<std::string> lines;
        
        CppDeclLLVMVisitor(const GlobalTypes &ts,
                           const CppGenCtx &c,
                           const std::string &vn) : types(ts),
                                                    ctx(c),
                                                    var_name(vn) {
            type_str = "";
            decl = "";
            line = "";
            val = "";
        }

        void visitInstruction(const llvm::Instruction &inst) {
            // default
            auto t = inst.getType();
            if (var_name != "") {
                type_str = get_llvm_type(inst.getModule(), t);
                decl = type_str + " " + var_name + ";";
                throw CodeGenException("unknown llvm inst");
            }
        }

        std::string get_llvm_type(const llvm::Module *module, llvm::Type *t) {
            if (t->isPointerTy()) {
                auto val_type = t->getPointerElementType();
                auto val_type_str = get_llvm_type(module, val_type);
                return val_type_str + " *";
            } else if (t->isStructTy()) {
                auto type_str = t->getStructName().str();
                type_str = sanitize_type(type_str);
                if (ctx.template_mapping.find(type_str) != ctx.template_mapping.end()) {
                    type_str = ctx.template_mapping.find(type_str)->second;
                }
                return type_str;
            } else {
                auto type_size = get_type_size(module, t);
                std::string type_str = "u" + std::to_string(type_size * 8);
                return type_str;
            }
        }

        void visitGetElementPtrInst(const llvm::GetElementPtrInst &inst) {
            auto reg_type = inst.getType();
            assert(reg_type->isPointerTy());
            auto val_type = reg_type->getPointerElementType();
            auto type_size = get_type_size(inst.getModule(), val_type);
            //"u" + std::to_string(type_size * 8) + " *";
            type_str = get_llvm_type(inst.getModule(), reg_type);
            auto base_var = sanitize_name(get_llvm_name(*inst.getOperand(0)));
            llvm::Type *type = inst.getPointerOperandType();
            std::string offset_str = "";
            inst.print(llvm::errs());
            llvm::errs() << "\n";
            for (int i = 1; i < inst.getNumOperands(); i++) {
                auto val = inst.getOperand(i);
                std::string idx;
                int int_idx;
                if (const llvm::ConstantInt* CI = llvm::dyn_cast<llvm::ConstantInt>(val)) {
                    idx = get_llvm_name(*val);
                    int_idx = CI->getSExtValue();
                } else {
                    idx = sanitize_name(get_llvm_name(*val));
                    int_idx = -1;
                }
                std::string offset;
                if (type->isPointerTy()) {
                    auto val_t = type->getPointerElementType();
                    auto ts = get_type_size(inst.getModule(), val_t);
                    offset = std::to_string(ts) + " * " + idx;
                    if (int_idx == 0) {
                        offset = "";
                    }
                    type = val_t;
                    //std::cerr << i << ": is ptr " << idx << std::endl;
                } else if (type->isStructTy()) {
                    assert(int_idx >= 0);
                    llvm::DataLayout* dl = new llvm::DataLayout(inst.getModule());
                    llvm::StructType *struct_t = static_cast<llvm::StructType *>(type);
                    const llvm::StructLayout* sl = dl->getStructLayout(struct_t);
                    auto off = sl->getElementOffset(int_idx);
                    if (off != 0) {
                        offset = std::to_string(off);
                    } else {
                        offset = "";
                    }
                    type = type->getStructElementType(int_idx);
                    //std::cerr << i << ": is struct " << int_idx << std::endl;
                } else if (type->isArrayTy()) {
                    auto val_t = type->getArrayElementType();
                    auto ts = get_type_size(inst.getModule(), val_t);
                    offset = std::to_string(ts) + " * " + idx;
                    if (int_idx == 0) {
                        offset = "";
                    }
                    type = val_t;
                    //std::cerr << i << ": is array " << idx << std::endl;
                } else {
                    llvm::errs() << i << ": ";
                    type->print(llvm::errs());
                    llvm::errs() << "\n";
                    throw CodeGenException{"unknown gep type"};
                }
                if (offset_str == "") {
                    offset_str = offset;
                } else if (offset != "") {
                    offset_str = offset_str + " + " + offset;
                }
            }
            if (offset_str == "") {
                offset_str = "0";
            }
            std::string val_str = "((char *)" + base_var + " + " + offset_str + ");";
            decl = type_str + " " + var_name + ";";
            lines.push_back(var_name + " = (" + type_str + ")" + val_str);
        }

        void visitLoadInst(const llvm::LoadInst &inst) {
            auto ptr_type = inst.getPointerOperandType();
            auto val_type = ptr_type->getPointerElementType();
            auto type_size = get_type_size(inst.getModule(), val_type);
            type_str = "u" + std::to_string(type_size * 8);
            //line = type_str + " " + var_name + ";";
            decl = type_str + " " + var_name + ";";
            lines.push_back(var_name + " = *"
                            + sanitize_name(get_llvm_name(*inst.getOperand(0))) + ";");
        }

        void visitStoreInst(const llvm::StoreInst &inst) {
            std::string ptr_name = sanitize_name(get_llvm_name(*inst.getOperand(1)));
            lines.push_back("*" + ptr_name + " = "
                            + sanitize_name(get_llvm_name(*inst.getOperand(0))) + ";");
        }

        void visitBinaryOperator(const llvm::BinaryOperator &inst) {
            auto t = inst.getType();
            auto type_size = get_type_size(inst.getModule(), t);
            type_str = "u" + std::to_string(type_size * 8);
            decl = type_str + " " + var_name + ";";
            auto get_name = [](const llvm::Value *v) -> std::string {
                return sanitize_name(get_llvm_name(*v));
            };
            std::string arg_list = get_name(inst.getOperand(0)) + ", " + get_name(inst.getOperand(1));
            std::string op_str = inst.getOpcodeName();
            lines.push_back(var_name + " = " + "Morula::op_" + op_str + "(" + arg_list + ");");
        }

        void visitICmpInst(const llvm::ICmpInst &inst) {
            auto dst_reg = get_llvm_name(inst);
            using P = llvm::CmpInst::Predicate;
            auto predicate = inst.getPredicate();
            auto oprand1 = sanitize_name(get_llvm_name(*inst.getOperand(0)));
            auto oprand2 = sanitize_name(get_llvm_name(*inst.getOperand(1)));

            std::string op = "";
            
            switch (predicate) {
            case P::ICMP_EQ:
                op = "op_eq";
                break;
            case P::ICMP_NE:
                op = "op_ne";
                break;
            case P::ICMP_SLE:
                op = "op_sle";
                break;
            case P::ICMP_SLT:
                op = "op_slt";
                break;
            case P::ICMP_SGE:
                op = "op_sge";
                break;
            case P::ICMP_SGT:
                op = "op_sgt";
                break;
            case P::ICMP_ULE:
                op = "op_ule";
                break;
            case P::ICMP_ULT:
                op = "op_ult";
                break;
            case P::ICMP_UGE:
                op = "op_eq";
                break;
            case P::ICMP_UGT:
                op = "op_eq";
                break;
            default:
                throw CodeGenException{"unsupported icmp"};
            }
            type_str = get_llvm_type(inst.getModule(), inst.getType());
            decl = type_str + " " + var_name + ";";
            lines.push_back(var_name + " = Morula::" + op + "("
                            + sanitize_name(oprand1) + ", "
                            + sanitize_name(oprand2) + ");");
        }

        void visitBitCastInst(const llvm::BitCastInst &inst) {
            auto t = inst.getType();
            type_str = get_llvm_type(inst.getModule(), t);
            std::cerr << "bitcast ret type: " << type_str << std::endl;
            decl = type_str + " " + var_name + ";";
            lines.push_back(var_name + " = " + "(" + type_str + ")"
                            + sanitize_name(get_llvm_name(*inst.getOperand(0))) + ";");
        }
    };

    class CppDeclInstVisitor : public InstVisitor {
    public:
        std::string &type_str;
        const GlobalTypes &types;
        const std::string &var_name;
        const CppGenCtx &ctx;
        std::string decl;
        std::vector<std::string> lines;
        
        CppDeclInstVisitor(std::string &r,
                           const GlobalTypes &ts,
                           const CppGenCtx &c,
                           const std::string &vn) : type_str(r),
                                                    types(ts),
                                                    ctx(c),
                                                    var_name(vn) {
            type_str = "";
            lines.clear();
            decl = "";
        }
        
        virtual void visit_inst(Instruction &inst) {
            throw CodeGenException("unknown instruction");
        }
        
        virtual void visit_inst(LLVMInst &inst) {
            CppDeclLLVMVisitor visitor(types, ctx, var_name);
            visitor.visit(*inst.get_inst());
            type_str = visitor.type_str;
            decl = visitor.decl;
            lines = visitor.lines;
        }
        
        virtual void visit_inst(ArithInst &inst) {
            auto oprands = inst.oprands();
            if (inst.op() == ArithInst::Op::CONST_VAL) {
                assert(inst.dst_type_anno != nullptr);
                type_str = get_llvm_type(ctx, ctx.module,
                                         inst.dst_type_anno);
            }
            for (const auto &arg : oprands) {
                //auto arg_name = sanitize_name(arg);
                auto arg_name = arg;
                if (ctx.reg_type.find(arg_name) != ctx.reg_type.end()) {
                    type_str = ctx.reg_type.find(arg_name)->second;
                    break;
                }
            }
            if (type_str == "") {
                inst.print(std::cerr);
                std::cerr << " " << var_name << " " << oprands.size() << " ";
                for (const auto &arg : oprands) {
                    std::cerr << " " << arg;
                }
                std::cerr << std::endl;
                throw CodeGenException("unknown type");
            }
            std::string op_func = "Morula::op_" + inst.op_str();
            std::string arg_list = "";
            auto args = inst.oprands();
            for (int i = 0; i < args.size(); i++) {
                arg_list += sanitize_name(args[i]);
                if (i != args.size() - 1) {
                    arg_list += ", ";
                }
            }
            decl = type_str + " " + var_name + ";";
            lines.push_back(var_name + " = " + op_func + "(" + arg_list + ");");
        }
        
        virtual void visit_inst(HeaderReadInst &inst) {
            std::string key = inst.header_name() + ":" + inst.field_name();
            if (types.pkt_fields.find(key) != types.pkt_fields.end()) {
                type_str = types.pkt_fields.find(key)->second;
            } else if (inst.llvm_inst_ptr_ != nullptr) {
                auto t = inst.llvm_inst_ptr_->getType();
                type_str = get_llvm_type(ctx, ctx.module, t);
            } else {
                type_str = "u64";
            }

            auto pkt_name = sanitize_name(inst.pkt_name());
            decl = type_str + " " + var_name + ";";
            lines.push_back(var_name + " = " + pkt_name
                            + "->" + inst.header_name()
                            + "." + inst.field_name() + ";");
        }
        
        virtual void visit_inst(HeaderWriteInst &inst) {
            auto pkt_name = sanitize_name(inst.pkt_name());
            auto val_reg = sanitize_name(inst.val_reg());            
            lines.push_back(pkt_name + "->" + inst.header_name()
                            + "." + inst.field_name()
                            + " = " + val_reg + ";");
        }
        
        virtual void visit_inst(MapGetInst &inst) {
            type_str = "void *";
            if (inst.llvm_inst_ptr_ != nullptr) {
                auto t = inst.llvm_inst_ptr_->getType();
                type_str = get_llvm_type(ctx, ctx.module, t);
            }
            //line = "void * " + var_name + " = nullptr;";
            decl = type_str + " " + var_name + ";";
            std::stringstream ss;
            ss << var_name << " = "
               << sanitize_name(inst.map_reg())
               << "->"
               << "findp("
               << sanitize_name(inst.key_reg())
               << ");";
            lines.push_back(ss.str());
        }
        
        virtual void visit_inst(AllocaInst &inst) {
            type_str = sanitize_type(inst.type());
            decl = type_str + " " + var_name
                + "[" + std::to_string(inst.n_elements()) + "];";
            lines.clear();
        }
        
        virtual void visit_inst(PhiInst &inst) {
            for (const auto &kv : inst.vals()) {
                if (ctx.reg_type.find(kv.second) != ctx.reg_type.end()) {
                    type_str = ctx.reg_type.find(kv.second)->second;
                    decl = type_str + " " + var_name + ";";
                    break;
                }
            }
            assert(decl != "");
            for (auto &kv : inst.vals()) {
                auto bb_name = sanitize_name(kv.first);
                auto val_reg = sanitize_name(kv.second);
                assert(ctx.bb_id.find(bb_name) != ctx.bb_id.end());
                int bb_idx = ctx.bb_id.find(bb_name)->second;
                std::string cond_line = "if (__last_blk == " + std::to_string(bb_idx) + ") {";
                std::string assign = var_name + " = " + val_reg + ";";
                lines.push_back(var_name + " = 0;");
                lines.push_back(cond_line);
                lines.push_back("    " + assign);
                lines.push_back("}");
            }
        }
        
        virtual void visit_inst(CallInst &inst) {
            static const std::unordered_set<std::string> known_classes = {
                "Packet",
                "WritablePacket",
                "Vector",
                "HashMap",
                "IPFlowID",
                "MyIPRewriter",
            };
            std::string func_name = inst.func_name();
            std::string demangled;
            bool is_class_method = false;
            bool is_operator = false;
            bool is_constructor = false;
            std::string class_name;
            std::string method_name;
            if (cxx_demangle(func_name, demangled)) {
                func_name = demangled;
                auto pos = func_name.find("::");
                if (pos != std::string::npos) {
                    class_name = remove_template(func_name.substr(0, pos));
                    if (known_classes.find(class_name) != known_classes.end()) {
                        is_class_method = true;
                        method_name = func_name.substr(pos + 2);
                        auto end = method_name.find("(");
                        if (end != std::string::npos) {
                            method_name = method_name.substr(0, end);
                        }
                        if (str_begin_with(method_name, "operator")) {
                            is_operator = true;
                        }
                        if (class_name == method_name) {
                            is_constructor = true;
                        }
                        std::cerr << "class_name: " << class_name
                                  << " " << method_name
                                  << " " << is_operator << std::endl;
                    }
                }
            } else {
                func_name = sanitize_func_name(func_name);
            }
                

            //std::cerr << var_name << " : Target::CallInst " << func_name << std::endl;
            if (ctx.func_ret_type.find(func_name) != ctx.func_ret_type.end()) {
                type_str = ctx.func_ret_type.find(func_name)->second;
                decl = type_str + " " + var_name + ";";
            } else if (inst.llvm_inst_ptr_ != nullptr && var_name != "") {
                //std::cerr << var_name << "have inst_ptr" << std::endl;
                if (const llvm::CallInst *call
                    = llvm::dyn_cast<llvm::CallInst>(inst.llvm_inst_ptr_)) {
                    auto t = call->getType();
                    auto type_size = get_type_size(call->getModule(), t);
                    type_str = get_llvm_type(ctx, call->getModule(), t);
                    std::cerr << "type_str for " << var_name << " : " << type_str << std::endl;
                    decl = type_str + " " + var_name + ";";
                }
            }
            std::string l = "";
            if (var_name != "") {
                l = var_name + " = ";
            }
            func_name = remove_func_paran(func_name);
            std::string arg_list = "";
            int start = (is_class_method) ? 1 : 0;
            for (int i = start; i < inst.args().size(); i++) {
                arg_list += sanitize_name(inst.args()[i]);
                if (i != inst.args().size() - 1) {
                    arg_list += ", ";
                }
            }
            if (is_class_method) {
                auto this_ptr = sanitize_name(inst.args()[0]);
                if (is_operator) {
                    l = l + "(*" + this_ptr + ")";
                } else if (is_constructor) {
                    l = "(void)new (" + this_ptr + ") ";
                } else {
                    if (this_ptr == "undef") {
                        this_ptr = "((" + class_name + " *)nullptr)";
                    }
                    l = l + this_ptr;
                    l += "->";
                } 
                func_name = method_name;
            }

            if (is_operator) {
                l = l + operator_to_str(func_name, inst.args());
                std::cerr << "operator: " << l << std::endl;
            } else {
                l = l + func_name + "(" + arg_list + ");";
            }
            
            lines.push_back(l);
        }
        
        virtual void visit_inst(ReturnInst &inst) {
            if (inst.ret_val() == "") {
                lines.push_back("return;");
            } else {
                lines.push_back("return "
                                + sanitize_name(inst.ret_val()) + ";");
            }
        }
        
        virtual void visit_inst(EmitPktInst &inst) {
            auto pkt_name = sanitize_name(inst.pkt_name());
            lines.push_back("Morula::emit_pkt(" + pkt_name
                            + ", " + sanitize_name(inst.port_reg()) + ");");
        }
        
        virtual void visit_inst(UnknownInst &inst) {
            throw CodeGenException{"found unknown instruction"};
        }
        
        virtual void visit_inst(TransitInst &inst) {
            lines.push_back("Morula::to_next_state();");
        }
    };

    CppGen::CppGen(std::unordered_map<std::string, BasicBlock *> &blocks,
                   llvm::Module *module,
                   std::vector<std::string> &entries,
                   const GlobalTypes &t): CodeGen(blocks, module, entries), types_(t) {
    }

    std::vector<std::string> CppGen::gen_code() const {
        /* 
         * first calculate the in-degree of each basic block.
         * This will be used to determine if this block is in a loop
         */
        std::vector<std::string> result;
        std::unordered_map<std::string, std::unordered_set<std::string>> prev_block;
        for (auto &kv : blocks_) {
            auto blk_ptr = kv.second;
            auto nexts = blk_ptr->next_blocks();
            for (auto &n : nexts) {
                prev_block[n].insert(kv.first);
            }
        }

        std::string type_str;

        CppGenCtx ctx;
        ctx.module = module_;

        struct QEle {
            std::string blk_name;
        };

        std::queue<QEle> q;

        //std::unordered_map<std::string, std::string> var_type;
        std::unordered_set<std::string> queued;
        std::vector<std::string> visit_order;
        std::unordered_set<std::string> need_forward_decl;
        std::unordered_set<std::string> live_regs;
        int blk_id = 1;
        ctx.bb_id.clear();
        for (auto &bn : this->entries_) {
            q.emplace();
            QEle &e = q.back();
            e.blk_name = bn;
            queued.insert(bn);
        }
        while (!q.empty()) {
            QEle curr = q.front();
            q.pop();
            visit_order.push_back(curr.blk_name);
            assert(this->blocks_.find(curr.blk_name) != this->blocks_.end());
            auto blk_ptr = this->blocks_.find(curr.blk_name)->second;
            auto insts = blk_ptr->insts_mut();
            for (int i = 0; i < insts.size(); i++) {
                auto dst_reg = insts[i]->get_dst_reg();
                if (dst_reg != "") {
                    live_regs.insert(dst_reg);
                }
                InstDeps deps;
                get_deps(*insts[i], deps);
                for (auto &r : deps.reg_dep) {
                    if (live_regs.find(r) == live_regs.end()) {
                        need_forward_decl.insert(r);
                    }
                }
                if (insts[i]->is_alloca()) {
                    need_forward_decl.insert(insts[i]->get_dst_reg());
                }
            }
            auto nexts = blk_ptr->next_blocks();
            for (auto &n : nexts) {
                if (queued.find(n) == queued.end()) {
                    q.emplace();
                    QEle &e = q.back();
                    e.blk_name = n;
                    queued.insert(n);
                }
            }
            ctx.bb_id[sanitize_name(curr.blk_name)] = blk_id;
            blk_id++;
        }

        for (auto &blk_name : visit_order) {
            auto blk_ptr = this->blocks_.find(blk_name)->second;
            auto insts = blk_ptr->insts_mut();
            for (int i = 0; i < insts.size(); i++) {
                if (insts[i]->is_call()) {
                    auto inst = std::dynamic_pointer_cast<CallInst>(insts[i]);
                    auto f_name = inst->func_name();
                    std::string demangled;
                    if (!cxx_demangle(f_name, demangled)) {
                        continue;
                    }
                    if (!is_class_method(demangled)) {
                        continue;
                    }
                    auto class_name = get_class_name(demangled);
                    if (!is_template_type(class_name)) {
                        continue;
                    }
                    auto template_base = get_template_base(class_name);
                    if (inst->llvm_inst_ptr_ == nullptr) {
                        continue;
                    }
                    auto this_ptr = inst->llvm_inst_ptr_->getOperand(0);
                    assert(this_ptr->getType()->isPointerTy());
                    auto type_name = get_llvm_type(ctx, inst->llvm_inst_ptr_->getModule(),
                                                   this_ptr->getType()->getPointerElementType());
                    auto pos = type_name.find(".");
                    auto type_name_base = type_name.substr(0, pos);
                    if (type_name_base == template_base) {
                        ctx.template_mapping[type_name] = class_name;
                    }
                }
            }
        }

        for (auto &kv : ctx.template_mapping) {
            std::cerr << "template_mapping : " << kv.first << " -> " << kv.second << std::endl;
        }

        std::vector<std::string> decls;
        std::vector<std::string> body;
        decls.push_back("    u64 __last_blk = 0;");
        for (auto &blk_name : visit_order) {
            auto blk_ptr = this->blocks_.find(blk_name)->second;
            auto insts = blk_ptr->insts_mut();
            body.push_back(sanitize_name(blk_name) + ":");
            for (int i = 0; i < insts.size(); i++) {
                auto dst_reg = insts[i]->get_dst_reg();
                auto var_name = sanitize_name(dst_reg);
                CppDeclInstVisitor type_visitor(type_str, types_,
                                                ctx, var_name);
                type_visitor.visit(*insts[i]);
                if (type_visitor.decl != "") {
                    decls.push_back("    " + type_visitor.decl);
                }
                // if (need_forward_decl.find(dst_reg) != need_forward_decl.end()) {
                //     if (type_visitor.type_str == "") {
                //         throw CodeGenException{"error: decl not correctly generated"};
                //     }
                //     if (insts[i]->is_alloca()) {
                //         decls.push_back("    " + type_visitor.decl);
                //     } else {
                //         decls.push_back("    " + type_str + " " + var_name + ";");
                //     }
                //     //var_type.insert({dst_reg, type_str});
                // } else if (dst_reg != "" && type_visitor.lines.size() > 0) {
                //     type_visitor.lines[0] = type_str + " " + type_visitor.lines[0];
                // }
                for (int j = 0; j < type_visitor.lines.size(); j++) {
                    body.push_back("    " + type_visitor.lines[j]);
                }

                if (dst_reg != "") {
                    ctx.reg_type.insert({dst_reg, type_str});
                }
            }
            body.push_back("    __last_blk = " + std::to_string(ctx.bb_id[sanitize_name(blk_name)]) + ";");
            auto nexts = blk_ptr->next_blocks();
            if (blk_ptr->is_conditional()) {
                assert(nexts.size() == 2);
                auto cond_var = sanitize_name(blk_ptr->branch_cond());
                body.push_back("    if (" + cond_var + ") {");
                body.push_back("        goto " + sanitize_name(nexts[0]) + ";");
                body.push_back("    } else {");
                body.push_back("        goto " + sanitize_name(nexts[1]) + ";");
                body.push_back("    }");
            } else if (nexts.size() == 1) {
                body.push_back("    goto " + sanitize_name(nexts[0]) + ";");
            }
        }

        result = decls;
        for (auto &l : body) {
            result.push_back(l);
        }

        return result;
    }

    P4Gen::P4Gen(std::unordered_map<std::string, BasicBlock *> &blocks,
                 std::vector<std::string> &entries): CodeGen(blocks, nullptr, entries) {
    }

    bool have_loop(const std::unordered_map<std::string, BasicBlock *> &blocks,
                   std::unordered_set<std::string> &visited,
                   const std::string &curr) {
        // using depth first search to check if there are loop
        if (visited.find(curr) != visited.end()) {
            return true;
        } else {
            auto nexts = blocks.find(curr)->second->next_blocks();
            visited.insert(curr);
            for (auto &n : nexts) {
                bool r = have_loop(blocks, visited, n);
                if (r) {
                    return true;
                }
            }
            visited.erase(curr);
            return false;
        }
    }

    void p4_reg_live_check(std::unordered_map<std::string, std::unordered_set<std::string>> &live_vars,
                           const std::unordered_map<std::string, BasicBlock *> &blocks,
                           const std::unordered_map<std::string, std::string> &prev_bb) {
        struct BfsEle {
            std::string curr;
            std::unordered_set<std::string> live_var;
        };

        std::queue<BfsEle> q;

        for (auto &kv : blocks) {
            auto blk = kv.second;
            if (blk->next_blocks().size() == 0) {
                BfsEle ele;
                ele.curr = blk->get_name();
                ele.live_var.clear();
                q.push(ele);
            }
        }

        while (!q.empty()) {
            auto ele = q.front();
            q.pop();

            assert(blocks.find(ele.curr) != blocks.end());
            BasicBlock *blk = blocks.find(ele.curr)->second;

            auto &insts = blk->insts_mut();
            for (auto &inst : insts) {
                InstDeps deps;
                get_deps(*inst, deps);
                for (auto reg : deps.reg_dep) {
                    ele.live_var.insert(reg);
                }
                ele.live_var.erase(inst->get_dst_reg());
            }

            for (auto &reg : ele.live_var) {
                live_vars[ele.curr].insert(reg);
            }
            if (prev_bb.find(ele.curr) != prev_bb.end()) {
                ele.curr = prev_bb.find(ele.curr)->second;
                q.push(ele);
            }
        }
    }

    struct P4CodeGenCtx {
        llvm::Module *module;
        std::unordered_map<std::string, BasicBlock *> blocks;
        std::unordered_map<std::string,
                           std::unordered_set<std::string>> live_vars;
        std::unordered_map<std::string, int> metadata_vars;
        std::unordered_map<int, std::unordered_set<std::string>> free_vars;
        std::unordered_map<std::string, std::shared_ptr<P4::RValue>> var_mapping;
        NameFactory &name_gen;
    };

    class P4StmtGenInstVisitor : public ConstInstVisitor {
    public:
        P4::StmtBlock stmts;
        P4CodeGenCtx &ctx;

        P4StmtGenInstVisitor(P4CodeGenCtx &c): ctx(c) {
            stmts.clear();
        }

        std::string get_free_var_of_size(int num_bits) {
            std::string var_name = "";
            if (ctx.free_vars[num_bits].size() == 0) {
                var_name = ctx.name_gen("bv" + std::to_string(num_bits));
                ctx.metadata_vars[var_name] = num_bits;
            } else {
                var_name = *ctx.free_vars[num_bits].begin();
                ctx.free_vars[num_bits].erase(var_name);
            }
            return var_name;
        }
        
        virtual void visit_inst(const Instruction &inst) override {
            std::stringstream ss;
            inst.print(ss);
            auto s = std::make_shared<P4::UntranslatedStmt>(ss.str());
            stmts.push_back(s);
        }
        
        // virtual void visit_inst(const LLVMInst &inst) override {
        // }
        
        virtual void visit_inst(const ArithInst &inst) override {
            ArithInst::Op op = inst.op();
            std::string op_str = "";
            using Op = ArithInst::Op;

            // first find the field to write to
            // get type of the dst reg
            std::string dst_name = "";
            auto t = inst.dst_type_anno;
            assert(t != nullptr);
            int num_bits = get_type_size(ctx.module, t) * 8;
            if (ctx.free_vars[num_bits].size() == 0) {
                dst_name = ctx.name_gen("bv" + std::to_string(num_bits));
                ctx.metadata_vars[dst_name] = num_bits;
            } else {
                dst_name = *ctx.free_vars[num_bits].begin();
                ctx.free_vars[num_bits].erase(dst_name);
            }

            using namespace P4;

            auto dst = std::make_shared<MetadataRef>(dst_name);
            std::vector<std::shared_ptr<RValue>> args;
            for (int i = 0; i < inst.oprands().size(); i++) {
                auto arg = inst.oprands()[i];
                if (ctx.var_mapping.find(arg) != ctx.var_mapping.end()) {
                    args.push_back(ctx.var_mapping[arg]);
                } else {
                    args.push_back(std::make_shared<ConstVal>(inst.oprands()[i]));
                }
            }
            
            switch (op) {
            case Op::CONST_VAL: {
                auto val = std::make_shared<ConstVal>(inst.oprands()[0]);
                stmts.push_back(std::make_shared<Assign>(dst, val));
                break;
            }
            case Op::ADD:
                stmts.push_back(std::make_shared<OpStmt>("add", dst, args));
                break;
            case Op::SUB:
                stmts.push_back(std::make_shared<OpStmt>("subtract", dst, args));
                break;
            // case Op::ARSH:
            //     break;
            // case Op::LRSH:
            //     break;
            // case Op::LSH:
            //     break;
            // case Op::EQ:
            //     break;
            // case Op::NE:
            //     break;
            // case Op::SLT:
            //     break;
            // case Op::ULT:
            //     break;
            // case Op::SLE:
            //     break;
            // case Op::ULE:
            //     break;
            // case Op::SGT:
            //     break;
            // case Op::UGT:
            //     break;
            // case Op::SGE:
            //     break;
            // case Op::UGE:
            //     break;
            case Op::AND:
                stmts.push_back(std::make_shared<OpStmt>("bit_and", dst, args));
                break;
            case Op::OR:
                stmts.push_back(std::make_shared<OpStmt>("bit_or", dst, args));
                break;
            case Op::XOR:
                stmts.push_back(std::make_shared<OpStmt>("bit_xor", dst, args));
                break;
            // case Op::NOT:
            //     break;
            // case Op::LAND:
            //     break;
            // case Op::LOR:
            //     break;
            // case Op::LNOT:
            //     break;
            default:
                throw CodeGenException {"unknown arith op"};
                break;
            }
        }
        
        // virtual void visit_inst(const BranchInst &inst) override {
        // }
        
        virtual void visit_inst(const HeaderReadInst &inst) override {
            auto val = std::make_shared<P4::HeaderRef>(inst.header_name(), inst.field_name());
            int num_bits = get_type_size(ctx.module, inst.llvm_inst_ptr_->getType()) * 8;
            auto dst_name = get_free_var_of_size(num_bits);
            auto dst = std::make_shared<P4::MetadataRef>(dst_name);
            stmts.push_back(std::make_shared<P4::Assign>(dst, val));
        }
        
        virtual void visit_inst(const HeaderWriteInst &inst) override {
            auto dst = std::make_shared<P4::HeaderRef>(inst.header_name(), inst.field_name());
            auto val = ctx.var_mapping[inst.val_reg()];
            stmts.push_back(std::make_shared<P4::Assign>(dst, val));
        }
        
        virtual void visit_inst(const MapGetInst &inst) override {
            // do nothing
        }
        
        virtual void visit_inst(const AllocaInst &inst) override {
            // do nothing
        }
        
        virtual void visit_inst(const PhiInst &inst) override {
        }
        
        virtual void visit_inst(const CallInst &inst) override {
        }
        
        virtual void visit_inst(const ReturnInst &inst) override {
        }
        
        virtual void visit_inst(const EmitPktInst &inst) override {
        }
        
        virtual void visit_inst(const UnknownInst &inst) override {
        }
        
        virtual void visit_inst(const TransitInst &inst) override {
        }
        
    };

    P4::StmtBlock gen_p4_recursive(const std::string &curr,
                                   const P4CodeGenCtx &ctx) {
        P4::StmtBlock result;
        // genreate code for this block and call next blocks recursively
        auto blk = ctx.blocks.find(curr)->second;
        auto insts = blk->insts_mut();

        // TODO: generate p4
        
        
        // recursive call to next blocks
        if (blk->is_conditional()) {
            auto next_bb = blk->next_bb();
            auto code = gen_p4_recursive(next_bb, ctx);
            for (auto &stmt : code) {
                result.push_back(stmt);
            }
        } else {
            auto t_bb = blk->t_branch();
            auto f_bb = blk->f_branch();
            auto t_code = gen_p4_recursive(t_bb, ctx);
            auto f_code = gen_p4_recursive(f_bb, ctx);

            auto cond = blk->branch_cond();
            auto cond_var = ctx.var_mapping.find(cond)->second;
            auto if_stmt = std::make_shared<P4::IfStmt>(cond_var, t_code, f_code);
            result.push_back(if_stmt);
        }
        return result;
    }

    std::vector<std::string> P4Gen::gen_code() const {
        /* 
         * first calculate the in-degree of each basic block.
         * This will be used to determine if this block is in a loop
         */
        std::unordered_map<std::string, std::unordered_set<std::string>> prev_block;
        for (auto &kv : blocks_) {
            auto blk_ptr = kv.second;
            auto nexts = blk_ptr->next_blocks();
            for (auto &n : nexts) {
                prev_block[n].insert(kv.first);
            }
        }

        // check if there are loop
        for (auto &e : entries_) {
            std::unordered_set<std::string> visited;
            assert(!have_loop(blocks_, visited, e));
        }

        assert(entries_.size() == 1);

        auto action_blocks = split_blocks(blocks_);

        // now split all map lookups into a single basic block
        // note that now instructions in each of the basic block is "dependency free"
        // therefore we could simply find the map lookup instruction and put them
        // into new basic blocks at the end of the original block

        std::vector<BasicBlock *> to_insert;

        for (auto &kv : action_blocks) {
            auto blk = kv.second;
            auto &insts = blk->insts_mut();
            std::vector<int> to_remove;
            for (int i = 0; i < insts.size(); i++) {
                if (insts[i]->is_map_get()) {
                    to_remove.push_back(i);
                }
            }
            std::vector<BasicBlock *> new_blks;
            for (int i = to_remove.size() - 1; i >= 0; i++) {
                auto blk_name = blk->get_name() + "_map_get_bb_" + std::to_string(new_blks.size());
                auto nb = new BasicBlock(blk_name, BasicBlock::InstList{insts[to_remove[i]]});
                insts.erase(insts.begin() + to_remove[i]);
                new_blks.push_back(nb);
            }

            // now connect new basic blocks
            for (int i = 0; i < new_blks.size(); i++) {
                if (i != 0) {
                    new_blks[i-1]->add_next(new_blks[i]->get_name());
                }
            }

            // now create basic block for each of the "map-get" instruction
            for (auto b : new_blks) {
                to_insert.push_back(b);
            }

            if (new_blks.size() > 0) {
                if (blk->is_conditional()) {
                    new_blks[new_blks.size() - 1]->add_branch(blk->branch_cond(),
                                                              blk->t_branch(),
                                                              blk->f_branch());
                } else {
                    new_blks[new_blks.size() - 1]->add_next(blk->next_bb());
                }
                blk->add_next(new_blks[0]->get_name());
            }
        }

        // at this point we could start generate P4 code        
        // each block should be an apply clause
        std::unordered_map<std::string, bool> vars_live;                  // if the variable is in use
        std::unordered_map<int, std::vector<std::string>> metadata_vars;  // vars of certain size (in bits)

        // first perform lifetime check for each variable
        std::unordered_map<std::string, std::unordered_set<std::string>> live_vars;
        // live_vars: map that stores live variables at the \emph{Beginning} of each basic block
        std::unordered_map<std::string, std::string> prev_bb;
        for (auto &kv : action_blocks) {
            auto blk = kv.second;
            auto nexts = blk->next_blocks();
            for (auto &b : nexts) {
                assert(prev_bb.find(b) == prev_bb.end());
                prev_bb[b] = blk->get_name();
            }
        }

        p4_reg_live_check(live_vars, action_blocks, prev_bb);

        /* now start to generate p4 code block by block
         * each block will be translate into either
         * (1) applying an action
         * (2) applying a table
         * we perform the translation using a depth first search from the entry bb
         */

        
        
        std::vector<std::string> result;
        return result;
    }
}
