#include "pass-p4gen.hpp"
#include "p4-parser-common.hpp"

using namespace Target;

namespace Morula {

    void P4TableInfo::print(std::ostream &os) const {
        os << "{";
        for (int i = 0; i < this->key_info.size(); i++) {
            os << this->key_info[i];
            if (i != this->key_info.size() - 1) {
                os << ", ";
            }
        }
        os << "} -> {";

        for (int i = 0; i < this->val_info.size(); i++) {
            os << this->val_info[i];
            if (i != this->val_info.size() - 1) {
                os << ", ";
            }
        }
        os << "}";
    }

    std::string p4_ident_sanitize(const std::string &ident) {
        auto str = str_replace_all(ident, "%", "_");
        return str;
    }
    
    std::unique_ptr<P4GenCtx> P4ExtendCtx::pass_impl(std::unique_ptr<PassCtx> s) {
        return std::make_unique<P4GenCtx>(std::move(*s));
    }
    
    std::unique_ptr<P4GenCtx> P4Alloca::pass_impl(std::unique_ptr<P4GenCtx> s) {
        /*
         * for all "alloca" instruction, create metadata field for them
         */
        for (auto &kv : s->blocks) {
            auto blk = kv.second;
            auto insts = blk->insts_mut();
            for (int i = 0; i < insts.size(); i++) {
                auto inst = insts[i];
                if (inst->is_alloca()) {
                    auto alloca = std::dynamic_pointer_cast<AllocaInst>(inst);
                    auto t = alloca->llvm_type;
                    // now find how many fields are necessary
                    if (!llvm_contains_no_ptr(t)) {
                        continue;
                    }
                    P4Entry entry;
                    auto fields = llvm_flatten_struct_layout(s->llvm_module.get(), t);
                    auto entry_name = "alloca_" + p4_ident_sanitize(inst->get_dst_reg()) + "_";
                    s->metadata_entries[entry_name] = fields;
                } else if (inst->is_data_structure_op()) {
                    // the value needs space to save
                    auto ptr = std::dynamic_pointer_cast<DataStructureOp>(inst);
                    auto dst = ptr->get_dst_reg();
                    if (dst != "") {
                        // get its type from the llvm instruction
                        auto llvm = ptr->llvm_inst_ptr_;
                        auto ret_t = llvm->getType();
                        // this return type should be a pointer
                        assert(ret_t->isPointerTy());
                        auto data_t = ret_t->getPointerElementType();
                        assert(llvm_contains_no_ptr(data_t));
                        // now flatten the struct
                        auto fields = llvm_flatten_struct_layout(s->llvm_module.get(), data_t);
                        auto entry_name = inst->get_dst_reg();//"val_" + p4_ident_sanitize(inst->get_dst_reg()) + "_";
                        s->metadata_entries[entry_name] = fields;
                    }
                } else if (inst->is_map_get()) {
                    assert(false && "deprecated");
                }
            }
        }
        return s;
    }

    static P4Entry get_p4entry_from_type(llvm::Module *mod, llvm::Type *llvm_type) {
        llvm::Type *t = llvm_type;
        if (t->isPointerTy()) {
            t = t->getPointerElementType();
        }
        assert(llvm_contains_no_ptr(t));
        auto fields = llvm_flatten_struct(mod, t);
        return fields;
    }

    PASS_IMPL(P4EntryAlloc, s) {
        std::unordered_set<std::string> entry_regs;
        for (auto &kv : s->blocks) {
            auto blk = kv.second;
            auto insts = blk->insts_mut();
            for (int i = 0; i < insts.size(); i++) {
                auto inst = insts[i];
                if (inst->is_entry_read()) {
                    auto ptr = std::dynamic_pointer_cast<EntryReadInst>(inst);
                    entry_regs.insert(ptr->entry_reg());
                }

                if (inst->is_entry_write()) {
                    auto ptr = std::dynamic_pointer_cast<EntryWriteInst>(inst);
                    entry_regs.insert(ptr->entry_reg());
                }
            }
        }

        for (auto reg : entry_regs) {
            // TODO: for each entry trace the source to find its type
            // Assumption: the type of the register should be a pointer
            // Where the pointer type denotes the type of the entry
            auto id = s->var_source[reg];
            auto inst = s->blocks[std::get<0>(id)]->insts_mut()[std::get<1>(id)];
            inst->print(std::cerr);
            std::cerr << std::endl;
            auto entry_t = inst->llvm_type_;
            if (entry_t == nullptr) {
                entry_t = inst->llvm_inst_ptr_->getType();
            }
            assert(entry_t->isPointerTy());
            std::cerr << "flatten entry: " << reg << " " << get_llvm_type_str(*entry_t) << " : ";
            auto layout = llvm_flatten_struct_layout(s->llvm_module.get(), entry_t->getPointerElementType());
            for (int i = 0; i < layout.fields.size(); i++) {
                auto &field = layout.fields[i];
                std::cerr << "(" << field.offset << ", " << field.size << ") ";
            }
            std::cerr << std::endl;

            // Now allocate metadata field for the entry
            auto entry_name = reg;//"entry" + p4_ident_sanitize((*s->name_gen)(reg));
            //s->metadata_entries[entry_name] = layout;
        }
        return s;
    }

    PASS_IMPL(P4Map, s) {
        for (auto &kv : s->blocks) {
            auto blk = kv.second;
            auto insts = blk->insts_mut();
            for (int i = 0; i < insts.size(); i++) {
                if (insts[i]->is_data_structure_op()) {
                    // now we need to find out info about the map
                    auto ptr = std::dynamic_pointer_cast<DataStructureOp>(insts[i]);
                    std::cerr << "Got Data Structure OP: ";
                    ptr->print(std::cerr);
                    std::cerr << std::endl;
                    auto data_type = ptr->data_structure_type();
                    auto op = ptr->get_op();
                    if (data_type == "map") {
                        if (op == "findp") {
                            // dst_reg is value, 1st arg is key
                            auto llvm = ptr->llvm_inst_ptr_;
                            assert(llvm != nullptr);
                            auto kt = llvm->getOperand(1)->getType();
                            auto vt = llvm->getType();
                            P4TableInfo tab;
                            tab.key_info = get_p4entry_from_type(s->llvm_module.get(), kt);
                            tab.val_info = get_p4entry_from_type(s->llvm_module.get(), vt);
                            auto tab_name = p4_ident_sanitize("table" + ptr->obj_reg());
                            if (s->tables.find(tab_name) != s->tables.end()) {
                                // table have to be same
                                const auto &old_tab = s->tables.find(tab_name)->second;
                                assert(tab == s->tables[tab_name]);
                            }
                            s->tables.insert({tab_name, tab});
                        }
                    } else if (data_type == "vector") {
                        if (op == "operator[]") {
                            // dst_reg is value, key is int
                            auto llvm = ptr->llvm_inst_ptr_;
                            assert(llvm != nullptr);
                            auto kt = llvm->getOperand(1)->getType();
                            auto vt = llvm->getType();
                            P4TableInfo tab;
                            tab.key_info = get_p4entry_from_type(s->llvm_module.get(), kt);
                            tab.val_info = get_p4entry_from_type(s->llvm_module.get(), vt);
                            auto tab_name = p4_ident_sanitize("vec" + ptr->obj_reg());
                            if (s->tables.find(tab_name) != s->tables.end()) {
                                // table have to be same
                                const auto &old_tab = s->tables.find(tab_name)->second;
                                assert(tab == s->tables[tab_name]);
                            }
                            s->tables.insert({tab_name, tab});
                        }
                    }
                }
            }
        }
        return s;
    }

    static void basic_block_dfs(const std::string &curr,
                                std::vector<std::string> &visited,
                                PassCtx &ctx) {
        if (std::find(visited.begin(), visited.end(), curr) != visited.end()) {
            return;
        }

        auto blk = ctx.blocks.find(curr)->second;
        auto nexts = blk->next_blocks();
        visited.push_back(curr);
        for (auto &n : nexts) {
            basic_block_dfs(n, visited, ctx);
        }
    }

    std::vector<std::string> topo_sort(PassCtx &ctx) {
        std::vector<std::string> entries;
        for (auto &kv : ctx.blocks) {
            auto iter = ctx.rev_edges.find(kv.first);
            if (iter == ctx.rev_edges.end()
                || iter->second.size() == 0) {
                entries.push_back(kv.first);
            }
        }
        std::vector<std::string> order;
        
        for (auto &e : entries) {
            basic_block_dfs(e, order, ctx);
        }
        return order;
    }

    class P4GenLLVMVisitor : public llvm::InstVisitor<P4GenLLVMVisitor> {
    public:
        std::vector<std::shared_ptr<P4::Stmt>> &stmts;
        P4GenCtx &ctx;

        P4GenLLVMVisitor(P4GenCtx &c,
                         std::vector<std::shared_ptr<P4::Stmt>> &s): ctx(c), stmts(s) {}

        void visitBinaryOperator(const llvm::BinaryOperator &inst) {
            auto a1 = get_llvm_name(*inst.getOperand(0));
            auto a2 = get_llvm_name(*inst.getOperand(1));
            std::shared_ptr<P4::Value> arg1 = nullptr;
            std::shared_ptr<P4::Value> arg2 = nullptr;
            if (!is_llvm_constant(*inst.getOperand(0))) {
                arg1 = ctx.reg2p4val.find(a1)->second;
            } else {
                arg1 = std::make_shared<P4::ConstVal>(a1);
            }

            if (!is_llvm_constant(*inst.getOperand(1))) {
                arg2 = ctx.reg2p4val.find(a2)->second;
            } else {
                arg2 = std::make_shared<P4::ConstVal>(a2);
            }

            std::string opstring = inst.getOpcodeName();
            static const std::unordered_map<std::string, std::string> op_mapping = {
                {"add", "add"},
                {"sub", "substract"},
                {"and", "bit_and"},
                {"or", "bit_or"},
                {"xor", "bit_xor"},
                {"shl", "shift_left"},
                {"lshr", "shift_right"},
                {"ashr", "shift_right"},
            };
            assert(op_mapping.find(opstring) != op_mapping.end());
            auto op = op_mapping.find(opstring)->second;
            std::vector<std::shared_ptr<P4::Value>> args = {arg1, arg2};
            auto stmt = std::make_shared<P4::PrimitiveStmt>(op, args);
            stmts.push_back(stmt);
        }
    };

    class P4GenVisitor : public InstVisitor {
    public:
        std::vector<std::shared_ptr<P4::Stmt>> &stmts;
        P4GenCtx &ctx;

        P4GenVisitor(P4GenCtx &c,
                     std::vector<std::shared_ptr<P4::Stmt>> &s): ctx(c), stmts(s) {}

        virtual void visit_inst(Instruction &inst) {
            inst.print(std::cerr);
            std::cerr << std::endl;
            assert(false && "Unknown Instruction");
        }

        virtual void visit_inst(LLVMInst &inst) {
            inst.print(std::cerr);
            std::cerr << std::endl;

            auto llvm = inst.get_inst();
            
            P4GenLLVMVisitor visitor(ctx, stmts);
            visitor.visit(*llvm);
        }

        virtual void visit_inst(PhiInst &phi) {
            
        }

        virtual void visit_inst(CallInst &inst) {
            auto fn = inst.func_name();
            if (fn == "Packet::uniqueify()") {
                return;
            } else if (fn == "Packet::transport_length() const") {
                auto dst = inst.get_dst_reg();
                auto dst_field = ctx.reg2p4val[dst];
                P4::ValList args = {dst_field, std::make_shared<P4::MetadataRef>("packet_length")};
                auto stmt = std::make_shared<P4::PrimitiveStmt>("modify_field", args);
                stmts.push_back(stmt);
                return;
            } else if (fn == "click_jiffies()") {
                auto dst = inst.get_dst_reg();
                auto dst_field = ctx.reg2p4val[dst];
                auto ref = std::make_shared<P4::MetadataRef>("ingress_global_timestamp");
                P4::ValList args = {dst_field, ref};
                stmts.push_back(std::make_shared<P4::PrimitiveStmt>("modify_field", args));
                return;
            } else if (fn == "Packet::has_network_header() const") {
                // TODO: currently only a place holder here
                auto dst = inst.get_dst_reg();
                auto dst_field = ctx.reg2p4val[dst];
                auto ref = std::make_shared<P4::MetadataRef>("has_netwrk_header");
                P4::ValList args = {dst_field, ref};
                stmts.push_back(std::make_shared<P4::PrimitiveStmt>("modify_field", args));
                return;
            }

            inst.print(std::cerr);
            std::cerr << "   :   "
                      << fn << std::endl;
            assert(false && "unknown callinst");
        }

        virtual void visit_inst(HeaderReadInst &inst) {
            auto dst = inst.get_dst_reg();
            assert(ctx.reg2p4val.find(dst) != ctx.reg2p4val.end());
            auto md_field = ctx.reg2p4val[dst];
            auto hdr = inst.header_name();
            auto field = inst.field_name();
            std::vector<std::shared_ptr<P4::Value>> args = {
                md_field,
                std::make_shared<P4::HeaderRef>(hdr, field),
            };
            auto stmt_ptr = std::make_shared<P4::PrimitiveStmt>("modify_field", args);
            stmts.push_back(stmt_ptr);
        }

        virtual void visit_inst(HeaderWriteInst &inst) {
            auto val = inst.val_reg();
            assert(ctx.reg2p4val.find(val) != ctx.reg2p4val.end());
            auto md_field = ctx.reg2p4val[val];
            auto hdr = inst.header_name();
            auto field = inst.field_name();
            std::vector<std::shared_ptr<P4::Value>> args = {
                std::make_shared<P4::HeaderRef>(hdr, field),
                md_field,
            };
            auto stmt_ptr = std::make_shared<P4::PrimitiveStmt>("modify_field", args);
            stmts.push_back(stmt_ptr);
        }

        static std::string arith_to_p4primitive(ArithInst::Op op) {
            using Op = ArithInst::Op;
            switch (op) {
            case Op::CONST_VAL:
                return "modify_field";
            case Op::ADD:
                return "add";
            case Op::SUB:
                return "subtract";
            case Op::AND:
                return "bit_and";
            case Op::OR:
                return "bit_or";
            case Op::XOR:
                return "bit_xor";
            case Op::NOT:
                return "bit_not";
            case Op::LSH:
                return "shift_left";
            case Op::LRSH:
                return "shift_right";
            case Op::EQ:
            case Op::NE:
            case Op::ULT:
            case Op::ULE:
            case Op::UGT:
            case Op::UGE:
            case Op::SLT:
            case Op::SLE:
            case Op::SGT:
            case Op::SGE:
            case Op::LAND:
            case Op::LOR:
            case Op::LNOT:
            case Op::ARSH:
            default:
                throw "unknown op";
            }
        }

        static bool is_number(const std::string& s) {
            std::string::const_iterator it = s.begin();
            while (it != s.end() && std::isdigit(*it)) ++it;
            return !s.empty() && it == s.end();
        }

        virtual void visit_inst(ArithInst &inst) {
            auto dst = inst.get_dst_reg();
            assert(ctx.reg2p4val.find(dst) != ctx.reg2p4val.end());
            auto dst_field = ctx.reg2p4val[dst];
            std::vector<std::shared_ptr<P4::Value>> args_field;
            args_field.push_back(dst_field);
            for (auto &oprand : inst.oprands()) {
                std::shared_ptr<P4::Value> arg = nullptr;
                if (is_number(oprand)) {
                    arg = std::make_shared<P4::ConstVal>(oprand);
                } else {
                    assert(ctx.reg2p4val.find(oprand) != ctx.reg2p4val.end());
                    arg = ctx.reg2p4val[oprand];
                }
                args_field.push_back(arg);
            }

            auto op_str = arith_to_p4primitive(inst.op());
            auto stmt_ptr = std::make_shared<P4::PrimitiveStmt>(op_str, args_field);
            stmts.push_back(stmt_ptr);
        }

        virtual void visit_inst(MapGetInst &inst) {
            assert(false && "MapGetInst Deprecated");
        }

        virtual void visit_inst(DataStructureOp &inst) {
            assert(false && "DataStructureOp should be a seperate apply");
        }

        std::string find_entry_field(const std::string &entry, int off) {
            assert(ctx.metadata_entries.find(entry) != ctx.metadata_entries.end());
            const auto &p4_entry = ctx.metadata_entries[entry];
            for (int i = 0; i < p4_entry.fields.size(); i++) {
                auto &field = p4_entry.fields[i];
                if (field.offset == off) {
                    return entry + "_" + std::to_string(i);
                }
            }
            assert(false && "could not find entry field");
        }
                                            

        virtual void visit_inst(EntryReadInst &inst) {
            auto entry = inst.entry_reg();
            auto off = inst.field_idx();
            auto field = find_entry_field(entry, off);
            
            auto dst = inst.get_dst_reg();
            assert(ctx.reg2p4val.find(dst) != ctx.reg2p4val.end());
            auto dst_ref = ctx.reg2p4val[dst];

            auto val_ref = std::make_shared<P4::HeaderRef>("metadata", field);
            std::vector<std::shared_ptr<P4::Value>> args = {dst_ref, val_ref};
            auto stmt_ptr = std::make_shared<P4::PrimitiveStmt>("modify_field", args);
            stmts.push_back(stmt_ptr);                                                    
        }
        
        virtual void visit_inst(EntryWriteInst &inst) {
            auto entry = inst.entry_reg();
            auto off = inst.field_idx();
            auto field = find_entry_field(entry, off);

            auto val = inst.val_reg();
            assert(ctx.reg2p4val.find(val) != ctx.reg2p4val.end());
            auto val_ref = ctx.reg2p4val[val];
            auto dst = std::make_shared<P4::HeaderRef>("metadata", field);
            
            std::vector<std::shared_ptr<P4::Value>> args = {dst, val_ref};
            auto stmt_ptr = std::make_shared<P4::PrimitiveStmt>("modify_field", args);
            stmts.push_back(stmt_ptr);
        }
        
        virtual void visit_inst(AllocaInst &inst) {
            // alloca is simply a nop now
        }
        
        virtual void visit_inst(EmitPktInst &inst) {
        }
        
        virtual void visit_inst(TransitInst &inst) {
        }
    };

    static bool is_map_get(Instruction *inst) {
        if (!inst->is_data_structure_op()) {
            return false;
        }

        auto ptr = dynamic_cast<DataStructureOp *>(inst);
        if (ptr->data_structure_type() == "map"
            && ptr->get_op() == "findp") {
            return true;
        } else {
            return false;
        }
    }

    std::vector<BasicBlock *> split_data_structure_op(BasicBlock *blk) {
        std::vector<BasicBlock *> result;
        auto &insts = blk->insts_mut();
        std::vector<std::shared_ptr<Instruction>> ns;
        for (int i = 0; i < insts.size(); i++) {
            auto inst = insts[i];
            if (inst->is_data_structure_op()) {
                auto blk_name = blk->get_name() + "_ds_" + std::to_string(i);
                auto new_blk = new BasicBlock(blk_name, {inst});
                result.push_back(new_blk);
            } else {
                ns.push_back(inst);
            }
        }
        blk->set_insts(ns);
        result.push_back(blk);
        return result;
    }

    static bool is_logical_op(std::shared_ptr<Instruction> inst) {
        if (inst->is_arith_inst()) {
            auto ptr = std::dynamic_pointer_cast<ArithInst>(inst);
            auto op = ptr->op();
            if (ArithInst::is_cmp(op)) {
                return true;
            }
        } else if (inst->is_llvm_inst()) {
            auto llvm = std::dynamic_pointer_cast<LLVMInst>(inst);
            if (llvm::ICmpInst *icmp = llvm::dyn_cast<llvm::ICmpInst>(llvm->get_inst())) {
                return true;
            } else if (llvm::BinaryOperator *bin_op
                       = llvm::dyn_cast<llvm::BinaryOperator>(llvm->get_inst())) {
                //std::string opstring = bin_op->getOpcodeName();
                
            }
        }
        return false;
    }

    std::vector<BasicBlock *> split_logical_op(BasicBlock *blk) {
        std::vector<BasicBlock *> result;
        auto &insts = blk->insts_mut();
        std::vector<std::shared_ptr<Instruction>> ns;
        for (int i = 0; i < insts.size(); i++) {
            auto inst = insts[i];
            bool splitted = false;
            std::string split_str = "";
            if (inst->is_arith_inst()) {
                auto ptr = std::dynamic_pointer_cast<ArithInst>(inst);
                auto op = ptr->op();
                if (ArithInst::is_cmp(op)) {
                    splitted = true;
                    split_str = "cmp";
                }
            } else if (inst->is_llvm_inst()) {
                auto llvm = std::dynamic_pointer_cast<LLVMInst>(inst);
                if (llvm::ICmpInst *icmp = llvm::dyn_cast<llvm::ICmpInst>(llvm->get_inst())) {
                    splitted = true;
                    split_str = "icmp";
                } else if (llvm::BinaryOperator *bin_op
                           = llvm::dyn_cast<llvm::BinaryOperator>(llvm->get_inst())) {
                    //std::string opstring = bin_op->getOpcodeName();
                    
                }
            }

            if (splitted) {
                auto blk_name = blk->get_name() + "_" + split_str
                    + "_"  + std::to_string(i);
                auto new_blk = new BasicBlock(blk_name, {inst});
                result.push_back(new_blk);
            } else {
                ns.push_back(inst);
            }
        }
        blk->set_insts(ns);
        result.push_back(blk);
        return result;
    }

    static std::vector<BasicBlock *>
    split_blocks(const std::vector<BasicBlock *> &blocks,
                 std::function<std::vector<BasicBlock *>(BasicBlock *)> split_fn) {
        std::vector<BasicBlock *> result;
        for (auto b : blocks) {
            auto b_list = split_fn(b);
            for (auto bb : b_list) {
                result.push_back(bb);
            }
        }
        return result;
    }

    PASS_IMPL(P4SplitAction, s) {
        // split each basic block into smaller blocks with no dependency
        std::unordered_map<std::string, std::shared_ptr<BasicBlock>> new_blks;
        for (auto &kv : s->blocks) {
            auto blk = kv.second;
            auto blocks = blk->split_to_parallel_blks();
            assert(blocks.size() > 0);
            blocks = split_blocks(blocks, split_data_structure_op);
            blocks = split_blocks(blocks, split_logical_op);
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
                std::shared_ptr<BasicBlock> ptr(b);
                new_blks.insert({ptr->get_name(), ptr});
            }
        }
        s->blocks = new_blks;
        
        return P4UpdateMeta::apply_pass(std::move(s));
    }

    PASS_IMPL(P4AssignMeta, s) {
        // give each register a p4 value
        for (auto &kv : s->blocks) {
            auto blk = kv.second;
            auto &insts = blk->insts_mut();
            for (int i = 0; i < insts.size(); i++) {
                auto inst = insts[i];
                InstID id{kv.first, i};
                auto reg_name = inst->get_dst_reg();
                if (reg_name != "") {
                    /* a register is either a metadata field or a header field
                     * by default, we assign a metadata field.
                     * But if a header field is not modified before the last use of this register,
                     * we could use header field directly
                     */
                    llvm::Type *reg_type = nullptr;
                    int num_bits = 0;
                    if (inst->llvm_type_ != nullptr) {
                        reg_type = inst->llvm_type_;
                    } else if (inst->is_arith_inst()) {
                        auto arith = std::dynamic_pointer_cast<ArithInst>(inst);
                        auto op = arith->op();
                        if (ArithInst::is_cmp(op)) {
                            num_bits = 1;
                        }
                    }
                    if (reg_type == nullptr && num_bits == 0) {
                        auto llvm_inst_ptr = inst->llvm_inst_ptr_;
                        if (llvm_inst_ptr == nullptr) {
                            inst->print(std::cerr);
                            std::cerr << std::endl;
                        }
                        reg_type = llvm_inst_ptr->getType();
                    }

                    if (num_bits == 0) {
                        auto type_size = get_type_size(s->llvm_module.get(), reg_type);
                        num_bits = type_size * 8;
                    }
                    
                    auto rev_deps = s->inst_rev_dep[id];
                    
                    
                    auto meta_field_name = p4_ident_sanitize((*s->name_gen)("reg" + reg_name));
                    s->metadata_field[meta_field_name] = num_bits;
                    auto p4val = std::make_shared<P4::HeaderRef>("metadata", meta_field_name);
                    s->reg2p4val[reg_name] = p4val;
                    P4::PrintConf conf;
                    conf.metadata_name = "ig_intr_md_for_tm";
                    std::cerr << "reg2meta: " << reg_name << " : " << p4val->str(conf) << std::endl;
                }
            }
        }
        
        return s;
    }

    PASS_IMPL(P4AssignEntry, s) {
        // Find all the data structure op that returns an entry
        // assign metadata space for them.
        for (auto &kv : s->blocks) {
            auto blk = kv.second;
            auto &insts = blk->insts_mut();
            for (auto inst : insts) {
                if (inst->is_data_structure_op()) {
                    auto ptr = std::dynamic_pointer_cast<DataStructureOp>(inst);
                    auto data_type = ptr->data_structure_type();
                    auto obj_reg = ptr->obj_reg();
                    auto op = ptr->get_op();
                }
            }
        }
        return s;
    }

    PASS_IMPL(P4CodeGen, s) {
        using namespace P4;
        Prog prog = Common::default_l4_prog_template();

        // first generate table definition

        for (auto &kv : s->tables) {
            auto tab_name = kv.first;
            // generate metadata entry for key and value
            std::vector<Table::ReadEntry> reads;
            for (int i = 0; i < kv.second.key_fields.size(); i++) {
                auto field = kv.second.key_fields[i];
                reads.push_back({std::make_shared<HeaderRef>("metadata", field), Table::MatchType::EXACT});
            }
            
            // add two action, hit and miss
            std::vector<std::string> hit_args;
            std::vector<std::shared_ptr<Stmt>> hit_body;
            std::vector<std::shared_ptr<Stmt>> miss_body;
            auto hit_action = std::make_shared<Action>(tab_name + "_hit", hit_args, hit_body);
            auto miss_action = std::make_shared<Action>(tab_name + "_miss", std::vector<std::string>{},
                                                        miss_body);
            auto tab = std::make_shared<Table>(tab_name,
                                               reads,
                                               std::vector<std::shared_ptr<Action>>{hit_action, miss_action},
                                               65536);
            prog.add_table(tab);
        }

        // now start generating code
        // first do a topological sort
        auto order = topo_sort(*s);

        std::vector<std::shared_ptr<Stmt>> main_stmts;
        auto &name_gen = *s->name_gen;
        // then generate basic blocks using that order
        for (auto &blk_name : order) {
            auto blk = s->blocks[blk_name];
            // each basic block is translated into an action
            // except for data structure op
            auto &insts = blk->insts_mut();
            if (insts.size() == 1
                && insts[0]->is_data_structure_op()) {
                // emit a seperate "apply" stmt
                // TODO: impl this, now it is just a place holder
                auto ptr = std::dynamic_pointer_cast<DataStructureOp>(insts[0]);
                auto tmp_tab_name = p4_ident_sanitize("tab_" + ptr->obj_reg());
                main_stmts.push_back(std::make_shared<Apply>(tmp_tab_name));
            } else if (insts.size() == 1
                  && is_logical_op(insts[0])) {
                main_stmts.push_back(std::make_shared<UntranslatedStmt>("Some logical op"));
            } else {
                std::vector<std::shared_ptr<Stmt>> stmts;
                P4GenVisitor visitor(*s, stmts);
                for (int i = 0; i < insts.size(); i++) {
                    auto inst = insts[i];
                    visitor.visit(*inst);
                }
                // create action block from stmts
                auto act = std::make_shared<Action>(p4_ident_sanitize(name_gen("bb_act")),
                                                    std::vector<std::string>{""},
                                                    stmts);
                // now create temperary table for this action
                std::vector<P4::Table::ReadEntry> reads = {
                    {std::make_shared<P4::HeaderRef>("ipv4", "srcAddr"),
                     P4::Table::MatchType::EXACT},
                };
                auto tmp_tab_name = p4_ident_sanitize(name_gen("bb_tab"));
                auto tmp_tab = std::make_shared<Table>(tmp_tab_name,
                                                       reads,
                                                       std::vector<std::shared_ptr<Action>>{act},
                                                       2, act);
                prog.add_table(tmp_tab);
                main_stmts.push_back(std::make_shared<Apply>(tmp_tab_name));
            }
        }
        prog.set_ingress(std::make_shared<Control>("ingress", main_stmts));
        auto result = std::make_unique<P4Source>(prog);
        return result;
    }
}
    
bool operator==(const Morula::P4TableInfo &lhs, const Morula::P4TableInfo &rhs) {
    using namespace Morula;

    auto p4_entry_eq = [](const P4Entry &l, const P4Entry &r) -> bool {
        if (l.size() != r.size()) {
            return false;
        }
        for (int i = 0; i < l.size(); i++) {
            if (l[i] != r[i]) {
                return false;
            }
        }
        return true;
    };

    return p4_entry_eq(lhs.key_info, rhs.key_info)
        && p4_entry_eq(rhs.val_info, rhs.val_info);
}
