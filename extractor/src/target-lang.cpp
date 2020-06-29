#include "target-lang.hpp"
#include "utils.hpp"
#include <algorithm>
#include <memory>
#include <queue>
#include <sstream>
#include <unordered_set>
#include "llvm-incl.hpp"

static int64_t get_int_val(const llvm::Value *value) {
    if (const llvm::ConstantInt* CI = llvm::dyn_cast<llvm::ConstantInt>(value)) {
        if (CI->getBitWidth() <= 64) {
            return CI->getSExtValue();
        }
    }
    assert(false && "not an integer constant");
    throw "not an integer constant";
}

namespace Target {

    Instruction::Instruction(const std::string &dst): dst_reg_(dst),
                                                      placement_("cpu"),
                                                      llvm_inst_ptr_(nullptr) {}

    Instruction::~Instruction() {}

    TransitInst::TransitInst(): Instruction("") {}

    LLVMInst::LLVMInst(const llvm::Instruction &inst): Instruction(""),
                                                       inst_(const_cast<llvm::Instruction *>(&inst)) {
        auto dst_reg = get_llvm_name(*inst_);
        if (dst_reg == "<badref>") {
            // magic name that indicates this instruction does not have dst reg
            dst_reg_ = "";
        } else {
            dst_reg_ = dst_reg;
        }
    }

    void LLVMInst::print(std::ostream &os) const {
        os << "(llvm-inst ";
        std::string res;
        llvm::raw_string_ostream stream{res};
        inst_->print(stream);
        stream.str();
        os << res << ")";
    }

    ArithInst::ArithInst(const std::string &dst, Op op,
                         const std::vector<std::string> &oprands): Instruction(dst),
                                                                   op_(op),
                                                                   oprands_(oprands) {}

    bool ArithInst::is_cmp(Op op) {
        switch (op) {
        case Op::ARSH:
        case Op::LRSH:
        case Op::LSH:
        case Op::EQ:
        case Op::NE:
        case Op::SLT:
        case Op::ULT:
        case Op::SLE:
        case Op::ULE:
        case Op::SGT:
        case Op::UGT:
        case Op::SGE:
        case Op::UGE:
            return true;
        default:
            return false;
        }
        return false;
    }

    static std::string get_op_str(ArithInst::Op op) {
        using Op = ArithInst::Op;
        switch (op) {
        case Op::CONST_VAL:
            return "const";
        case Op::ADD:
            return "add";
        case Op::SUB:
            return "sub";
        case Op::MUL:
            return "mul";
        case Op::DIV:
            return "div";
        case Op::MOD:
            return "mod";
        case Op::ARSH:
            return "arsh";
        case Op::LRSH:
            return "lrsh";
        case Op::LSH:
            return "lsh";
        case Op::EQ:
            return "eq";
        case Op::NE:
            return "ne";
        case Op::ULT:
            return "ult";
        case Op::ULE:
            return "ule";
        case Op::UGT:
            return "ugt";
        case Op::UGE:
            return "uge";
        case Op::SLT:
            return "slt";
        case Op::SLE:
            return "sle";
        case Op::SGT:
            return "sgt";
        case Op::SGE:
            return "sge";
        case Op::AND:
            return "and";
        case Op::OR:
            return "or";
        case Op::XOR:
            return "xor";
        case Op::NOT:
            return "not";
        case Op::LAND:
            return "land";
        case Op::LOR:
            return "lor";
        case Op::LNOT:
            return "lnot";
        default:
            throw "unknown op";
        }
    }

    std::string ArithInst::op_str() const {
        return get_op_str(op_);
    }

    void ArithInst::print(std::ostream &os) const {
        auto op_str = get_op_str(op_);
        os << "(" << op_str << " " << dst_reg_;
        for (auto &arg : oprands_) {
            os << " " << arg;
        }
        os << ")";
    }

    BranchInst::BranchInst(const std::string &reg, const std::string &target): Instruction(""),
                                                                               cond_reg_(reg),
                                                                               target_bb_(target) {
    }

    void BranchInst::print(std::ostream &os) const {
        os << "(jmp-if " << cond_reg_ << " " << target_bb_ << ")";
    }

    HeaderReadInst::HeaderReadInst(const std::string &dst, const std::string &pkt_name,
                                   const std::string &header_name, const std::string &field_name):
        Instruction(dst),
        pkt_name_(pkt_name),
        header_name_(header_name),
        field_name_(field_name) {
    }

    void HeaderReadInst::print(std::ostream &os) const {
        os << "(header-read " << dst_reg_ << " "
           << pkt_name_ << " "
           << header_name_ << " "
           << field_name_ << ")";
    }

    HeaderWriteInst::HeaderWriteInst(const std::string &pkt_name, const std::string &header_name,
                                     const std::string &field_name, const std::string &val_reg):
        Instruction(""),
        pkt_name_(pkt_name),
        header_name_(header_name),
        field_name_(field_name),
        val_reg_(val_reg) {
    }

    void HeaderWriteInst::print(std::ostream &os) const {
        os << "(header-write " << pkt_name_ << " "
           << header_name_ << " "
           << field_name_ << " "
           << val_reg_ << ")";
    }

    DataStructureOp::DataStructureOp(const std::string &type,
                                     const std::string &op,
                                     const std::string &obj,
                                     const std::string &dst,
                                     const std::vector<std::string> &args): Instruction(dst),
                                                                            type_(type),
                                                                            op_(op),
                                                                            obj_(obj),
                                                                            args_(args) {}

    void DataStructureOp::print(std::ostream &os) const {
        os << "(data-structure-op " << type_ << " "
           << op_ << " " << obj_;
        for (auto &arg : args_) {
            os << " " << arg;
        }
        os << " -> " << this->get_dst_reg() << ")";
    }

    MapGetInst::MapGetInst(const std::string &dst_reg, const std::string &map_reg,
                           const std::string &key_reg, const std::string &val_reg): Instruction(dst_reg),
                                                                                    map_reg_(map_reg),
                                                                                    key_reg_(key_reg),
                                                                                    val_reg_(val_reg) {
    }

    void MapGetInst::print(std::ostream &os) const {
        os << "(map-get " << dst_reg_ << " "
           << map_reg_ << " " << key_reg_ << " " <<  val_reg_ << ")";
    }

    EntryReadInst::EntryReadInst(const std::string &dst,
                                 const std::string &entry_reg,
                                 int field_idx): Instruction(dst),
                                                 entry_reg_(entry_reg),
                                                 field_idx_(field_idx) {}
    
    void EntryReadInst::print(std::ostream &os) const {
        os << "(entry-read " << this->get_dst_reg() << " "
           << entry_reg_ << " " << field_idx_ << ")";
    }

    EntryWriteInst::EntryWriteInst(const std::string &entry_reg,
                                   int field_idx,
                                   const std::string &val_reg): Instruction(""),
                                                                entry_reg_(entry_reg),
                                                                field_idx_(field_idx),
                                                                val_reg_(val_reg) {}
                                                                
    void EntryWriteInst::print(std::ostream &os) const {
        os << "(entry-write " << entry_reg_ << " " << field_idx_ << val_reg_ << ")";
    }

    PhiInst::PhiInst(const std::string &dst, const std::unordered_map<std::string, std::string> &vals):
        Instruction(dst),
        vals_(vals) {
    }

    void PhiInst::print(std::ostream &os) const {
        os << "(phi " << dst_reg_;
        for (auto iter = vals_.begin(); iter != vals_.end(); iter++) {
            os << " " << iter->first << " " << iter->second;
        }
        os << ")";
    }

    CallInst::CallInst(const std::string &dst_reg, const std::string &func_name,
                       const std::vector<std::string> &arg_regs): Instruction(dst_reg),
                                                                  func_(func_name),
                                                                  args_(arg_regs) {
    }

    void CallInst::print(std::ostream &os) const {
        if (dst_reg_ != "") {
            os << "(func-call";
            os << " " << dst_reg_;
        } else {
            os << "(proc-call";
        }

        os << " " << func_;
        for (auto iter = args_.begin(); iter != args_.end(); iter++) {
            os << " " << *iter;
        }
        os << ")";
    }

    ReturnInst::ReturnInst(const std::string &val): Instruction(""),
                                                    ret_reg_(val) {
    }

    void ReturnInst::print(std::ostream &os) const {
        os << "(return";
        if (ret_reg_ != "") {
            os << " " << ret_reg_;
        }
        os << ")";
    }

    EmitPktInst::EmitPktInst(const std::string &pkt_reg,
                             const std::string &port_reg): Instruction(""),
                                                           pkt_reg_(pkt_reg),
                                                           port_reg_(port_reg) {
    }
    
    void EmitPktInst::print(std::ostream &os) const {
        os << "(emit-pkt "
           << " " << pkt_reg_
           << " " << port_reg_
           << ")";
    }

    AllocaInst::AllocaInst(const std::string &dst, 
                           const std::string &type_name, 
                           int size): Instruction(dst),
                                      type_(type_name),
                                      n_elements_(size) {
    }

    bool AllocaInst::is_alloca() const {
        return true;
    }


    void AllocaInst::print(std::ostream &os) const {
        os << "(alloca " << dst_reg_ << " " << type_
           << " " << n_elements_ << ")";
    }
    

    UnknownInst::UnknownInst(const std::string &desc): Instruction(""),
                                                       description_(desc) {}

    void UnknownInst::print(std::ostream &os) const {
        os << "(unknown " << description_ << ")";
    }

    BasicBlock::BasicBlock(const std::string &name, InstList &&insts):
        name_(name),
        insts_(std::move(insts)),
        branch_cond_(""),
        t_bb_(""),
        f_bb_("") {
    }

    BasicBlock::BasicBlock(const std::string &name, const InstList &insts):
        name_(name),
        insts_(std::move(insts)),
        branch_cond_(""),
        t_bb_(""),
        f_bb_("") {
    }

    void BasicBlock::add_branch(const std::string &cond_var,
                                const std::string &t_target_bb,
                                const std::string &f_target_bb) {
        branch_cond_ = cond_var;
        t_bb_ = t_target_bb;
        f_bb_ = f_target_bb;
    }

    void BasicBlock::add_next(const std::string next_bb) {
        branch_cond_ = "";
        t_bb_ = next_bb;
        f_bb_ = "";
    }

    bool BasicBlock::is_conditional() const {
        return branch_cond_ != "";
    }

    std::vector<BasicBlock *> BasicBlock::split_to_parallel_blks() const {
        // 1 : create read_set and write_set
        std::cout << "start splitting....." << std::endl;
        auto num_inst = insts_.size();
        std::vector<WriteSet> write_set(num_inst);
        std::vector<InstDeps> deps(num_inst);
        for (int i = 0; i < num_inst; i++) {
            get_deps(*insts_[i], deps[i]);
            get_write_set(*insts_[i], write_set[i]);
        }

        // 2 : find all the "happen-before" within the block
        std::vector<std::unordered_set<int>> happen_before(num_inst);
        for (int i = 0; i < num_inst; i++) {
            for (int j = i - 1; j >= 0; j--) {
                /* test if insts_[j] must be executed before insts_[i]
                 * (check if some element in insts_[i]'s read set is
                 *  in insts[j]'s write set)
                 */
                auto &ws = write_set[j];
                auto &rs = deps[i];
                auto &my_ws = write_set[i];

                bool have_dependency = false;

                // first check read-after-write dependency
                
                // check registers
                for (auto reg : rs.reg_dep) {
                    auto iter = std::find(ws.regs.begin(), ws.regs.end(), reg);
                    if (iter != ws.regs.end()) {
                        have_dependency = true;
                        break;
                    }
                }

                // check states
                if (!have_dependency) {
                    for (auto s : rs.state_dep) {
                        auto iter = std::find(ws.states.begin(), ws.states.end(), s);
                        if (iter != ws.states.end()) {
                            have_dependency = true;
                            break;
                        }
                    }
                }

                // also check write-write dependency
                // check registers
                for (auto reg : my_ws.regs) {
                    auto iter = std::find(ws.regs.begin(), ws.regs.end(), reg);
                    if (iter != ws.regs.end()) {
                        have_dependency = true;
                        break;
                    }
                }

                // check states
                if (!have_dependency) {
                    for (auto s : my_ws.states) {
                        auto iter = std::find(ws.states.begin(), ws.states.end(), s);
                        if (iter != ws.states.end()) {
                            have_dependency = true;
                            break;
                        }
                    }
                }

                if (have_dependency) {
                    happen_before[i].insert(j);
                }
            }
        }

        // 3 : traverse the instructions and find a parallel block
        std::vector<bool> visited(num_inst, false);
        int num_visited = 0;
        std::vector<BasicBlock *> result;

        while (num_visited != num_inst) {
            std::string blk_name = name_ + "b" + std::to_string(result.size());
            std::vector<int> inst_idx;
            for (int i = 0; i < num_inst; i++) {
                if (visited[i]) {
                    continue;
                }

                bool can_add_to_blk = true;
                for (auto idx : happen_before[i]) {
                    if (!visited[idx]) {
                        can_add_to_blk = false;
                        break;
                    }
                }

                if (can_add_to_blk) {
                    inst_idx.push_back(i);
                }
            }

            if (inst_idx.size() == 0 && num_visited != num_inst) {
                assert(false && "Oops: can not proceed block splitting");
            }
            
            BasicBlock::InstList blk_insts;
            for (auto idx : inst_idx) {
                blk_insts.push_back(insts_[idx]);
                visited[idx] = true;
                num_visited++;
            }

            auto new_blk = new BasicBlock(blk_name, blk_insts);
            result.push_back(new_blk);
            std::cout << "one splitted block pushed" << std::endl;
        }

        if (result.size() == 0) {
            assert(num_inst == 0);
            auto new_blk = new BasicBlock(*this);
            result.push_back(new_blk);
        }
        
        return result;
    }

    void InstVisitor::visit(Instruction &inst) {
        inst.call_visitor(*this);
    }

    void InstVisitor::visit_inst(Instruction &inst) {
    }
    
    void InstVisitor::visit_inst(LLVMInst &inst) {
        this->visit_inst(dynamic_cast<Instruction &>(inst));
    }
    
    void InstVisitor::visit_inst(ArithInst &inst) {
        this->visit_inst(dynamic_cast<Instruction &>(inst));
    }
    
    void InstVisitor::visit_inst(BranchInst &inst) {
        this->visit_inst(dynamic_cast<Instruction &>(inst));
    }
    
    void InstVisitor::visit_inst(HeaderReadInst &inst) {
        this->visit_inst(dynamic_cast<Instruction &>(inst));
    }
    
    void InstVisitor::visit_inst(HeaderWriteInst &inst) {
        this->visit_inst(dynamic_cast<Instruction &>(inst));
    }
    
    void InstVisitor::visit_inst(MapGetInst &inst) {
        this->visit_inst(dynamic_cast<Instruction &>(inst));
    }

    void InstVisitor::visit_inst(DataStructureOp &inst) {
        this->visit_inst(dynamic_cast<Instruction &>(inst));
    }

    void InstVisitor::visit_inst(EntryReadInst &inst) {
        this->visit_inst(dynamic_cast<Instruction &>(inst));
    }

    void InstVisitor::visit_inst(EntryWriteInst &inst) {
        this->visit_inst(dynamic_cast<Instruction &>(inst));
    }
    
    void InstVisitor::visit_inst(AllocaInst &inst) {
        this->visit_inst(dynamic_cast<Instruction &>(inst));
    }
    
    void InstVisitor::visit_inst(PhiInst &inst) {
        this->visit_inst(dynamic_cast<Instruction &>(inst));
    }
    
    void InstVisitor::visit_inst(CallInst &inst) {
        this->visit_inst(dynamic_cast<Instruction &>(inst));
    }
    
    void InstVisitor::visit_inst(ReturnInst &inst) {
        this->visit_inst(dynamic_cast<Instruction &>(inst));
    }

    void InstVisitor::visit_inst(EmitPktInst &inst) {
        this->visit_inst(dynamic_cast<Instruction &>(inst));
    }
    
    void InstVisitor::visit_inst(UnknownInst &inst) {
        this->visit_inst(dynamic_cast<Instruction &>(inst));
    }

    void InstVisitor::visit_inst(TransitInst &inst) {
        this->visit_inst(dynamic_cast<Instruction &>(inst));
    }

    void ConstInstVisitor::visit(const Instruction &inst) {
        inst.call_const_visitor(*this);
    }

    void ConstInstVisitor::visit_inst(const Instruction &inst) {
    }
    
    void ConstInstVisitor::visit_inst(const LLVMInst &inst) {
        this->visit_inst(dynamic_cast<const Instruction &>(inst));
    }
    
    void ConstInstVisitor::visit_inst(const ArithInst &inst) {
        this->visit_inst(dynamic_cast<const Instruction &>(inst));
    }
    
    void ConstInstVisitor::visit_inst(const BranchInst &inst) {
        this->visit_inst(dynamic_cast<const Instruction &>(inst));
    }
    
    void ConstInstVisitor::visit_inst(const HeaderReadInst &inst) {
        this->visit_inst(dynamic_cast<const Instruction &>(inst));
    }
    
    void ConstInstVisitor::visit_inst(const HeaderWriteInst &inst) {
        this->visit_inst(dynamic_cast<const Instruction &>(inst));
    }
    
    void ConstInstVisitor::visit_inst(const MapGetInst &inst) {
        this->visit_inst(dynamic_cast<const Instruction &>(inst));
    }

    void ConstInstVisitor::visit_inst(const DataStructureOp &inst) {
        this->visit_inst(dynamic_cast<const Instruction &>(inst));
    }

    void ConstInstVisitor::visit_inst(const EntryReadInst &inst) {
        this->visit_inst(dynamic_cast<const Instruction &>(inst));
    }

    void ConstInstVisitor::visit_inst(const EntryWriteInst &inst) {
        this->visit_inst(dynamic_cast<const Instruction &>(inst));
    }
    
    void ConstInstVisitor::visit_inst(const AllocaInst &inst) {
        this->visit_inst(dynamic_cast<const Instruction &>(inst));
    }
    
    void ConstInstVisitor::visit_inst(const PhiInst &inst) {
        this->visit_inst(dynamic_cast<const Instruction &>(inst));
    }
    
    void ConstInstVisitor::visit_inst(const CallInst &inst) {
        this->visit_inst(dynamic_cast<const Instruction &>(inst));
    }
    
    void ConstInstVisitor::visit_inst(const ReturnInst &inst) {
        this->visit_inst(dynamic_cast<const Instruction &>(inst));
    }

    void ConstInstVisitor::visit_inst(const EmitPktInst &inst) {
        this->visit_inst(dynamic_cast<const Instruction &>(inst));
    }
    
    void ConstInstVisitor::visit_inst(const UnknownInst &inst) {
        this->visit_inst(dynamic_cast<const Instruction &>(inst));
    }

    void ConstInstVisitor::visit_inst(const TransitInst &inst) {
        this->visit_inst(dynamic_cast<const Instruction &>(inst));
    }

    class PlaceLLVMVisitor : public llvm::InstVisitor<PlaceLLVMVisitor> {
    public:
        PlaceReqSet &req_set;
        const std::unordered_map<std::string, InstID> &dst_map;
        InstID id;
        PlaceLLVMVisitor(PlaceReqSet &r, const InstID &_id,
                         const std::unordered_map<std::string, InstID> &d_m): req_set(r), id(_id), dst_map(d_m) {}

        void visitInstruction(const llvm::Instruction &inst) {
            PlaceReq req("cpu");
            req_set.inst_reqs.insert({id, req});
        }

        void visitGetElementPtrInst(const llvm::GetElementPtrInst &inst) {
            auto base_ptr = get_llvm_name(*inst.getOperand(0));
            // perform a walk through for the offset, only allow register or constant as offset
            // if base_ptr is on p4 and offset is zero, we allow the resulting ptr to be on p4
            auto offset = 0;
            bool constant_off = true;
            for (int i = 1; i < inst.getNumOperands(); i++) {
                auto v = inst.getOperand(i);
                int o = 0;
                if (const llvm::ConstantInt* CI = llvm::dyn_cast<llvm::ConstantInt>(v)) {
                    offset += get_int_val(v);
                } else {
                    constant_off = false;
                }
            }

            if (constant_off && offset == 0) {
                PlaceReq req("p4");
                req.inst_pre_req.push_back(dst_map.find(base_ptr)->second);
                req_set.inst_reqs.insert({id, req});
            } else {
                PlaceReq req("cpu");
                req_set.inst_reqs.insert({id, req});
            }
        }

        void visitICmpInst(const llvm::ICmpInst &inst) {
            /* 
             * the assumption is that all integer comparation are supported in p4
             * if all the oprands can be placed in p4
             */
            PlaceReq req("p4");
            auto a1 = get_llvm_name(*inst.getOperand(0));
            auto a2 = get_llvm_name(*inst.getOperand(1));
            if (!is_llvm_constant(*inst.getOperand(0))) {
                assert(dst_map.find(a1) != dst_map.end());
                req.inst_pre_req.push_back(dst_map.find(a1)->second);
            }

            if (!is_llvm_constant(*inst.getOperand(1))) {
                assert(dst_map.find(a2) != dst_map.end());
                req.inst_pre_req.push_back(dst_map.find(a2)->second);
            }
            req.next = std::make_shared<PlaceReq>("cpu");
            req_set.inst_reqs.insert({id, req});
        }

        void visitBinaryOperator(const llvm::BinaryOperator &inst) {
            PlaceReq req("p4");
            auto a1 = get_llvm_name(*inst.getOperand(0));
            auto a2 = get_llvm_name(*inst.getOperand(1));
            if (!is_llvm_constant(*inst.getOperand(0))) {
                assert(dst_map.find(a1) != dst_map.end());
                req.inst_pre_req.push_back(dst_map.find(a1)->second);
            }

            if (!is_llvm_constant(*inst.getOperand(1))) {
                assert(dst_map.find(a2) != dst_map.end());
                req.inst_pre_req.push_back(dst_map.find(a2)->second);
            }

            std::string opstring = inst.getOpcodeName();

            // now check if the opcode can be supported by p4
            static const std::unordered_set<std::string> p4_compat_ops = {
                "add",
                "sub",
                "and",
                "or",
                "xor"
                "shl",
                "lshr",
                "ashr",
            };

            if (p4_compat_ops.find(opstring) != p4_compat_ops.end()) {
                req.next = std::make_shared<PlaceReq>("cpu");
                req_set.inst_reqs.insert({id, req});
            } else {
                PlaceReq req("cpu");
                req_set.inst_reqs.insert({id, req});
            }
        }
    };

    class PlaceReqVisitor : public InstVisitor {
    public:
        PlaceReqSet &req_set;
        const std::unordered_map<std::string, InstID> &dst_map;
        InstID id;
        PlaceReqVisitor(PlaceReqSet &r, const InstID &_id,
                        const std::unordered_map<std::string, InstID> &d_m): req_set(r), id(_id), dst_map(d_m) {}

        virtual void visit_inst(Instruction &inst) {
        }

        virtual void visit_inst(LLVMInst &inst) {
            auto llvm = inst.get_inst();
            PlaceLLVMVisitor visitor(req_set, id, dst_map);
            visitor.visit(*llvm);
        }

        virtual void visit_inst(PhiInst &phi) {
            const auto &vals = phi.vals();
            PlaceReq req("p4");
            for (auto iter = vals.begin(); iter != vals.end(); iter++) {
                auto r = iter->second;
                assert(dst_map.find(r) != dst_map.end());
                auto r_id = dst_map.find(r)->second;
                req.inst_pre_req.push_back(r_id);
            }
            req.next = std::make_shared<PlaceReq>("cpu");
            req_set.inst_reqs.insert({id, req});
        }

        virtual void visit_inst(BranchInst &inst) {}

        virtual void visit_inst(HeaderReadInst &inst) {
            PlaceReq req("p4");
            req_set.inst_reqs.insert({id, req});
        }
        
        virtual void visit_inst(HeaderWriteInst &inst) {
            PlaceReq req("p4");
            req_set.inst_reqs.insert({id, req});
        }
        
        virtual void visit_inst(MapGetInst &inst) {
            PlaceReq req("p4");
            auto r = inst.map_reg();
            assert(dst_map.find(r) != dst_map.end());
            auto r_id = dst_map.find(r)->second;
            req.inst_pre_req.push_back(r_id);
            req.next = std::make_shared<PlaceReq>("cpu");
            req_set.inst_reqs.insert({id, req});
        }
        
        virtual void visit_inst(AllocaInst &inst) {
            PlaceReq req("p4");
            req_set.inst_reqs.insert({id, req});
        }
        
        virtual void visit_inst(CallInst &inst) {
            static const std::unordered_set<std::string> p4_compat_funcs = {
                "HashMap::findp const",
                "WritablePacket::ip_header() const",
                "Packet::transport_header() const",
                "Packet::has_network_header() const",
                "Packet::uniqueify()",
                "Packet::transport_length() const",
                "Vector::begin()",
                "Vector::end()",
                "IPAddress* find"
            };
            auto fn = inst.func_name();
            std::string func_name;
            auto demangled = cxx_demangle(fn, func_name);
            bool can_be_p4 = false;
            if (demangled) {
                func_name = remove_template(func_name);
                auto no_arg_ver = remove_func_args(func_name);
                if (p4_compat_funcs.find(no_arg_ver) != p4_compat_funcs.end()) {
                    can_be_p4 = true;
                }
            } else {
                func_name = fn;
            }

            if (p4_compat_funcs.find(func_name) != p4_compat_funcs.end()) {
                can_be_p4 = true;
            }

            if (can_be_p4) {
                PlaceReq req("p4");
                const auto &args = inst.args();
                for (auto &a : args) {
                    if (dst_map.find(a) != dst_map.end()) {
                        req.inst_pre_req.push_back(dst_map.find(a)->second);
                        // std::cerr << "dep of ";
                        // inst.print(std::cerr);
                        // std::cerr << " " << a << std::endl;
                    }
                }
                req.next = std::make_shared<PlaceReq>("cpu");
                req_set.inst_reqs.insert({id, req});
            } else {
                PlaceReq req("cpu");
                req_set.inst_reqs.insert({id, req});
            }
        }
        
        virtual void visit_inst(ReturnInst &inst) {
            PlaceReq req("cpu");
            req_set.inst_reqs.insert({id, req});
        }

        virtual void visit_inst(EmitPktInst &inst) {
            
        }
        
        virtual void visit_inst(UnknownInst &inst) {
            assert(false && "visiting unknown instruction");
        }
    };

    void add_place_req(Instruction *inst, const InstID &id, PlaceReqSet &req_set,
                       const std::unordered_map<std::string, InstID> &dst_map) {
        PlaceReqVisitor visitor(req_set, id, dst_map);
        visitor.visit(*inst);
    }

    class DepLLVMVisitor : public llvm::InstVisitor<DepLLVMVisitor> {
    public:
        InstDeps &deps;

        DepLLVMVisitor(InstDeps &deps_): deps(deps_) {}

        void visitInstruction(const llvm::Instruction &inst) {
        }

        void visitLoadInst(const llvm::LoadInst &inst) {
            auto ptr_name = get_llvm_name(*inst.getOperand(0));
            deps.reg_dep.push_back(ptr_name);
        }

        void visitStoreInst(const llvm::StoreInst &inst) {
            auto ptr_name = get_llvm_name(*inst.getOperand(1));
            deps.reg_dep.push_back(ptr_name);
            auto val_name = get_llvm_name(*inst.getOperand(0));
            deps.reg_dep.push_back(val_name);
        }

        void visitGetElementPtrInst(const llvm::GetElementPtrInst &inst) {
            deps.moveable = true;
            auto base_ptr = get_llvm_name(*inst.getOperand(0));
            deps.reg_dep.push_back(base_ptr);
        }

        void visitICmpInst(const llvm::ICmpInst &inst) {
            deps.moveable = true;
            auto a1 = get_llvm_name(*inst.getOperand(0));
            auto a2 = get_llvm_name(*inst.getOperand(1));
            if (!is_llvm_constant(*inst.getOperand(0))) {
                deps.reg_dep.push_back(a1);
            }

            if (!is_llvm_constant(*inst.getOperand(1))) {
                deps.reg_dep.push_back(a2);
            }
        }

        void visitBinaryOperator(const llvm::BinaryOperator &inst) {
            deps.moveable = true;
            auto a1 = get_llvm_name(*inst.getOperand(0));
            auto a2 = get_llvm_name(*inst.getOperand(1));
            if (!is_llvm_constant(*inst.getOperand(0))) {
                deps.reg_dep.push_back(a1);
            }

            if (!is_llvm_constant(*inst.getOperand(1))) {
                deps.reg_dep.push_back(a2);
            }
        }

        void visitBitCastInst(const llvm::BitCastInst &inst) {
            deps.moveable = true;
            auto ptr = get_llvm_name(*inst.getOperand(0));
            if (!is_llvm_constant(*inst.getOperand(0))) {
                deps.reg_dep.push_back(ptr);
            }
        }
    };

    class DepVisitor : public ConstInstVisitor {
    public:
        InstDeps &deps;

        DepVisitor(InstDeps &deps_): deps(deps_) {}

        void visit_inst(const Instruction &inst) {
        }
        
        void visit_inst(const LLVMInst &inst) {
            auto llvm = inst.get_inst();
            DepLLVMVisitor v(deps);
            v.visit(*llvm);
        }
        
        void visit_inst(const ArithInst &inst) {
            const auto &oprands = inst.oprands();
            for (auto &reg : oprands) {
                deps.reg_dep.push_back(reg);
            }
            deps.moveable = true;
        }
        
        void visit_inst(const BranchInst &inst) {
            
        }
        
        void visit_inst(const HeaderReadInst &inst) {
            deps.moveable = true;
            //deps.reg_dep.push_back(inst.pkt_name());
            std::string header_field_str = inst.header_name() + "." + inst.field_name();
            deps.state_dep.push_back(inst.pkt_name() + "->" + header_field_str);
            
        }
        
        void visit_inst(const HeaderWriteInst &inst) {
            deps.moveable = true;
            //deps.reg_dep.push_back(inst.pkt_name());
            //deps.state_dep.push_back(inst.pkt_name());
            deps.reg_dep.push_back(inst.val_reg());
        }

        void visit_inst(const DataStructureOp &inst) {
            auto ds_type = inst.data_structure_type();
            auto op = inst.get_op();
            auto obj = inst.obj_reg();
            const auto &args = inst.args();
            deps.reg_dep.push_back(obj);
            if (ds_type == "map") {
                if (op == "findp") {
                    deps.reg_dep.push_back(args[0]);
                }
            } else if (ds_type == "vector") {
                if (op == "operator[]") {
                    deps.reg_dep.push_back(args[0]);
                }
            }
        }

        void visit_inst(const EntryReadInst &inst) {
            deps.moveable = true;
            deps.reg_dep.push_back(inst.entry_reg());
        }

        void visit_inst(const EntryWriteInst &inst) {
            deps.moveable = true;
            deps.reg_dep.push_back(inst.val_reg());
        }
        
        void visit_inst(const MapGetInst &inst) {
            deps.moveable = true;
            deps.reg_dep.push_back(inst.map_reg());
            deps.reg_dep.push_back(inst.key_reg());
        }

        void visit_inst(const EmitPktInst &inst) {
            deps.moveable = true;
            deps.state_dep.push_back(inst.pkt_name());
            deps.reg_dep.push_back(inst.port_reg());
        }
        
        void visit_inst(const AllocaInst &inst) {
            deps.moveable = true;
        }
        
        void visit_inst(const PhiInst &inst) {
            deps.moveable = true;
            const auto &vals = inst.vals();
            for (auto &kv : vals) {
                deps.reg_dep.push_back(kv.second);
            }
        }
        
        void visit_inst(const CallInst &inst) {
            deps.moveable = true;
            const auto &args = inst.args();
            for (auto &a : args) {
                deps.reg_dep.push_back(a);
            }
        }
        
        void visit_inst(const ReturnInst &inst) {
        }
        
        void visit_inst(const UnknownInst &inst) {
        }
    };

    void get_deps(const Instruction &inst, InstDeps &deps) {
        deps.moveable = false;
        DepVisitor visitor(deps);
        visitor.visit(inst);
    }

    class SideEffectLLVMVisitor : public llvm::InstVisitor<SideEffectLLVMVisitor> {
    public:
        bool &no_side_effect_;
        SideEffectLLVMVisitor(bool &no_side_effect): no_side_effect_(no_side_effect) {}

        void visitInstruction(const llvm::Instruction &inst) {
            no_side_effect_ = false;
        }

        void visitGetElementPtrInst(const llvm::GetElementPtrInst &inst) {
            no_side_effect_ = true;
        }

        void visitICmpInst(const llvm::ICmpInst &inst) {
            no_side_effect_ = true;
        }

        void visitBinaryOperator(const llvm::BinaryOperator &inst) {
            no_side_effect_ = true;
        }

        void visitBitCastInst(const llvm::BitCastInst &inst) {
            no_side_effect_ = true;
        }
    };

    class SideEffectVisitor : public InstVisitor {
    public:
        bool &no_side_effect_;
        SideEffectVisitor(bool &no_side_effect): no_side_effect_(no_side_effect) {}
        
        void visit_inst(Instruction &inst) {
            no_side_effect_ = false;
        }

        void visit_inst(LLVMInst &inst) {
            SideEffectLLVMVisitor v(no_side_effect_);
            v.visit(*inst.get_inst());
        }

        void visit_inst(ArithInst &inst) {
            no_side_effect_ = true;
        }

        void visit_inst(BranchInst &inst) {
            no_side_effect_ = true;
        }
        
        void visit_inst(HeaderReadInst &inst) {
            no_side_effect_ = true;
        }
        
        void visit_inst(MapGetInst &inst) {
            no_side_effect_ = true;
        }

        void visit_inst(CallInst &inst) {
            std::unordered_set<std::string> funcs = {
                "HashMap::findp const",
                "WritablePacket::ip_header() const",
                "Packet::transport_header() const",
                "Packet::has_network_header() const",
                "Packet::uniqueify()",
                "Packet::transport_length() const",
            };
            no_side_effect_ = false;

            auto fn = inst.func_name();
            std::string func_name;
            auto demangled = cxx_demangle(fn, func_name);
            if (demangled) {
                func_name = remove_template(func_name);
                auto no_arg_ver = remove_func_args(func_name);
                if (funcs.find(no_arg_ver) != funcs.end()) {
                    no_side_effect_ = true;
                }
            } else {
                func_name = fn;
            }

            if (funcs.find(func_name) != funcs.end()) {
                no_side_effect_ = true;
            }
        }
        
        void visit_inst(AllocaInst &inst) {
            no_side_effect_ = true;
        }
        
        void visit_inst(PhiInst &inst) {
            no_side_effect_ = true;
        }
    };

    bool no_side_effect(Instruction &inst) {
        bool result;
        SideEffectVisitor v(result);
        v.visit(inst);
        return result;
    }

    class WriteSetLLVMVisitor : public llvm::InstVisitor<WriteSetLLVMVisitor> {
    public:
        WriteSet &ws;

        WriteSetLLVMVisitor(WriteSet &ws_) : ws(ws_) {}
        
        void visitInstruction(const llvm::Instruction &inst) {
            
        }

        void visitStoreInst(const llvm::StoreInst &inst) {
            auto dst_name = get_llvm_name(*inst.getOperand(1));
            ws.regs.push_back(dst_name);
        }
    };

    class WriteSetVisitor : public InstVisitor {
    public:
        WriteSet &ws;

        WriteSetVisitor(WriteSet &ws_) : ws(ws_) {}

        void visit_inst(Instruction &inst) {
            if (inst.get_dst_reg() != "") {
                ws.regs.push_back(inst.get_dst_reg());
            }
        }

        void visit_inst(LLVMInst &inst) {
            if (inst.get_dst_reg() != "") {
                ws.regs.push_back(inst.get_dst_reg());
            }
            auto llvm = inst.get_inst();
            WriteSetLLVMVisitor v(ws);
            v.visit(*llvm);
        }

        void visit_inst(MapGetInst &inst) {
            //ws.regs.push_back(inst.val_reg());
        }

        void visit_inst(EntryWriteInst &inst) {
            ws.regs.push_back(inst.entry_reg());
        }

        void visit_inst(HeaderWriteInst &inst) {
            std::string header_field_str = inst.header_name() + "." + inst.field_name();
            ws.states.push_back(inst.pkt_name() + "->" + header_field_str);
        }

        void visit_inst(CallInst &inst) {
            // TODO: fill in this one
            if (inst.get_dst_reg() != "") {
                ws.regs.push_back(inst.get_dst_reg());
            }
            auto fn = inst.func_name();
            std::string func_name;
            auto demangled = cxx_demangle(fn, func_name);
            bool can_be_p4 = false;
            if (demangled) {
                func_name = remove_template(func_name);
                auto no_arg_ver = remove_func_args(func_name);
                func_name = no_arg_ver;
            } else {
                func_name = fn;
            }
            
            if (func_name == "HashMap::insert") {
                ws.states.push_back(inst.args()[0]);
            }
        }
    };

    void get_write_set(Instruction &inst, WriteSet &ws) {
        //TODO
        WriteSetVisitor visitor(ws);
        visitor.visit(inst);
    }

    class PrefixInfoVisitorLLVM : public llvm::InstVisitor<PrefixInfoVisitorLLVM> {
    public:
        PlaceInfo &info;
        PrefixInfoVisitorLLVM(PlaceInfo &info_): info(info_) {}
        void visitInstruction(const llvm::Instruction &inst) {
        }
    };

    class PrefixInfoVisitor : public InstVisitor {
    public:
        PlaceInfo &info;
        const std::unordered_map<std::string, InstID> &dst_map;
        PrefixInfoVisitor(PlaceInfo &info_,
                          const std::unordered_map<std::string, InstID> &dst_map_): info(info_),
                                                                                    dst_map(dst_map_) {}

        void add_reg_to_dep(const std::string &reg_name) {
            if (dst_map.find(reg_name) != dst_map.end()) {
                auto id = dst_map.find(reg_name)->second;
                info.prefix_inst_dep.push_back(id);
            } else {
                // if not found in dst_map, we assume it is a constant
                // TODO: we may need to handle access to global here
            }
        }

        virtual void visit_inst(Instruction &inst) {
        }

        virtual void visit_inst(LLVMInst &inst) {
            auto llvm = inst.get_inst();
            PrefixInfoVisitorLLVM visitor(info);
            visitor.visit(*llvm);
        }

        virtual void visit_inst(PhiInst &phi) {
            const auto &vals = phi.vals();
            info.can_be_prefix = true;
            for (auto iter = vals.begin(); iter != vals.end(); iter++) {
                auto r = iter->second;
                add_reg_to_dep(r);
            }
        }

        virtual void visit_inst(BranchInst &inst) {}

        virtual void visit_inst(HeaderReadInst &inst) {
            info.can_be_prefix = true;
            auto pkt = inst.pkt_name();
            add_reg_to_dep(pkt);
        }
        
        virtual void visit_inst(HeaderWriteInst &inst) {
            info.can_be_prefix = true;
            auto pkt = inst.pkt_name();
            add_reg_to_dep(pkt);
            auto r = inst.val_reg();
            add_reg_to_dep(r);
        }
        
        virtual void visit_inst(MapGetInst &inst) {
            info.can_be_prefix = true;
            auto r = inst.map_reg();
            add_reg_to_dep(r);
        }
        
        virtual void visit_inst(AllocaInst &inst) {
            info.can_be_prefix = true;
        }
        
        virtual void visit_inst(CallInst &inst) {
            static const std::unordered_set<std::string> p4_compat_funcs = {
                "HashMap::findp const",
                "WritablePacket::ip_header() const",
                "Packet::transport_header() const",
                "Packet::uniqueify()",
                "Packet::transport_length() const",
            };
            auto fn = inst.func_name();
            std::string func_name;
            auto demangled = cxx_demangle(fn, func_name);
            bool can_be_p4 = false;
            if (demangled) {
                func_name = remove_template(func_name);
                auto no_arg_ver = remove_func_args(func_name);
                if (p4_compat_funcs.find(no_arg_ver) != p4_compat_funcs.end()) {
                    can_be_p4 = true;
                }
            } else {
                func_name = fn;
            }

            if (p4_compat_funcs.find(func_name) != p4_compat_funcs.end()) {
                can_be_p4 = true;
            }

            if (can_be_p4) {
                info.can_be_prefix = true;
                const auto &args = inst.args();
                for (auto &a : args) {
                    add_reg_to_dep(a);
                }
            }
        }
        
        virtual void visit_inst(ReturnInst &inst) {
            
        }

        virtual void visit_inst(EmitPktInst &inst) {
            
        }
        
        virtual void visit_inst(UnknownInst &inst) {
            assert(false && "visiting unknown instruction");
        }
    };

    class CanBeP4LLVMVisitor : public llvm::InstVisitor<CanBeP4LLVMVisitor> {
    public:
        bool &result;
        CanBeP4LLVMVisitor(bool &b): result(b) {}

        void visitInstruction(const llvm::Instruction &inst) {
            result = false;
        }

        void visitGetElementPtrInst(const llvm::GetElementPtrInst &inst) {
            result = true;
        }

        void visitBinaryOperator(const llvm::BinaryOperator &inst) {
            std::string opstring = inst.getOpcodeName();

            // now check if the opcode can be supported by p4
            static const std::unordered_set<std::string> p4_compat_ops = {
                "add",
                "sub",
                "and",
                "or",
                "xor"
                "shl",
                "lshr",
                "ashr",
            };

            if (p4_compat_ops.find(opstring) != p4_compat_ops.end()) {
                result = true;
            } else {
                result = false;
            }
        }

        void visitICmpInst(const llvm::ICmpInst &inst) {
            result = true;
        }

        void visitBitCastInst(const llvm::BitCastInst &inst) {
            result = false;
        }

        void visitLoadInst(const llvm::LoadInst &inst) {
            result = true;
        }
    };

    class CanBeP4Visitor : public InstVisitor {
    public:
        bool &result;
        CanBeP4Visitor(bool &b): result(b) {}
        
        virtual void visit_inst(Instruction &inst) {
            result = false;
        }

        virtual void visit_inst(LLVMInst &inst) {
            CanBeP4LLVMVisitor visitor(result);
            visitor.visit(*inst.get_inst());
        }

        virtual void visit_inst(ArithInst &inst) {
            static const std::unordered_set<ArithInst::Op> p4_compat_ops = {
                ArithInst::Op::CONST_VAL,
                ArithInst::Op::ADD,
                ArithInst::Op::SUB,
                ArithInst::Op::ARSH,
                ArithInst::Op::LRSH,
                ArithInst::Op::LSH,
                ArithInst::Op::EQ,
                ArithInst::Op::NE,
                ArithInst::Op::SLT,
                ArithInst::Op::ULT,
                ArithInst::Op::SLE,
                ArithInst::Op::ULE,
                ArithInst::Op::SGT,
                ArithInst::Op::UGT,
                ArithInst::Op::SGE,
                ArithInst::Op::UGE,
                ArithInst::Op::AND,
                ArithInst::Op::OR,
                ArithInst::Op::XOR,
                ArithInst::Op::NOT,
                ArithInst::Op::LAND,
                ArithInst::Op::LOR,
                ArithInst::Op::LNOT,
            };
            result = (p4_compat_ops.find(inst.op()) != p4_compat_ops.end());
        }

        virtual void visit_inst(PhiInst &phi) {
            result = true;
        }

        virtual void visit_inst(HeaderReadInst &inst) {
            result = true;
        }

        virtual void visit_inst(HeaderWriteInst &inst) {
            result = true;
        }

        virtual void visit_inst(EntryReadInst &inst) {
            result = true;
        }

        virtual void visit_inst(EntryWriteInst &inst) {
            result = true;
        }

        virtual void visit_inst(DataStructureOp &inst) {
            auto ds_type = inst.data_structure_type();
            auto op = inst.get_op();
            auto obj = inst.obj_reg();
            const auto &args = inst.args();
            result = false;
            if (ds_type == "map") {
                if (op == "findp") {
                    result = true;
                }
            } else if (ds_type == "vector") {
                if (op == "operator[]") {
                    result = true;
                }
            }
        }

        virtual void visit_inst(MapGetInst &inst) {
            result = true;
        }

        virtual void visit_inst(AllocaInst &inst) {
            result = true;
        }

        virtual void visit_inst(EmitPktInst &inst) {
            result = true;
        }

        virtual void visit_inst(CallInst &inst) {
            static const std::unordered_set<std::string> p4_compat_funcs = {
                "HashMap::findp const",
                "Vector::operator[]",
                "WritablePacket::ip_header() const",
                "Packet::transport_header() const",
                "Packet::uniqueify()",
                "Packet::transport_length() const",
                "Packet::has_network_header() const",
                "Vector::begin()",
                "Vector::end()",
                "IPAddress* find",
                "click_in_cksum",
                "Packet::data() const",
                "Packet::data()",
                "click_jiffies()",
                "llvm.bswap.i16",
                "Element::checked_output_push() const"
            };
            auto fn = inst.func_name();
            std::string func_name;
            auto demangled = cxx_demangle(fn, func_name);
            bool can_be_p4 = false;
            if (demangled) {
                func_name = remove_template(func_name);
                auto no_arg_ver = remove_func_args(func_name);
                if (p4_compat_funcs.find(no_arg_ver) != p4_compat_funcs.end()) {
                    can_be_p4 = true;
                }
            } else {
                func_name = fn;
            }

            if (p4_compat_funcs.find(func_name) != p4_compat_funcs.end()) {
                can_be_p4 = true;
            }

            result = can_be_p4;
        }
    };

    bool can_be_p4(Instruction &inst) {
        bool result = false;
        CanBeP4Visitor visitor(result);
        visitor.visit(inst);
        return result;
    }

    using InstIDSet = std::unordered_set<InstID, InstIDHasher, InstIDEqual>;

    struct LastAccess {
        std::unordered_map<std::string, InstIDSet> reads;
        std::unordered_map<std::string, InstIDSet> writes;
    };

    struct StateDepCtx {
        const std::unordered_map<std::string, BasicBlock *> &blocks;
        std::unordered_map<std::string, LastAccess> block_visited;
        const std::unordered_map<std::string, std::unordered_set<std::string>> &predecessor;

        StateDepCtx(const std::unordered_map<std::string, BasicBlock *> &b,
                    const std::unordered_map<std::string, std::unordered_set<std::string>> &p) :
            blocks(b), predecessor(p) {}
    };
    
    LastAccess get_state_deps(const std::string &curr_block, StateDepCtx &ctx) {
        // returns the latest access of all states AFTER executing the basic block
        if (ctx.block_visited.find(curr_block) != ctx.block_visited.end()) {
            return ctx.block_visited[curr_block];
        }
        LastAccess result;

        // instruction by instruction, update the read and write access records

        LastAccess local;
        auto blk = ctx.blocks.find(curr_block)->second;
        auto &insts = blk->insts_mut();
        for (int i = insts.size() - 1; i >= 0; i--) {
            auto &inst = *insts[i];
            InstID id{curr_block, i};
            InstDeps deps;
            get_deps(inst, deps);
            WriteSet ws;
            get_write_set(inst, ws);
            for (auto &s : deps.state_dep) {
                InstIDSet set;
                set.insert(id);
                result.reads[s] = set;
            }

            for (auto &s : ws.states) {
                InstIDSet set;
                set.insert(id);
                result.writes[s] = set;
            }
        }
        ctx.block_visited.insert({curr_block, local});
        if (ctx.predecessor.find(curr_block) != ctx.predecessor.end()) {
            auto &prev_blocks = ctx.predecessor.find(curr_block)->second;
            for (auto &bn : prev_blocks) {
                auto access = get_state_deps(bn, ctx);
                // merge result
                for (auto &kv : access.reads) {
                    if (result.reads.find(kv.first) == result.reads.end()) {
                        result.reads[kv.first] = kv.second;
                    }
                }
                for (auto &kv : access.writes) {
                    if (result.writes.find(kv.first) == result.writes.end()) {
                        result.writes[kv.first] = kv.second;
                    }
                }
            }
        }

        ctx.block_visited.insert({curr_block, result});

        return result;
    }

    LastAccess state_deps_at_blk_start(const std::string &curr_block, StateDepCtx &ctx) {
        LastAccess result;
        if (ctx.predecessor.find(curr_block) != ctx.predecessor.end()) {
            auto &prev_blocks = ctx.predecessor.find(curr_block)->second;
            for (auto &bn : prev_blocks) {
                StateDepCtx c1(ctx.blocks, ctx.predecessor);
                auto access = get_state_deps(bn, c1);
                // merge result
                for (auto &kv : access.reads) {
                    for (auto &ele : kv.second) {
                        result.reads[kv.first].insert(ele);
                    }
                }
                for (auto &kv : access.writes) {
                    for (auto &ele : kv.second) {
                        result.writes[kv.first].insert(ele);
                    }
                }
            }
        }
        return result;
    }

    InfoSet get_place_info(const std::unordered_map<std::string, BasicBlock *> &blocks, const std::string &entry_blk) {
        InfoSet result;
        std::unordered_map<InstID, InstDeps, InstIDHasher, InstIDEqual> inst_deps;
        std::unordered_map<InstID, WriteSet, InstIDHasher, InstIDEqual> write_sets;
        std::unordered_map<std::string, InstID> dst_map;
        dst_map.insert({"%0", {"args", 0}});
        dst_map.insert({"%1", {"args", 1}});
        dst_map.insert({"%2", {"args", 2}});

        // create dst_map and compute dependencies
        for (auto &blk_kv : blocks) {
            auto blk_name = blk_kv.first;
            auto blk = blk_kv.second;
            auto &insts = blk->insts_mut();
            for (int i = 0; i < insts.size(); i++) {
                InstID id{blk_name, i};
                auto &inst = *insts[i];
                InstDeps dep;
                get_deps(inst, dep);
                inst_deps.insert({id, dep});

                WriteSet ws;
                get_write_set(inst, ws);
                write_sets.insert({id, ws});
                auto dst_reg = inst.get_dst_reg();
                if (dst_reg != "") {
                    dst_map.insert({dst_reg, id});
                }
            }
        }

        // now get reversed dependency
        std::unordered_map<InstID, InstDeps, InstIDHasher, InstIDEqual> rev_inst_deps;
        for (auto &blk_kv : blocks) {
            auto blk_name = blk_kv.first;
            auto blk = blk_kv.second;
            auto &insts = blk->insts_mut();
            auto next = blk->next_blocks();
            for (int i = 0; i < insts.size(); i++) {
                InstID id{blk_name, i};
                InstDeps dep;
                rev_inst_deps.insert({id, dep});
            }
        }
        for (auto &kv : inst_deps) {
            auto id = kv.first;
            assert(blocks.find(std::get<0>(id)) != blocks.end());
            auto blk = blocks.find(std::get<0>(id))->second;
            auto &insts = blk->insts_mut();
            auto &inst = *insts[std::get<1>(id)];
            if (inst.get_dst_reg() == "") {
                continue;
            }
            auto &dep = kv.second;
            for (auto &s : dep.state_dep) {
                
            }

            for (auto &r : dep.reg_dep) {
                if (dst_map.find(r) == dst_map.end()) {
                    continue;
                }
                auto id = dst_map.find(r)->second;
                auto i_iter = rev_inst_deps.find(id);
                if (i_iter == rev_inst_deps.end()) {
                    InstDeps new_dep;
                    rev_inst_deps.insert({id, new_dep});
                    i_iter = rev_inst_deps.find(id);
                    assert(i_iter != rev_inst_deps.end());
                }
                auto &dep = i_iter->second;
                dep.reg_dep.push_back(inst.get_dst_reg());
            }
        }

        std::unordered_map<std::string, std::unordered_set<std::string>> rev_edges;

        for (auto &kv : blocks) {
            auto next = (kv.second)->next_blocks();
            for (auto &b : next) {
                assert(blocks.find(b) != blocks.end());
                rev_edges[b].insert(kv.first);
            }
        }

        std::unordered_map<std::string, LastAccess> last_access;

        for (auto &kv : blocks) {
            StateDepCtx ctx(blocks, rev_edges);
            auto acc = get_state_deps(kv.first, ctx);
            last_access.insert({kv.first, acc});
        }

        for (auto &blk_kv : blocks) {
            auto blk_name = blk_kv.first;
            auto blk = blk_kv.second;
        }

        std::unordered_map<InstID, InstIDSet, InstIDHasher, InstIDEqual> state_dep;
        std::unordered_map<InstID, InstIDSet, InstIDHasher, InstIDEqual> rev_state_dep;

        for (auto &blk_kv : blocks) {
            auto blk_name = blk_kv.first;
            auto blk = blk_kv.second;
            auto &insts = blk->insts_mut();
            StateDepCtx ctx(blocks, rev_edges);
            auto access = state_deps_at_blk_start(blk_name, ctx);
            for (int i = 0; i < insts.size(); i++) {
                InstID id{blk_name, i};
                auto &inst = *insts[i];
                InstDeps deps;
                get_deps(inst, deps);
                WriteSet ws;
                get_write_set(inst, ws);

                InstIDSet dep_set;

                // read
                for (auto &s: deps.state_dep) {
                    if (access.writes.find(s) != access.writes.end()) {
                        for (auto &i : access.writes[s]) {
                            dep_set.insert(i);
                        }
                    }
                }
                
                // write
                for (auto &s: ws.states) {
                    if (access.reads.find(s) != access.reads.end()) {
                        for (auto &i : access.reads[s]) {
                            dep_set.insert(i);
                        }
                    }

                    if (access.writes.find(s) != access.writes.end()) {
                        for (auto &i : access.writes[s]) {
                            dep_set.insert(i);
                        }
                    }
                }

                if (dep_set.size() > 0) {
                    state_dep[id] = dep_set;
                }
                
                // update rev_dep
                for (auto &inst_id : dep_set) {
                    rev_state_dep[inst_id].insert(id);
                }

                // update access records
                for (auto &s : deps.state_dep) {
                    InstIDSet set;
                    set.insert(id);
                    access.reads[s] = set;
                }
                for (auto &s : ws.states) {
                    InstIDSet set;
                    set.insert(id);
                    access.writes[s] = set;
                }
            }
        }

        // construct PlaceInfo from dependency
        for (auto &blk_kv : blocks) {
            auto blk_name = blk_kv.first;
            auto blk = blk_kv.second;
            auto &insts = blk->insts_mut();
            StateDepCtx ctx(blocks, rev_edges);
            auto access = state_deps_at_blk_start(blk_name, ctx);
            for (int i = 0; i < insts.size(); i++) {
                InstID id{blk_name, i};
                auto &inst = *insts[i];
                assert(inst_deps.find(id) != inst_deps.end());
                assert(rev_inst_deps.find(id) != rev_inst_deps.end());
                auto &dep = inst_deps.find(id)->second;
                auto &r_dep = rev_inst_deps.find(id)->second;
                
                PlaceInfo info;
                if (can_be_p4(inst)) {
                    //inst.print(std::cerr);
                    info.can_be_prefix = true;
                    info.can_be_suffix = true;
                    for (auto &s : dep.state_dep) {
                        info.prefix_state_dep.push_back(s);
                    }
                    
                    for (auto &reg : dep.reg_dep) {
                        if (dst_map.find(reg) != dst_map.end()) {
                            info.prefix_inst_dep.push_back(dst_map.find(reg)->second);
                        }
                    }

                    for (auto &s : r_dep.state_dep) {
                        info.suffix_state_dep.push_back(s);
                    }

                    for (auto &reg : r_dep.reg_dep) {
                        if (dst_map.find(reg) != dst_map.end()) {
                            info.suffix_inst_dep.push_back(dst_map.find(reg)->second);
                        }
                    }

                    if (state_dep.find(id) != state_dep.end()) {
                        auto &inst_state_dep = state_dep[id];
                        for (auto &dep_i : inst_state_dep) {
                            info.prefix_inst_dep.push_back(dep_i);
                        }
                    }

                    if (rev_state_dep.find(id) != rev_state_dep.end()) {
                        auto &inst_state_dep = rev_state_dep[id];
                        for (auto &dep_i : inst_state_dep) {
                            info.suffix_inst_dep.push_back(dep_i);
                        }
                    }

                    InstIDSet &state_dep_set = state_dep[id];
                    InstIDSet &rev_state_dep_set = rev_state_dep[id];
                    for (auto &inst_id : state_dep_set) {
                        info.prefix_inst_dep.push_back(inst_id);
                    }
                    for (auto &inst_id : rev_state_dep_set) {
                        info.suffix_inst_dep.push_back(inst_id);
                    }
                }
                result.inst_info.insert({id, info});
            }
        }
        return result;
    }

    std::string graphviz_inst_str(const Instruction &inst) {
        const static int max_len = 50;
        std::stringstream ss;
        inst.print(ss);
        auto raw_str = ss.str();
        if (raw_str.length() > max_len) {
            raw_str = raw_str.substr(0, max_len - 3) + "...";
        }
        return str_escape_html(raw_str);
    }

    void generate_dot_file(std::ostream &os,
                           const std::unordered_map<std::string, BasicBlock *> &blocks,
                           const std::unordered_map<InstID, std::string,
                           InstIDHasher, InstIDEqual> &inst_color) {
        generate_dot_file(os, blocks,
                          [&inst_color](InstID id) -> std::string {
                              if (inst_color.find(id) != inst_color.end()) {
                                  return inst_color.find(id)->second;
                              } else {
                                  return "white";
                              }
                          });
    }

    void generate_dot_file(std::ostream &os,
                           const std::unordered_map<std::string, std::shared_ptr<BasicBlock>> &blocks,
                           std::function<std::string(InstID)> color_of) {
        std::unordered_map<std::string, BasicBlock *> blks;
        for (auto &kv : blocks) {
            blks.insert({kv.first, kv.second.get()});
        }
        generate_dot_file(os, blks, color_of);
    }

    void generate_dot_file(std::ostream &os, const std::unordered_map<std::string, BasicBlock *> &blocks,
                           std::function<std::string(InstID)> color_of) {
        os << "digraph cfg {" << std::endl;
        
        // first print all the basic blocks
        for (auto &kv : blocks) {
            auto &blk = *kv.second;
            auto &insts = blk.insts_mut();
            os << "\"" << kv.first << "\"";
            os << " [" << std::endl << "shape=none" << std::endl;
            // print instructions, we use html style label
            os << "label = <<table border=\"0\" cellspacing=\"0\">" << std::endl;
            os << "<tr><td port=\"title\" border=\"1\" bgcolor=\"black\">"
               << "<font color=\"white\">"
               << kv.first
               << "</font>"
               << "</td></tr>"
               << std::endl;
            for (int i = 0; i < insts.size(); i++) {
                auto &inst = *insts[i];
                auto inst_str = graphviz_inst_str(inst);
                auto port_str = "port" + std::to_string(i);
                InstID inst_id{kv.first, i};
                std::string color_str = color_of(inst_id);
                os << "<tr><td port=\"" << port_str << "\" ";
                os << "border=\"1\" bgcolor=\""
                   << color_str
                   << "\">"
                   << inst_str
                   << "</td></tr>"
                   << std::endl;
            }
            os << "</table>>" << std::endl;
            os << "];" << std::endl;
        }

        for (auto &kv : blocks) {
            auto &blk = *kv.second;
            auto nbs = blk.next_blocks();
            if (nbs.size() == 0) {
                continue;
            }
            os << "\"" << blk.get_name() << "\":s -> \"";
            os << nbs[0] << "\":n";
            if (nbs.size() > 1) {
                os << "[label=\"" << blk.branch_cond() << "\"];";
                os << std::endl;
                os << "\"" << blk.get_name() << "\":s -> \"";
                os << nbs[1] << "\":n";
            }
            os << ";" << std::endl;
        }
        
        os << "}" << std::endl;
    }

    bool can_swap(Instruction &lhs, Instruction &rhs) {
        InstDeps lhs_dep, rhs_dep;
        WriteSet lhs_ws, rhs_ws;
        get_deps(lhs, lhs_dep);
        get_deps(rhs, rhs_dep);
        get_write_set(lhs, lhs_ws);
        get_write_set(rhs, rhs_ws);

        for (auto &reg : lhs_ws.regs) {
            if (std::find(rhs_ws.regs.begin(),
                          rhs_ws.regs.end(), reg)
                != rhs_ws.regs.end()) {
                return false;
            }

            if (std::find(rhs_dep.reg_dep.begin(),
                          rhs_dep.reg_dep.end(), reg)
                != rhs_dep.reg_dep.end()) {
                return false;
            }
        }

        for (auto &reg : lhs_dep.reg_dep) {
            if (std::find(rhs_ws.regs.begin(),
                          rhs_ws.regs.end(), reg)
                != rhs_ws.regs.end()) {
                return false;
            }
        }

        for (auto &s : lhs_ws.states) {
            if (std::find(rhs_ws.states.begin(),
                          rhs_ws.states.end(), s)
                != rhs_ws.states.end()) {
                return false;
            }

            if (std::find(rhs_dep.state_dep.begin(),
                          rhs_dep.state_dep.end(), s)
                != rhs_dep.state_dep.end()) {
                return false;
            }
        }

        for (auto &s : lhs_dep.state_dep) {
            if (std::find(rhs_ws.states.begin(),
                          rhs_ws.states.end(), s)
                != rhs_ws.states.end()) {
                return false;
            }
        }
        
        return true;
    }

    void reorder_insts(BasicBlock &blk, InfoSet &info_set, PlaceResult &result) {
        auto &insts = blk.insts_mut();
        std::vector<PlaceType> inst_type;
        for (int i = 0; i < insts.size(); i++) {
            InstID id{blk.get_name(), i};
            assert(result.fixed_inst.find(id) != result.fixed_inst.end());
            inst_type.push_back(result.fixed_inst.find(id)->second);
        }

        // move prefix
        for (int i = 1; i < insts.size(); i++) {
            if (inst_type[i] != PlaceType::P4_PREFIX
                && inst_type[i] != PlaceType::P4_BOTH) {
                continue;
            }
            auto inst_ptr = insts[i];
            auto inst_t = inst_type[i];
            int end_idx = i;
            for (int j = i - 1; j >= 0; j--) {
                if (can_swap(*inst_ptr, *insts[j])) {
                    insts[j+1] = insts[j];
                    inst_type[j+1] = inst_type[j];
                    end_idx = j;
                } else {
                    break;
                }
            }
            insts[end_idx] = inst_ptr;
            inst_type[end_idx] = inst_t;
        }

        // move suffix
        for (int i = insts.size() - 1; i >= 0; i--) {
            if (inst_type[i] != PlaceType::P4_SUFFIX) {
                continue;
            }
            auto inst_ptr = insts[i];
            auto inst_t = inst_type[i];
            int end_idx = i;
            for (int j = i + 1; j < insts.size(); j++) {
                if (can_swap(*inst_ptr, *insts[j])) {
                    insts[j-1] = insts[j];
                    inst_type[j-1] = inst_type[j];
                    end_idx = j;
                } else {
                    break;
                }
            }
            insts[end_idx] = inst_ptr;
            inst_type[end_idx] = inst_t;
        }
        for (int i = 0; i < insts.size(); i++) {
            InstID id{blk.get_name(), i};
            result.fixed_inst[id] = inst_type[i];
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
}
