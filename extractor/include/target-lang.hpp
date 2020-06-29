#ifndef _TARGET_LANG_HPP_
#define _TARGET_LANG_HPP_

#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>
#include <tuple>
#include <memory>
#include <type_traits>
#include "llvm-incl.hpp"
#include "placer.hpp"
#include "utils.hpp"


#define INST_VISITER_DISPATCHER \
    virtual void call_visitor(InstVisitor &v) override {                \
        return v.visit_inst(*this);                                     \
    }                                                                   \
    virtual void call_const_visitor(ConstInstVisitor &v)                \
        const override {                                                \
        return v.visit_inst(*this);                                     \
    }


namespace Target {

    class Type {
    };

    class NumType : public Type {
    public:
        
    };

    class InstVisitor;
    class ConstInstVisitor;
    
    class LLVMInst;
    class ArithInst;
    class BranchInst;
    class HeaderReadInst;
    class HeaderWriteInst;
    class MapGetInst;
    class DataStructureOp;
    class EntryReadInst;
    class EntryWriteInst;
    class AllocaInst;
    class PhiInst;
    class CallInst;
    class ReturnInst;
    class EmitPktInst;
    class UnknownInst;
    class TransitInst; // dev -> cpu && cpu -> dev

    class WithAnnotation {
    public:
        template <typename T>
        void set_anno(std::shared_ptr<T> ptr) {
            anno_ptr_ = std::dynamic_pointer_cast(ptr);
        }

        template <typename T>
        std::shared_ptr<T> get_anno() const {
            return std::dynamic_pointer_cast<T>(anno_ptr_);
        }
    protected:
        std::shared_ptr<void> anno_ptr_ = nullptr;
    };

    class Instruction : public WithAnnotation {
    public:
        const llvm::Instruction *llvm_inst_ptr_ = nullptr;
        llvm::Type *llvm_type_ = nullptr;
        
        Instruction(const std::string &dst);
        virtual void print(std::ostream &os) const = 0;
        std::string get_dst_reg() const {
            return dst_reg_;
        }

        virtual bool is_call() const {
            return false;
        }

        virtual bool is_arith_inst() const {
            return false;
        }

        virtual bool is_phi() const {
            return false;
        }

        virtual bool is_llvm_inst() const {
            return false;
        }

        virtual bool is_alloca() const {
            return false;
        }

        virtual bool is_map_get() const {
            return false;
        }

        virtual bool is_data_structure_op() const {
            return false;
        }

        virtual bool is_entry_read() const {
            return false;
        }

        virtual bool is_entry_write() const {
            return false;
        }

        virtual bool is_map_set() const {
            return false;
        }

        virtual bool is_header_get() const {
            return false;
        }

        virtual bool is_header_set() const {
            return false;
        }

        virtual bool is_return() const {
            return false;
        }

        virtual void set_place(const std::string &place) {
            placement_ = place;
        }

        virtual std::string placement() const {
            return placement_;
        }

        virtual void call_visitor(InstVisitor &v)=0;
        virtual void call_const_visitor(ConstInstVisitor &v) const=0;

        virtual ~Instruction();

    protected:
        std::string dst_reg_;
        std::string placement_;
    };


    class ConstInstVisitor {
    public:
        virtual void visit(const Instruction &inst);
        virtual void visit_inst(const Instruction &inst);
        virtual void visit_inst(const LLVMInst &inst);
        virtual void visit_inst(const ArithInst &inst);
        virtual void visit_inst(const BranchInst &inst);
        virtual void visit_inst(const HeaderReadInst &inst);
        virtual void visit_inst(const HeaderWriteInst &inst);
        virtual void visit_inst(const MapGetInst &inst);
        virtual void visit_inst(const DataStructureOp &inst);
        virtual void visit_inst(const EntryReadInst &inst);
        virtual void visit_inst(const EntryWriteInst &inst);
        virtual void visit_inst(const AllocaInst &inst);
        virtual void visit_inst(const PhiInst &inst);
        virtual void visit_inst(const CallInst &inst);
        virtual void visit_inst(const ReturnInst &inst);
        virtual void visit_inst(const EmitPktInst &inst);
        virtual void visit_inst(const UnknownInst &inst);
        virtual void visit_inst(const TransitInst &inst);
    };

    class InstVisitor {
    public:
        virtual void visit(Instruction &inst);
        virtual void visit_inst(Instruction &inst);
        virtual void visit_inst(LLVMInst &inst);
        virtual void visit_inst(ArithInst &inst);
        virtual void visit_inst(BranchInst &inst);
        virtual void visit_inst(HeaderReadInst &inst);
        virtual void visit_inst(HeaderWriteInst &inst);
        virtual void visit_inst(MapGetInst &inst);
        virtual void visit_inst(DataStructureOp &inst);
        virtual void visit_inst(EntryReadInst &inst);
        virtual void visit_inst(EntryWriteInst &inst);
        virtual void visit_inst(AllocaInst &inst);
        virtual void visit_inst(PhiInst &inst);
        virtual void visit_inst(CallInst &inst);
        virtual void visit_inst(ReturnInst &inst);
        virtual void visit_inst(EmitPktInst &inst);
        virtual void visit_inst(UnknownInst &inst);
        virtual void visit_inst(TransitInst &inst);
    };

    class TransitInst : public Instruction {
    public:
        TransitInst();
    };
    
    class LLVMInst : public Instruction {
    public:
        LLVMInst(const llvm::Instruction &inst);
        virtual void print(std::ostream &os) const override;
        virtual bool is_llvm_inst() const override {
            return true;
        }
        llvm::Instruction *get_inst() const {
            return inst_;
        }

        virtual void call_visitor(InstVisitor &v) override {
            return v.visit_inst(*this);
        }
        
        virtual void call_const_visitor(ConstInstVisitor &v) const override {
            return v.visit_inst(*this);
        }
        
    protected:
        llvm::Instruction *inst_;
    };


    class ArithInst : public Instruction {
    public:
        enum class Op {
            CONST_VAL,
            ADD,
            SUB,
            MUL,
            DIV,
            MOD,
            ARSH,
            LRSH,
            LSH,
            EQ,
            NE,
            SLT,
            ULT,
            SLE,
            ULE,
            SGT,
            UGT,
            SGE,
            UGE,
            AND,
            OR,
            XOR,
            NOT,
            LAND,
            LOR,
            LNOT,
        };
        ArithInst(const std::string &dst, Op op,
                  const std::vector<std::string> &oprands);

        static bool is_cmp(Op op);

        virtual bool is_arith_inst() const override {
            return true;
        }

        virtual void print(std::ostream &os) const override;
        virtual void call_visitor(InstVisitor &v) override {
            return v.visit_inst(*this);
        }

        virtual void call_const_visitor(ConstInstVisitor &v) const override {
            return v.visit_inst(*this);
        }

        Op op() const {
            return op_;
        }

        std::string op_str() const;

        std::vector<std::string> oprands() const {
            return oprands_;
        }

        llvm::Type *dst_type_anno = nullptr;
    protected:
        Op op_;
        std::vector<std::string> oprands_;
    };


    class BranchInst : public Instruction {
    public:
        BranchInst(const std::string &reg, const std::string &target);

        virtual void print(std::ostream &os) const override;
        virtual void call_visitor(InstVisitor &v) override {
            return v.visit_inst(*this);
        }

        virtual void call_const_visitor(ConstInstVisitor &v) const override {
            return v.visit_inst(*this);
        }
    protected:
        std::string cond_reg_;
        std::string target_bb_;
    };


    class HeaderReadInst : public Instruction {
    public:
        HeaderReadInst(const std::string &dst, const std::string &pkt_name,
                       const std::string &header_name, const std::string &field_name);

        virtual void print(std::ostream &os) const override;
        virtual void call_visitor(InstVisitor &v) override {
            return v.visit_inst(*this);
        }

        virtual void call_const_visitor(ConstInstVisitor &v) const override {
            return v.visit_inst(*this);
        }
        
        std::string pkt_name() const {
            return pkt_name_;
        }
        
        std::string header_name() const {
            return header_name_;
        }
        
        std::string field_name() const {
            return field_name_;
        }
        
    protected:
        std::string pkt_name_;
        std::string header_name_;
        std::string field_name_;
    };


    class HeaderWriteInst : public Instruction {
    public:
        HeaderWriteInst(const std::string &pkt_name, const std::string &header_name,
                        const std::string &field_name, const std::string &val_reg);
        virtual void print(std::ostream &os) const override;
        virtual void call_visitor(InstVisitor &v) override {
            return v.visit_inst(*this);
        }

        virtual bool is_header_set() const override {
            return true;
        }

        virtual void call_const_visitor(ConstInstVisitor &v) const override {
            return v.visit_inst(*this);
        }
        
        std::string pkt_name() const {
            return pkt_name_;
        }
        std::string val_reg() const {
            return val_reg_;
        }
        std::string header_name() const {
            return header_name_;
        }
        std::string field_name() const {
            return field_name_;
        }
    protected:
        std::string pkt_name_;
        std::string header_name_;
        std::string field_name_;
        std::string val_reg_;
    };


    class MapGetInst : public Instruction {
    public:
        /*
         * map_reg : pointer to the hash map object
         * key_reg : pointer to the key struct (e.g. pointer to alloca)
         */
        MapGetInst(const std::string &dst_reg, const std::string &map_reg,
                   const std::string &key_reg, const std::string &val_reg);
        virtual void print(std::ostream &os) const override;
        std::string map_reg() const {
            return map_reg_;
        }
        virtual bool is_map_get() const override {
            return true;
        }
        std::string key_reg() const {
            return key_reg_;
        }
        std::string val_reg() const {
            return val_reg_;
        }
        virtual void call_visitor(InstVisitor &v) override {
            return v.visit_inst(*this);
        }

        virtual void call_const_visitor(ConstInstVisitor &v) const override {
            return v.visit_inst(*this);
        }
        
    protected:
        std::string map_reg_;
        std::string key_reg_;
        std::string val_reg_;
    };


    class DataStructureOp : public Instruction {
    public:
        DataStructureOp(const std::string &type,
                        const std::string &op,
                        const std::string &obj,
                        const std::string &dst,
                        const std::vector<std::string> &args);

        virtual void print(std::ostream &os) const override;

        virtual bool is_data_structure_op() const override {
            return true;
        }
        
        INST_VISITER_DISPATCHER

        std::string data_structure_type() const {
            return type_;
        }

        std::string obj_reg() const {
            return obj_;
        }

        std::string get_op() const {
            return op_;
        }

        const std::vector<std::string> &args() const {
            return args_;
        }

    protected:
        std::string type_, op_, obj_;
        std::vector<std::string> args_;
    };


    class EntryReadInst : public Instruction {
    public:
        EntryReadInst(const std::string &dst,
                      const std::string &entry_reg,
                      int field_idx);
        virtual void print(std::ostream &os) const override;
        std::string entry_reg() const {
            return entry_reg_;
        }
        int field_idx() const {
            return field_idx_;
        }

        virtual bool is_entry_read() const override {
            return true;
        }

        INST_VISITER_DISPATCHER
        
    protected:
        std::string entry_reg_;
        int field_idx_;
    };

    
    class EntryWriteInst : public Instruction {
    public:
        EntryWriteInst(const std::string &entry_reg,
                       int field_idx,
                       const std::string &val_reg);
        virtual void print(std::ostream &os) const override;
        std::string entry_reg() const {
            return entry_reg_;
        }
        std::string val_reg() const {
            return val_reg_;
        }
        int field_idx() const {
            return field_idx_;
        }

        virtual bool is_entry_write() const override {
            return true;
        }

        INST_VISITER_DISPATCHER
        
    protected:
        std::string entry_reg_;
        int field_idx_;
        std::string val_reg_;
    };


    class AllocaInst : public Instruction {
    public:
        AllocaInst(const std::string &dst, const std::string &type_name, int size);
        virtual void print(std::ostream &os) const override;

        virtual bool is_alloca() const override;
        virtual void call_visitor(InstVisitor &v) override {
            return v.visit_inst(*this);
        }

        virtual void call_const_visitor(ConstInstVisitor &v) const override {
            return v.visit_inst(*this);
        }
        
        std::string type() const {
            return type_;
        }
        int n_elements() const {
            return n_elements_;
        }
        llvm::Type *llvm_type;
    protected:
        std::string type_;
        int n_elements_;
    };


    class PhiInst : public Instruction {
    public:
        PhiInst(const std::string &dst, const std::unordered_map<std::string, std::string> &vals);

        virtual void print(std::ostream &os) const override;
        virtual void call_visitor(InstVisitor &v) override {
            return v.visit_inst(*this);
        }

        virtual void call_const_visitor(ConstInstVisitor &v) const override {
            return v.visit_inst(*this);
        }
        
        virtual bool is_phi() const override {
            return true;
        }

        const std::unordered_map<std::string, std::string> &vals() const {
            return vals_;
        }
    protected:
        /*
         * vals_ : mapping from incoming basic block to register
         */
        std::unordered_map<std::string, std::string> vals_;
    };


    class CallInst : public Instruction {
    public:
        CallInst(const std::string &dst_reg, const std::string &func_name,
                 const std::vector<std::string> &arg_regs);
        
        virtual void print(std::ostream &os) const override;
        virtual bool is_call() const override {
            return true;
        }

        std::string func_name() const {
            return func_;
        }

        const std::vector<std::string> &args() const {
            return args_;
        }

        std::vector<std::string>::iterator args_begin() {
            return args_.begin();
        }

        std::vector<std::string>::iterator args_end() {
            return args_.end();
        }
        virtual void call_visitor(InstVisitor &v) override {
            return v.visit_inst(*this);
        }

        virtual void call_const_visitor(ConstInstVisitor &v) const override {
            return v.visit_inst(*this);
        }
        
    protected:
        std::string func_;
        std::vector<std::string> args_;
    };


    class ReturnInst : public Instruction {
    public:
        ReturnInst(const std::string &val);

        virtual void print(std::ostream &os) const override;
        virtual void call_visitor(InstVisitor &v) override {
            return v.visit_inst(*this);
        }

        virtual void call_const_visitor(ConstInstVisitor &v) const override {
            return v.visit_inst(*this);
        }

        std::string ret_val() const {
            return ret_reg_;
        }

        virtual bool is_return() const override {
            return true;
        }
    protected:
        std::string ret_reg_;
    };


    class EmitPktInst : public Instruction {
    public:
        EmitPktInst(const std::string &pkt_reg, const std::string &port_reg);
        virtual void print(std::ostream &os) const override;
        virtual void call_visitor(InstVisitor &v) override {
            return v.visit_inst(*this);
        }

        virtual void call_const_visitor(ConstInstVisitor &v) const override {
            return v.visit_inst(*this);
        }

        std::string pkt_name() const {
            return pkt_reg_;
        }

        std::string port_reg() const {
            return port_reg_;
        }
    protected:
        std::string pkt_reg_;
        std::string port_reg_;
    };


    class UnknownInst : public Instruction {
    public:
        UnknownInst(const std::string &desc);
        virtual void print(std::ostream &os) const override;
        virtual void call_visitor(InstVisitor &v) override {
            return v.visit_inst(*this);
        }

        virtual void call_const_visitor(ConstInstVisitor &v) const override {
            return v.visit_inst(*this);
        }
        
    protected:
        std::string description_;
    };


    class BasicBlock : public WithAnnotation {
    public:
        using InstList = std::vector<std::shared_ptr<Instruction>>;
        BasicBlock(const std::string &name, std::vector<std::shared_ptr<Instruction>> &&insts);
        BasicBlock(const std::string &name, const std::vector<std::shared_ptr<Instruction>> &insts);

        void add_branch(const std::string &cond_var,
                        const std::string &t_target_bb,
                        const std::string &f_target_bb);
        void add_next(const std::string next_bb);
        bool is_conditional() const;
        std::string get_name() const {
            return name_;
        }

        void set_name(const std::string &name) {
            name_ = name;
        }

        InstList &insts_mut() {
            return insts_;
        }

        void set_insts(const InstList &insts) {
            insts_ = insts;
        }

        InstList::iterator inst_begin() {
            return insts_.begin();
        }

        InstList::iterator inst_end() {
            return insts_.end();
        }

        std::string branch_cond() const {
            return branch_cond_;
        }

        std::string t_branch() const {
            assert(this->is_conditional());
            return t_bb_;
        }

        std::string f_branch() const {
            assert(this->is_conditional());
            return f_bb_;
        }

        std::string next_bb() const {
            assert(!this->is_conditional());
            return t_bb_;
        }

        std::vector<std::string> next_blocks() const {
            std::vector<std::string> result;
            if (t_bb_ != "") {
                result.push_back(t_bb_);
            }
            if (branch_cond_ != "") {
                result.push_back(f_bb_);
            }
            return result;
        }

        std::vector<BasicBlock *> split_to_parallel_blks() const;
        
    protected:
        std::string name_;
        InstList insts_;
        std::string branch_cond_;
        std::string t_bb_;
        std::string f_bb_;
    };

    void add_place_req(Instruction *inst, const InstID &id, PlaceReqSet &req_set,
                       const std::unordered_map<std::string, InstID> &dst_map);

    struct InstDeps {
        bool moveable = false;
        std::vector<std::string> reg_dep;
        std::vector<std::string> state_dep;
    };

    void get_deps(const Instruction &inst, InstDeps &deps);

    struct WriteSet {
        std::vector<std::string> regs;
        std::vector<std::string> states;
    };

    void get_write_set(Instruction &inst, WriteSet &ws);

    bool no_side_effect(Instruction &inst);

    InfoSet get_place_info(const std::unordered_map<std::string, BasicBlock *> &blocks,
                           const std::string &entry_blk);

    std::string graphviz_inst_str(const Instruction &inst);

    void generate_dot_file(std::ostream &os,
                           const std::unordered_map<std::string, BasicBlock *> &blocks,
                           const std::unordered_map<InstID, std::string,
                           InstIDHasher, InstIDEqual> &inst_color);

    void generate_dot_file(std::ostream &os,
                           const std::unordered_map<std::string, BasicBlock *> &blocks,
                           std::function<std::string(InstID)> color_of);

    void generate_dot_file(std::ostream &os,
                           const std::unordered_map<std::string, std::shared_ptr<BasicBlock>> &blocks,
                           std::function<std::string(InstID)> color_of);

    void reorder_insts(BasicBlock &blk, InfoSet &info_set, PlaceResult &result);


    /*
     * Type infomation for packet header and maps
     */

    struct MapType {
        std::string key_type;
        std::string val_type;
    };

    struct GlobalTypes {
        std::unordered_map<std::string, MapType> maps;
        std::unordered_map<std::string, std::string> pkt_fields;
    };

    std::unordered_map<std::string, Target::BasicBlock *>
    split_blocks(std::unordered_map<std::string, Target::BasicBlock *> &blocks);

    bool can_be_p4(Instruction &inst);
}

#undef INST_VISITER_DISPATCHER

#endif /* _TARGET_LANG_HPP_ */
