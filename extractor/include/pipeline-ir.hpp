#ifndef __MORULA_PIPELINE_IR_HPP__
#define __MORULA_PIPELINE_IR_HPP__

#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <tuple>
#include <optional>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/functional/hash.hpp>
#include "llvm-incl.hpp"
#include "click-state.hpp"

namespace Morula {
    namespace PipeIR {
        // TODO: may be we need an UUID for each object in the IR
        using uuid_t = boost::uuids::uuid;
        using uuid_unordered_set_t = std::unordered_set<uuid_t, boost::hash<uuid_t>>;

        template <typename ValT>
        using uuid_unordered_map_t = std::unordered_map<uuid_t, ValT, boost::hash<uuid_t>>;
        class IRObj {
        public:
            IRObj();
            const uuid_t& get_uuid() const { return uuid_; };

            std::string name;        // a more human friendly name
        protected:
            uuid_t uuid_;
        };

        class IRException {
        public:
            IRException(const std::string &str) : msg(str) {}
            std::string msg;
        };

        class VarType {
        public:
            enum class T {
                INT,   // integer (bitvector) type
                PTR,   // pointer type
                STRUCT,
                ARRAY,
                ARGUMENT,
                CLASS, // this is a pointer to class
                STATE_PTR,
            };

            T type;

            int int_bitwidth;
            VarType *ptr_pointee_type;
            std::vector<VarType *> struct_types;
            std::vector<int> struct_offset; // struct field offset in bytes
            int struct_num_bytes;

            VarType *array_element_type;
            uint64_t array_size;
            std::string class_name;

            static std::unique_ptr<VarType> IntType(int bw);
            static std::unique_ptr<VarType> PtrType(VarType *t);
            static std::unique_ptr<VarType> StructType(const std::vector<VarType *> &ts);
            static std::unique_ptr<VarType> ArrayType(VarType *t, uint64_t size);
            static std::unique_ptr<VarType> ArgType();

            void EmplaceIntType(int bw);
            void EmplacePtrType(VarType *t);
            void EmplaceStructType(const std::vector<VarType *> &ts);
            void EmplaceArrayType(VarType *t, uint64_t size);
            void EmplaceArgType();
            void EmplaceClass(const std::string &class_name);

            bool equals(const VarType *other);
            bool have_no_ptr() const;
            int get_num_bytes() const;

            int get_off_by_idx(int i) const;
            VarType *get_type_by_idx(int i) const;

            int offset_from_gep_offset(const std::vector<int> &idx, VarType **typep) const;
        };

        class Operation;
        class Stage;

        class VarInfo {
        public:
            enum class T {
                UNKNOWN,
                STACK_PTR,
                PKT_OBJ,
                PKT_DATA,
                STATE_MID,
                STATE_FINAL,
            };

            T type = T::UNKNOWN;
            std::vector<int> state_offsets;
            bool is_array_type = false;
            bool have_dyn_offset = true;
        };

        class Var : public IRObj {
        public:
            static int new_var_cnt();

            VarType *type;

            std::shared_ptr<VarInfo> var_info;

            bool is_per_pkt; // header field or metadata
            bool is_pkt_header = false;
            bool is_param = false;
            bool is_constant = false;

            std::string header_name;
            std::string field_name;
            std::string var_name;

            Operation *from;
            int64_t const_val;
            std::unordered_set<Operation *> uses;
            std::unordered_set<Stage *> branch_uses;
            std::unordered_set<Stage *> func_call_uses;

            Var() {
                uses.clear();
                var_name = "var_" + std::to_string(Var::new_var_cnt());
            }

            Var(const std::string &v) {
                uses.clear();
                var_name = v;
            }

            void print(std::ostream &os);
            void print_decl(std::ostream &os);

            bool is_const_val(int64_t v) const { return is_constant && const_val == v; };
            bool is_state_ptr() const { return type->type == VarType::T::STATE_PTR; };

            std::shared_ptr<VarInfo> get_var_info();
        };

        class Stage;
        class GlobalState;

        class Operation : public IRObj {
        public:
            enum class Type {
                NOP,
                ALLOC_TMP,
                ARITH,
                PHI,
                STATE_OP,
                POINTER_OFF,
                LOAD,
                STORE,
                PKTHDR_R,
                PKTHDR_W,
            };

            Type type;

            std::string arith_op_name;
            std::string pointer_op_name;

            GlobalState *state;
            std::string state_op_name;

            std::string header_name;
            std::string field_name;

            std::vector<uuid_t> phi_incoming_stages;
            std::vector<std::shared_ptr<Var>> phi_incoming_vals;

            std::vector<std::shared_ptr<Var>> dst_var;
            std::vector<std::shared_ptr<Var>> oprands;

            std::unordered_set<Var *> vars_read() const;
            std::unordered_set<Var *> vars_written() const;

            std::unordered_set<GlobalState *> state_read() const;
            std::unordered_set<GlobalState *> state_written() const;

            std::unordered_set<std::string> possible_labels() const;

            Stage *parent = nullptr;
            int idx_in_stage = -1;

            std::optional<std::string> color_str = std::nullopt;

            std::shared_ptr<Var> get_load_store_pointer() const { return oprands[0]; }

            bool has_side_effect() const;

            friend std::ostream& operator<<(std::ostream &os, const Operation &op);
        };

        template <typename RetT>
        class OperationVisitor {
        public:
            RetT visit(Operation &op) {
                auto t = op.type;
                using T = Operation::Type;
                switch (t) {
                    case T::NOP:
                        return this->visitNop(op);
                    case T::ALLOC_TMP:
                        return this->visitAllocTmp(op);
                    case T::ARITH:
                        return this->visitArith(op);
                    case T::PHI:
                        return this->visitPhi(op);
                    case T::STATE_OP:
                        return this->visitStateOp(op);
                    case T::POINTER_OFF:
                        return this->visitPointerOffOp(op);
                    case T::LOAD:
                        return this->visitLoadOp(op);
                    case T::STORE:
                        return this->visitStoreOp(op);
                    case T::PKTHDR_R:
                        return this->visitHdrReadOp(op);
                    case T::PKTHDR_W:
                        return this->visitHdrWriteOp(op);
                    default:
                        return this->visitOtherOp(op);
                }

            }

            virtual RetT visitOtherOp(Operation &op) {
                assert(false && "unknown operation");
            };
            virtual RetT visitNop(Operation &op) {
                return this->visitOtherOp(op);
            }

            virtual RetT visitArith(Operation &op) {
                return this->visitOtherOp(op);
            }

            virtual RetT visitAllocTmp(Operation &op) {
                return this->visitOtherOp(op);
            }

            virtual RetT visitPhi(Operation &op) {
                return this->visitOtherOp(op);
            }

            virtual RetT visitStateOp(Operation &op) {
                return this->visitOtherOp(op);
            }

            virtual RetT visitPointerOffOp(Operation &op) {
                return this->visitOtherOp(op);
            }

            virtual RetT visitLoadOp(Operation &op) {
                return this->visitOtherOp(op);
            }

            virtual RetT visitStoreOp(Operation &op) {
                return this->visitOtherOp(op);
            }

            virtual RetT visitHdrReadOp(Operation &op) {
                return this->visitOtherOp(op);
            }

            virtual RetT visitHdrWriteOp(Operation &op) {
                return this->visitOtherOp(op);
            }
        };

        enum class StageTerminatorType {
            FAULT,
            BRANCH,
            SWITCH,
            RETURN,
            NEXT_DEV,
            FUNC_CALL,
            TABLE_DISPATCH,  // terminator_type for switch only
        };

        class Function;

        class Stage : public IRObj {
        public:
            std::vector<std::unique_ptr<Operation>> ops;
            std::vector<std::shared_ptr<Var>> params;     // packet not included here
            std::vector<std::shared_ptr<Var>> vars_defined;

            std::vector<GlobalState *> read_set();
            std::vector<GlobalState *> write_set();

            // INV: next_stages.size() == cond_vars.size() + 1
            std::vector<Var *> cond_vars;
            std::vector<Stage *> next_stages;
            std::vector<uint64_t> switch_cases;

            std::vector<Stage *> passed_continuations;

            StageTerminatorType terminator_type;
            std::string func_called;
            std::vector<std::shared_ptr<Var>> call_params;

            std::vector<std::shared_ptr<Var>> ret_vals;

            Function *parent = nullptr;

            Stage() {}
            Stage(std::vector<std::unique_ptr<Operation>> &&ops);
        };


        class Function {
        public:
            uuid_t entry_bb;
            uuid_unordered_map_t<std::unique_ptr<Stage>> bbs_;
            std::vector<std::shared_ptr<Var>> params_;
        };

        class Prog {
        public:
            Prog();
            Prog(std::vector<std::unique_ptr<Stage>> &&stages);

            Stage& get_stage(const uuid_t &idx);
            const Stage& get_stage(const uuid_t &idx) const;

            void build_rev_edge();

            uuid_t first_stage_id_;
            uuid_unordered_map_t<std::unique_ptr<Stage>> stages_;
            uuid_unordered_map_t<std::vector<uuid_t>> rev_edges;
        };

        class GlobalState {
        public:
            enum class Type {
                TABLE, // p4 table
                ARRAY, // fix-sized array (size known)
                CLICK_STATE,
            };

            Type type;

            Click::StateEntry click_t;

            std::vector<int> map_key_width;
            std::vector<int> map_val_width;
            int map_size;

            std::string name_anno;

            int array_ele_width;
            int array_size;
        };

        // classes for a "pre-pipeline" IR
        class PreStage : public IRObj {
        public:
            std::string name; // this is just for pretty printing and debugging
            std::vector<llvm::Instruction *> insts;

            std::vector<llvm::Value *> cond_vars;
            std::vector<llvm::ConstantInt *> switch_cases;
            std::vector<PreStage *> next_stages;
            std::vector<PreStage *> passed_continuations;
            bool call_continuation = false;
            StageTerminatorType terminator_type;
        };

        std::string op_to_str(Operation &op);
    }
}

std::ostream& operator<<(std::ostream &os, Morula::PipeIR::Operation &op);


#endif

