#include "pipeline-ir.hpp"

namespace Morula {
    namespace PipeIR {
        IRObj::IRObj() : uuid_(boost::uuids::random_generator()()) {
        }

        std::unique_ptr<VarType> VarType::IntType(int bw) {
            auto p = std::make_unique<VarType>();
            p->type = T::INT;
            p->int_bitwidth = bw;
            return p;
        }

        std::unique_ptr<VarType> VarType::PtrType(VarType *t) {
            auto p = std::make_unique<VarType>();
            p->type = T::PTR;
            p->ptr_pointee_type = t;
            return p;
        }

        std::unique_ptr<VarType> VarType::StructType(const std::vector<VarType *> &ts) {
            auto p = std::make_unique<VarType>();
            p->type = T::STRUCT;
            p->struct_types = ts;
            return p;
        }

        std::unique_ptr<VarType> VarType::ArrayType(VarType * t, uint64_t size) {
            auto p = std::make_unique<VarType>();
            p->type = T::ARRAY;
            p->array_element_type = t;
            p->array_size = size;
            return p;
        }

        std::unique_ptr<VarType> VarType::ArgType() {
            auto p = std::make_unique<VarType>();
            p->type = T::ARGUMENT;
            return p;
        }

        void VarType::EmplaceIntType(int bw) {
            type = T::INT;
            int_bitwidth = bw;
        }

        void VarType::EmplacePtrType(VarType *t) {
            type = T::PTR;
            ptr_pointee_type = t;
        }

        void VarType::EmplaceStructType(const std::vector<VarType *> &ts) {
            type = T::STRUCT;
            struct_types = ts;
        }

        void VarType::EmplaceArrayType(VarType *t, uint64_t size) {
            type = T::ARRAY;
            array_element_type = t;
            array_size = size;
        }

        void VarType::EmplaceArgType() {
            type = T::ARGUMENT;
        }

        void VarType::EmplaceClass(const std::string &c_name) {
            type = T::CLASS;
            class_name = c_name;
        }

        bool VarType::equals(const VarType *other) {
            if (this->type != other->type) {
                return false;
            }

            switch (this->type) {
            case T::INT:
                return (this->int_bitwidth == other->int_bitwidth);
            case T::PTR:
                return this->ptr_pointee_type->equals(other->ptr_pointee_type);
            default:
                throw IRException("unknown VarType type");
            }
        }

        bool VarType::have_no_ptr() const {
            switch (this->type) {
                case T::PTR:
                    return false;
                case T::STRUCT:
                    for (auto &et : struct_types) {
                        if (!et->have_no_ptr()) {
                            return false;
                        }
                    }
                case T::ARRAY:
                    return array_element_type->have_no_ptr();
                case T::ARGUMENT:
                    return false;
                default:
                    return true;
            }
            return true;
        }

        int VarType::get_num_bytes() const {
            switch(this->type) {
                case T::PTR:
                    return 8;
                case T::INT:
                    return (int_bitwidth / 8) + ((int_bitwidth % 8 == 0) ? 0 : 1);
                case T::STRUCT:
                    return struct_num_bytes;
                case T::ARRAY:
                    return array_element_type->get_num_bytes() * array_size;
                default:
                    return -1;
            }
        }

        int VarType::get_off_by_idx(int i) const {
            switch(this->type) {
                case T::PTR:
                    return i * this->ptr_pointee_type->get_num_bytes();
                case T::STRUCT:
                    return this->struct_offset[i];
                case T::ARRAY:
                    return array_element_type->get_num_bytes() * i;
                default:
                    return -1;
            }
        }

        VarType * VarType::get_type_by_idx(int i) const {
            switch(this->type) {
                case T::PTR:
                    return this->ptr_pointee_type;
                case T::STRUCT:
                    return this->struct_types[i];
                case T::ARRAY:
                    return array_element_type;
                default:
                    return nullptr;
            }
        }

        int VarType::offset_from_gep_offset(const std::vector<int> &idx, VarType **typep) const {
            auto t = this;
            int result = 0;
            for (auto &i : idx) {
                auto off = t->get_off_by_idx(i);
                result += off;
                t = t->get_type_by_idx(i);
            }
            *typep = const_cast<VarType *>(t);
            return result;
        }

        int Var::new_var_cnt() {
            static int global_var_cnt = 0;
            return global_var_cnt++;
        }

        void Var::print(std::ostream &os) {
            if (is_pkt_header) {
                os << header_name << "." << field_name;
            } else if (is_constant) {
                os << const_val;
            } else {
                os << var_name;
            }
        }

        void Var::print_decl(std::ostream &os) {

        }

        std::shared_ptr<VarInfo> Var::get_var_info() {
            if (this->var_info == nullptr) {
                this->var_info = std::make_shared<VarInfo>();
                assert(this->from != nullptr);
                auto op = this->from;
                using OpT = PipeIR::Operation::Type;
                if (op->type == OpT::PHI) {
                } else if (op->type == OpT::ALLOC_TMP) {
                    var_info->type = VarInfo::T::STACK_PTR;
                } else if (op->type == OpT::POINTER_OFF) {
                    auto base_info = op->oprands[0]->get_var_info();
                    if (base_info->type == VarInfo::T::STATE_MID) {
                    }
                }
            }
            return this->var_info;
        }

        std::unordered_set<Var *> Operation::vars_read() const {
            std::unordered_set<Var *> vars;
            if (type == Type::PHI) {
                for (auto &v : phi_incoming_vals) {
                    vars.insert(v.get());
                }
            } else {
                for (auto &v : oprands) {
                    vars.insert(v.get());
                }
            }
            return vars;
        }

        std::unordered_set<Var *> Operation::vars_written() const {
            std::unordered_set<Var *> vars;
            for (auto &v : dst_var) {
                vars.insert(v.get());
            }
            return vars;
        }

        std::unordered_set<GlobalState *> Operation::state_read() const {
            std::unordered_set<GlobalState *> states;
            if (type == Type::STATE_OP) {
                states.insert(state);
            }
            return states;
        }

        std::unordered_set<GlobalState *> Operation::state_written() const {
            std::unordered_set<GlobalState *> states;
            assert(false && "not implemented");
            if (type == Type::STATE_OP) {
                states.insert(state);
            }
            return states;
        }

        std::unordered_set<std::string> Operation::possible_labels() const {
            assert(false && "not implemented");
            return {};
        }

        bool Operation::has_side_effect() const {
            static std::unordered_set<std::string> side_effect_free_func = {
                "Vector::operator[]",
                "HashMap::findp const",
                "Packet::ip_header const",
                "Packet::transport_header const",
                "WritablePacket::ip_header const",
                "WritablePacket::transport_header const",
                "Packet::transport_length const",
            };
            switch (type) {
                case Type::STATE_OP:
                    if (side_effect_free_func.find(state_op_name) != side_effect_free_func.end()) {
                        return false;
                    }
                case Type::PKTHDR_W:
                case Type::STORE:
                    return true;
                default:
                    return false;
            }
        }

        Stage::Stage(std::vector<std::unique_ptr<Operation>> &&_ops) {
            for (int i = 0; i < _ops.size(); i++) {
                ops.push_back(std::move(_ops[i]));
            }
        }

        std::vector<GlobalState *> Stage::read_set() {
            static std::unordered_set<std::string> read_state_op = {
                "map_get",
                "array_get",
            };
            std::vector<GlobalState *> result;
            for (auto &ptr : ops) {
                if (ptr->type == Operation::Type::STATE_OP) {
                    // decide by operation name
                    auto state = ptr->state;
                    auto op_name = ptr->state_op_name;
                    if (read_state_op.find(op_name) == read_state_op.end()) {
                        result.push_back(state);
                    }
                }
            }
            return result;
        }

        std::vector<GlobalState *> Stage::write_set() {
            static std::unordered_set<std::string> write_state_op = {
                "map_set",
                "map_delete",
                "array_set",
            };
            std::vector<GlobalState *> result;
            for (auto &ptr : ops) {
                if (ptr->type == Operation::Type::STATE_OP) {
                    auto state = ptr->state;
                    auto op_name = ptr->state_op_name;
                    if (write_state_op.find(op_name) == write_state_op.end()) {
                        result.push_back(state);
                    }
                }
            }
            return result;
        }

        Prog::Prog() {}

        Prog::Prog(std::vector<std::unique_ptr<Stage>> &&stages) {
            for (auto &s : stages) {
                stages_.insert({s->get_uuid(), std::move(s)});
            }
            build_rev_edge();
        }

        Stage& Prog::get_stage(const uuid_t &uuid) {
           auto iter = stages_.find(uuid);
           if (iter == stages_.end()) {
               throw IRException("stage not found");
           } else {
               return *(iter->second);
           }
        }

        const Stage& Prog::get_stage(const uuid_t &uuid) const {
           auto iter = stages_.find(uuid);
           if (iter == stages_.end()) {
               throw IRException("stage not found");
           } else {
               return *(iter->second);
           }
        }

        void Prog::build_rev_edge() {
            rev_edges.clear();
            for (auto &kv : stages_) {
                auto stage_ptr = kv.second.get();
                for (auto &n : stage_ptr->next_stages) {
                    rev_edges[kv.first].push_back(n->get_uuid());
                }
            }
        }
        class OperationPrintVisitor : public OperationVisitor<void> {
        public:
            std::ostream &os;
            OperationPrintVisitor(std::ostream &_os) : os(_os) {}

            virtual void visitOtherOp(Operation &op) override {
                assert(false && "print: unknown operation");
            }

            void print_var_list(const std::vector<std::shared_ptr<Var>> &var_list,
                                const std::string &delimiter) {
                for (int i = 0; i < var_list.size(); i++) {
                    auto v = var_list[i];
                    if (i != 0) {
                        os << delimiter;
                    }
                    v->print(os);
                }
            }

            virtual void visitAllocTmp(Operation &op) override {
                print_var_list(op.dst_var, ", ");
                os << " = AllocTmp(" << ");";
            }

            virtual void visitArith(Operation &op) override {
                print_var_list(op.dst_var, ", ");

                os << " = "
                   << op.arith_op_name << "(";
                print_var_list(op.oprands, ", ");
                os << ");";
            }

            virtual void visitStateOp(Operation &op) override {
                if (op.dst_var.size() > 0) {
                    print_var_list(op.dst_var, ", ");
                    os << " = ";
                }
                if (op.state != nullptr) {
                    os << op.state->name_anno << "->";
                }
                os << op.state_op_name << "(";
                print_var_list(op.oprands, ", ");
                os << ");";
            }

            virtual void visitPhi(Operation &op) override {
                if (op.dst_var.size() > 0) {
                    print_var_list(op.dst_var, ", ");
                    os << " = ";
                }
                os << "PhiNode" << "(";
                print_var_list(op.phi_incoming_vals, ", ");
                os << ");";
            }

            virtual void visitPointerOffOp(Operation &op) override {
                if (op.dst_var.size() > 0) {
                    print_var_list(op.dst_var, ", ");
                    os << " = ";
                }
                os << "PointerOff" << "(";
                print_var_list(op.oprands, ", ");
                os << ");";
            }

            virtual void visitLoadOp(Operation &op) override {
                if (op.dst_var.size() > 0) {
                    print_var_list(op.dst_var, ", ");
                    os << " = ";
                }
                os << "Load" << "(";
                print_var_list(op.oprands, ", ");
                os << ");";
            }

            virtual void visitStoreOp(Operation &op) override {
                os << "Store" << "(";
                print_var_list(op.oprands, ", ");
                os << ");";
            }

            virtual void visitHdrReadOp(Operation &op) override {
                assert(op.oprands.size() == 1);
                if (op.dst_var.size() > 0) {
                    print_var_list(op.dst_var, ", ");
                    os << " = ";
                }
                op.oprands[0]->print(os);
                os << "." << op.header_name << "." << op.field_name << ";";
            }

            virtual void visitHdrWriteOp(Operation &op) override {
                assert(op.oprands.size() == 2);
                op.oprands[0]->print(os);
                os << "." << op.header_name << "." << op.field_name << " = ";
                op.oprands[1]->print(os);
                os << ";";
            }
        };

        std::string op_to_str(Operation &op) {
            std::stringstream ss;
            ss << op;
            return ss.str();
        }
    }
}


std::ostream& operator<<(std::ostream &os, Morula::PipeIR::Operation &op) {
    using namespace Morula::PipeIR;
    Morula::PipeIR::OperationPrintVisitor v(os);
    v.visit(op);
    return os;
}
