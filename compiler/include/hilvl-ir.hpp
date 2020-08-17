#pragma once

#include "llvm-incl.hpp"
#include "llvm-load.hpp"
#include <cassert>
#include <vector>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <utility>
#include <type_traits>

/* first define the click configuration (simply a directed graph) */

namespace HIR {

    struct ConfExpr {
    };


    class Element;

    /* instance of a element */
    class ElementInstance {
    public:
        std::string name;
        std::string type;
        std::vector<ConfExpr> init_args;
        std::shared_ptr<Element> element;

        int num_in;
        int num_out;
    };

    class Type;
    class Function;

    class Module {
    public:
        std::unordered_map<int, std::shared_ptr<Type>> int_types;
        std::vector<std::shared_ptr<Type>> types;
        std::unordered_map<std::string, std::shared_ptr<Function>> function_mapping;
        std::unordered_map<std::string, std::shared_ptr<Element>> elements;
        std::unordered_map<std::string, std::vector<std::string>> out_connection;

        std::shared_ptr<Type> get_int_type(int bitwidth);
    };


    class BasicBlock;
    class Var;
    class Operation;

    class Function : std::enable_shared_from_this<Function> {
    public:
        std::string name;
        std::vector<std::shared_ptr<BasicBlock>> bbs;
        std::vector<std::weak_ptr<Function>> called_functions;
        std::vector<std::shared_ptr<Type>> arg_types;
        std::vector<std::shared_ptr<Var>> args;
        Type *return_type = nullptr;

        Function () {}
        Function (const Function &func);

        int entry_bb_idx() const { return entry_bb_idx_; }
        void set_entry_idx(int idx) { entry_bb_idx_ = idx; }

        void translate_from(
                Module &module,
                std::unordered_map<
                    llvm::Type *,
                    std::shared_ptr<Type>>& type_mapping,
                llvm::Function *llvm_func);
        bool is_built_in = false;

        using OpPrinterT = std::function<void(std::ostream& os, const Operation& op)>;
        void print(std::ostream& os, OpPrinterT op_printer) const;
        void print(std::ostream& os) const;
    protected:
        int entry_bb_idx_;
    };

    class Element {
    public:
        Element() {}
        Element(
            Module &module,
            const LLVMStore &store,
            const std::string &element_name
        );

        Type* element_type;
        std::unordered_map<size_t, std::shared_ptr<Var>> states;
        std::vector<std::shared_ptr<Function>> funcs;

        int entry_func_idx() const { return entry_func_idx_; }
        void set_entry_func_idx(int idx) { entry_func_idx_ = idx; }

        std::shared_ptr<Function> entry() const {
            return funcs[entry_func_idx_];
        }

        void print(std::ostream &os) const;
        std::string name() const { return element_name_; }

        Module *module() const { return module_; }
    protected:
        int entry_func_idx_;
        std::string element_name_;
        Module *module_;

        void create_function_placeholder(
            llvm::Function *f,
            std::unordered_map<
                std::string,
                std::shared_ptr<Function>> &func_mapping);
    };

    class BasicBlock : std::enable_shared_from_this<BasicBlock> {
    public:
        std::vector<std::shared_ptr<Operation>> ops;

        struct BranchEntry {
            bool is_conditional = false;
            std::shared_ptr<Var> cond_var;
            std::weak_ptr<BasicBlock> next_bb;
        };

        bool is_return = false;
        bool is_short_circuit = false;
        bool is_err = false;
        std::vector<BranchEntry> branches;
        std::weak_ptr<BasicBlock> default_next_bb;
        Function* parent;

        std::shared_ptr<Var> return_val;

        std::string name;

        bool has_branch() const { return branches.size() > 0; }

        void print_branching(std::ostream &os) const;

        void append_operation(std::shared_ptr<Operation> op);
        void update_uses();
    };

    class Type {
    public:
        enum class T {
            UNDEF,
            VOID,
            INT,
            FLOAT,
            POINTER,
            STATE_PTR,
            PACKET,
            STRUCT,
            ARRAY,
            ELEMENT_BASE,
            VECTOR,
            MAP,
            OPAQUE,
        };

        T type;

        // data for each type
        int bitwidth;
        Type *pointee_type;
        std::string state_name;
        bool is_input_pkt; // if false the packet is newly created during the execution
        struct {
            std::string struct_name;
            std::vector<Type *> fields;
            std::vector<size_t> offsets;
        } struct_info;
        struct {
            uint64_t num_element;
            Type *element_type;
        } array_info;

        struct {
            Type *key_t;
            Type *val_t;
        } map_info;

        struct {
            Type *element_type;
        } vector_info;

        std::string opaque_type_name;

        void print(std::ostream &os) const;

        size_t num_bytes();
        bool sized() const;
        void set_size(size_t sz) { size_ = sz; }

    protected:
        std::optional<size_t> size_ = std::nullopt;
    };

    enum class ArithType {
        INT_ARITH,
        INT_CMP,
    };

    enum class IntArithType {
        INT_ADD,
        INT_SUB,
        INT_MUL,
        INT_DIV,
        INT_MOD,
        INT_UDIV,
        INT_UMOD,
        INT_AND,
        INT_OR,
        INT_XOR,
        INT_SHL,
        INT_LSHR,
        INT_ASHR,
        INT_NOT,

        INT_TRUNC,
        INT_ZEXT,
        INT_SEXT,
    };

    enum class IntCmpType {
        EQ,
        NE,
        ULE,
        ULT,
        SLE,
        SLT,
        // we will replace GE & GT with LE & LT
    };

    class Var {
    public:
        Type *type;

        std::string name;
        uint64_t constant;
        size_t global_state_idx;

        bool is_constant = false;
        bool is_constant_name = false;
        bool is_undef = false;
        bool is_param = false;
        bool is_global = false;

        std::weak_ptr<Operation> src_op;

        struct Use {
            enum class T {
                OP,
                BB_COND,
            };
            T type;
            union {
                Operation *op_ptr;
                BasicBlock *bb_ptr;
            } u;
        };
        std::vector<Use> uses;

        void print(std::ostream &os) const;
    };

    /* the high level IR is similar to LLVM IR */
    class Operation : std::enable_shared_from_this<Operation> {
    public:
        enum class T {
            ALLOCA,
            ARITH,
            LOAD,
            STORE,
            STRUCT_SET,
            STRUCT_GET,
            GEP,
            BITCAST,
            PHINODE,
            SELECT,
            FUNC_CALL,
            PKT_HDR_LOAD,
            PKT_HDR_STORE,
            PKT_ENCAP,
            PKT_DECAP,
            UNREACHABLE,
        };

        std::vector<std::shared_ptr<Var>> dst_vars;

        struct {
            ArithType t;
            union {
                IntArithType iarith_t;
                IntCmpType icmp_t;
            } u;
        } arith_info;

        std::vector<int> struct_ref_info{};
        bool struct_set_have_writeback = false;

        Type *alloca_type;
        struct {
            std::vector<std::weak_ptr<BasicBlock>> from;
        } phi_info;

        struct {
            bool is_built_in_func = false;
            std::string func_name;
            std::weak_ptr<Function> called_function;
        } call_info;

        struct {
            std::string header;
            std::string field;
        } pkt_op_info;

        std::vector<std::shared_ptr<Var>> args;
        BasicBlock* parent;

        T type;

        std::shared_ptr<void> anno_;

        template<typename AnnoT>
        void set_meta(std::shared_ptr<AnnoT> anno) {
            anno_ = anno;
        }

        template<typename AnnoT>
        std::shared_ptr<AnnoT> meta() const {
            return std::static_pointer_cast<AnnoT>(anno_);
        }

        template<typename AnnoT>
        AnnoT &meta_ref() {
            return *((AnnoT *)anno_.get());
        }

        template<typename AnnoT>
        const AnnoT &meta_ref() const {
            return *((AnnoT *)anno_.get());
        }

        void print(std::ostream &os) const;

        void update_uses();
    };

    template <typename DerivedT, typename RetT=void>
    class OperationVisitor {
    public:
        RetT visit(Operation &op) {
            using T = Operation::T;
            switch (op.type) {
                case T::ALLOCA:
                    return static_cast<DerivedT *>(this)->visitAlloca(op);
                    break;
                case T::ARITH:
                    return static_cast<DerivedT *>(this)->visitArith(op);
                    break;
                case T::STRUCT_SET:
                    return static_cast<DerivedT *>(this)->visitStructSet(op);
                    break;
                case T::STRUCT_GET:
                    return static_cast<DerivedT *>(this)->visitStructGet(op);
                    break;
                case T::LOAD:
                    return static_cast<DerivedT *>(this)->visitLoad(op);
                    break;
                case T::STORE:
                    return static_cast<DerivedT *>(this)->visitStore(op);
                    break;
                case T::GEP:
                    return static_cast<DerivedT *>(this)->visitGep(op);
                    break;
                case T::BITCAST:
                    return static_cast<DerivedT *>(this)->visitBitCast(op);
                    break;
                case T::PHINODE:
                    return static_cast<DerivedT *>(this)->visitPhiNode(op);
                    break;
                case T::SELECT:
                    return static_cast<DerivedT *>(this)->visitSelect(op);
                    break;
                case T::FUNC_CALL:
                    return static_cast<DerivedT *>(this)->visitFuncCall(op);
                    break;
                case T::PKT_HDR_LOAD:
                    return static_cast<DerivedT *>(this)->visitPktLoad(op);
                    break;
                case T::PKT_HDR_STORE:
                    return static_cast<DerivedT *>(this)->visitPktStore(op);
                    break;
                case T::PKT_ENCAP:
                    return static_cast<DerivedT *>(this)->visitPktEncap(op);
                    break;
                case T::PKT_DECAP:
                    return static_cast<DerivedT *>(this)->visitPktDecap(op);
                    break;
                case T::UNREACHABLE:
                    return static_cast<DerivedT *>(this)->visitUnreachable(op);
                    break;
            }
            assert(false && "unreachalbe");
        }
    protected:
#define VISITOR_DEFAULT_IMPL(fn)                                    \
        RetT fn(Operation &op) {                                    \
            return static_cast<DerivedT *>(this)->visitDefault(op); \
        }

        RetT visitDefault(Operation &op) {
            assert(false && "not implemented");
        }

        VISITOR_DEFAULT_IMPL(visitAlloca);
        VISITOR_DEFAULT_IMPL(visitArith);
        VISITOR_DEFAULT_IMPL(visitStructSet);
        VISITOR_DEFAULT_IMPL(visitStructGet);
        VISITOR_DEFAULT_IMPL(visitLoad);
        VISITOR_DEFAULT_IMPL(visitStore);
        VISITOR_DEFAULT_IMPL(visitGep);
        VISITOR_DEFAULT_IMPL(visitPhiNode);
        VISITOR_DEFAULT_IMPL(visitBitCast);
        VISITOR_DEFAULT_IMPL(visitSelect);
        VISITOR_DEFAULT_IMPL(visitFuncCall);
        VISITOR_DEFAULT_IMPL(visitPktLoad);
        VISITOR_DEFAULT_IMPL(visitPktStore);
        VISITOR_DEFAULT_IMPL(visitPktEncap);
        VISITOR_DEFAULT_IMPL(visitPktDecap);
        VISITOR_DEFAULT_IMPL(visitUnreachable);

#undef VISITOR_DEFAULT_IMPL
    };

    template <typename DerivedT, typename RetT=void>
    class OperationConstVisitor {
    public:
        RetT visit(const Operation &op) {
            using T = Operation::T;
            switch (op.type) {
                case T::ALLOCA:
                    return static_cast<DerivedT *>(this)->visitAlloca(op);
                    break;
                case T::ARITH:
                    return static_cast<DerivedT *>(this)->visitArith(op);
                    break;
                case T::STRUCT_SET:
                    return static_cast<DerivedT *>(this)->visitStructSet(op);
                    break;
                case T::STRUCT_GET:
                    return static_cast<DerivedT *>(this)->visitStructGet(op);
                    break;
                case T::LOAD:
                    return static_cast<DerivedT *>(this)->visitLoad(op);
                    break;
                case T::STORE:
                    return static_cast<DerivedT *>(this)->visitStore(op);
                    break;
                case T::GEP:
                    return static_cast<DerivedT *>(this)->visitGep(op);
                    break;
                case T::BITCAST:
                    return static_cast<DerivedT *>(this)->visitBitCast(op);
                    break;
                case T::PHINODE:
                    return static_cast<DerivedT *>(this)->visitPhiNode(op);
                    break;
                case T::SELECT:
                    return static_cast<DerivedT *>(this)->visitSelect(op);
                    break;
                case T::FUNC_CALL:
                    return static_cast<DerivedT *>(this)->visitFuncCall(op);
                    break;
                case T::PKT_HDR_LOAD:
                    return static_cast<DerivedT *>(this)->visitPktLoad(op);
                    break;
                case T::PKT_HDR_STORE:
                    return static_cast<DerivedT *>(this)->visitPktStore(op);
                    break;
                case T::PKT_ENCAP:
                    return static_cast<DerivedT *>(this)->visitPktEncap(op);
                    break;
                case T::PKT_DECAP:
                    return static_cast<DerivedT *>(this)->visitPktDecap(op);
                    break;
                case T::UNREACHABLE:
                    return static_cast<DerivedT *>(this)->visitUnreachable(op);
                    break;
            }
            assert(false && "unreachalbe");
        }
    protected:
#define VISITOR_DEFAULT_IMPL(fn)                                    \
        RetT fn(const Operation &op) {                              \
            return static_cast<DerivedT *>(this)->visitDefault(op); \
        }

        RetT visitDefault(const Operation &op) {
            assert(false && "not implemented");
        }

        VISITOR_DEFAULT_IMPL(visitAlloca);
        VISITOR_DEFAULT_IMPL(visitArith);
        VISITOR_DEFAULT_IMPL(visitStructSet);
        VISITOR_DEFAULT_IMPL(visitStructGet);
        VISITOR_DEFAULT_IMPL(visitLoad);
        VISITOR_DEFAULT_IMPL(visitStore);
        VISITOR_DEFAULT_IMPL(visitGep);
        VISITOR_DEFAULT_IMPL(visitPhiNode);
        VISITOR_DEFAULT_IMPL(visitBitCast);
        VISITOR_DEFAULT_IMPL(visitSelect);
        VISITOR_DEFAULT_IMPL(visitFuncCall);
        VISITOR_DEFAULT_IMPL(visitPktLoad);
        VISITOR_DEFAULT_IMPL(visitPktStore);
        VISITOR_DEFAULT_IMPL(visitPktEncap);
        VISITOR_DEFAULT_IMPL(visitPktDecap);
        VISITOR_DEFAULT_IMPL(visitUnreachable);

#undef VISITOR_DEFAULT_IMPL
    };

    class BuiltInFunction : public Function {
    public:
        BuiltInFunction();

        virtual bool match(const std::string &func_name) const = 0;
    };

    class BuiltInFunctionStore {
    public:
        static BuiltInFunctionStore *get();

        std::shared_ptr<BuiltInFunction> match_builtin(const std::string &fn) const;
        void register_builtin(std::shared_ptr<BuiltInFunction> f);
    protected:
        static std::unique_ptr<BuiltInFunctionStore> instance_;

        std::unordered_set<std::shared_ptr<BuiltInFunction>> functions_;
    };

    template <typename F>
    class RegisterBuiltInFunction {
    public:
        template<typename... Args>
        RegisterBuiltInFunction(Args&&... args) {
            static_assert(std::is_base_of<BuiltInFunction, F>::value,
                          "Not builtin function type");
            auto f = std::make_shared<F>(std::forward<Args>(args)...);
            BuiltInFunctionStore::get()->register_builtin(f);
        }
    };
}

#define DEF_HIR_BUILTIN_FUNC(NAME)                                       \
    class NAME : public ::HIR::BuiltInFunction {                         \
    public:                                                              \
        NAME() { name = #NAME; }                                         \
        virtual bool match(const std::string &func_name) const override; \
    }

#define DEF_HIR_BUILTIN_MATCH(name, fn) bool name::match(const std::string &fn) const

DEF_HIR_BUILTIN_FUNC(PushPktFn);
DEF_HIR_BUILTIN_FUNC(VectorIdxOp);
DEF_HIR_BUILTIN_FUNC(HashMapFindp);
DEF_HIR_BUILTIN_FUNC(HashMapInsert);
DEF_HIR_BUILTIN_FUNC(ClickJiffieFn);
DEF_HIR_BUILTIN_FUNC(AssertFailFn);

DEF_HIR_BUILTIN_FUNC(MemcpyFn);

/* packet ops */
DEF_HIR_BUILTIN_FUNC(PacketHeaderFns);
DEF_HIR_BUILTIN_FUNC(PacketKillFn);

DEF_HIR_BUILTIN_FUNC(IPFlowIDConstr);

extern HIR::RegisterBuiltInFunction<PushPktFn> PktPushFnReg;
extern HIR::RegisterBuiltInFunction<VectorIdxOp> VectorIdxOpReg;
extern HIR::RegisterBuiltInFunction<HashMapFindp> HashMapFindpReg;
extern HIR::RegisterBuiltInFunction<HashMapInsert> HashMapInsertReg;
extern HIR::RegisterBuiltInFunction<ClickJiffieFn> ClickJiffieFnReg;
extern HIR::RegisterBuiltInFunction<AssertFailFn> AssertFailFnReg;

extern HIR::RegisterBuiltInFunction<MemcpyFn> MemcpyFnReg;

extern HIR::RegisterBuiltInFunction<PacketHeaderFns> PacketHeaderFnsReg;
extern HIR::RegisterBuiltInFunction<PacketKillFn> PacketKillFnReg;

extern HIR::RegisterBuiltInFunction<IPFlowIDConstr> IPFlowIDConstrReg;
