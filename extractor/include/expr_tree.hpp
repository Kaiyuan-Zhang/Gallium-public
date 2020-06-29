#ifndef _EXPR_TREE_HPP_
#define _EXPR_TREE_HPP_

#include <cstdint>
#include <memory>
#include <vector>
#include <initializer_list>


namespace Expr {
    class Expression {
    };
}


using ExprPtr = std::shared_ptr<Expression>;


namespace Expr {
    class Value : public Expression {};


    class BitVecVal : public Value {
    public:
        BitVecVal(unsigned int num_bits, int64_t val): num_bits_(num_bits),
                                                       val_(val) {}
    
    protected:
        unsigned int num_bits_;
        int64_t val_;
    };

    class BitVecVar : public Value {
    public:
        BitVecVar(unsigned int num_bits,
                  const std::string &name): num_bits_(num_bits),
                                            name_(name) {}
    
    protected:
        unsigned int num_bits_;
        std::string name_;
    };


    class Operation : public Expression {
    public:
        Operation(const std::vector<ExprPtr> &oprands): oprands_(oprands) {}
    
    protected:
        std::vector<ExprPtr> oprands_;
    };


    class AddOp : public Operation {
    public:
        AddOp(const std::vector<ExprPtr> &oprands): Operation(oprands) {}
    };


    class SubOp : public Operation {
    public:
        SubOp(const std::vector<ExprPtr> &oprands): Operation(oprands) {}
    };


    class MulOp : public Operation {
    public:
        MulOp(const std::vector<ExprPtr> &oprands): Operation(oprands) {}
    };


    class DivOp : public Operation {
    public:
        DivOp(const std::vector<ExprPtr> &oprands): Operation(oprands) {}
    };


    class EqOp : public Operation {
    public:
        EqOp(const std::vector<ExprPtr> &oprands): Operation(oprands) {}
    };


    class NeqOp : public Operation {
    public:
        NeqOp(const std::vector<ExprPtr> &oprands): Operation(oprands) {}
    };


    class LtOp : public Operation {
    public:
        LtOp(const std::vector<ExprPtr> &oprands): Operation(oprands) {}
    };


    class AndOp : public Operation {
    public:
        AndOp(const std::vector<ExprPtr> &oprands): Operation(oprands) {}
    };


    class OrOp : public Operation {
    public:
        OrOp(const std::vector<ExprPtr> &oprands): Operation(oprands) {}
    };


    class NotOp : public Operation {
    public:
        NotOp(const std::vector<ExprPtr> &oprands): Operation(oprands) {}
    }


    class LAndOp : public Operation {
    public:
        LAndOp(const std::vector<ExprPtr> &oprands): Operation(oprands) {}
    };


    class LOrOp : public Operation {
    public:
        LOrOp(const std::vector<ExprPtr> &oprands): Operation(oprands) {}
    };


    class LNotOp : public Operation {
    public:
        LNotOp(const std::vector<ExprPtr> &oprands): Operation(oprands) {}
    }
}


template <typename Op>
ExprPtr make_op(const std::vector<ExprPtr> &oprands) {
    std::shared_ptr<Op> ptr = new shared_ptr<Op>(oprands);
    return std::static_pointer_cast<Expression>(ptr);
}


#endif
